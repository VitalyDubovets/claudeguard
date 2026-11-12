package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type tunnelState struct {
	State  string    `json:"state"` // off | direct | starting | up | down
	Detail string    `json:"detail,omitempty"`
	Since  time.Time `json:"since"`
}

// manager owns the live configuration: the bridge asks it for the current
// upstream on every connection, so switching servers needs no restart.
type manager struct {
	mu      sync.Mutex
	cfg     Config
	up      *upstream
	tunnel  tunnelState
	stopSSH context.CancelFunc
	save    func(Config) error
	tests   map[string]testRecord

	// onSwitch runs after the active server changes, e.g. to drop pooled
	// keep-alive connections that still lead to the old one.
	onSwitch func()
}

type testRecord struct {
	testResult
	At time.Time `json:"at"`
}

func newManager(cfg Config, save func(Config) error) *manager {
	m := &manager{cfg: cfg, save: save, tests: map[string]testRecord{}}
	m.mu.Lock()
	m.applyLocked()
	m.mu.Unlock()
	return m
}

func (m *manager) setTunnelLocked(state, detail string) {
	m.tunnel = tunnelState{State: state, Detail: detail, Since: time.Now()}
}

// applyLocked (re)starts whatever the active profile needs.
func (m *manager) applyLocked() {
	if m.stopSSH != nil {
		m.stopSSH()
		m.stopSSH = nil
	}
	m.up = nil
	p, ok := m.cfg.profile(m.cfg.Active)
	if !ok {
		m.setTunnelLocked("off", "сервер не выбран")
		return
	}
	if p.Kind == "ssh" {
		// The bridge gets the tunnel's port only while our own ssh is up
		// and listening on it; at any other moment it answers 502.
		ctx, cancel := context.WithCancel(context.Background())
		m.stopSSH = cancel
		go superviseSSH(ctx, p, func(state, detail string, port int) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			m.up = nil
			if state == "up" {
				m.up, _ = p.upstream(port)
			}
			m.setTunnelLocked(state, detail)
		})
		return
	}
	up, err := p.upstream(0)
	if err != nil {
		m.setTunnelLocked("off", err.Error())
		return
	}
	m.up = up
	m.setTunnelLocked("direct", "")
}

// stop takes the tunnel down (on exit, so no orphaned ssh stays behind).
func (m *manager) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopSSH != nil {
		m.stopSSH()
		m.stopSSH = nil
	}
}

func (m *manager) upstream() (*upstream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.up == nil {
		if m.stopSSH != nil {
			return nil, errors.New("the ssh tunnel is not up")
		}
		return nil, errors.New("no server selected: open the claudeguard UI")
	}
	return m.up, nil
}

func (m *manager) config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cfg
	c.Profiles = append([]Profile(nil), m.cfg.Profiles...)
	return c
}

// update applies fn to a copy of the config, saves it and, if the active
// server changed, switches to it.
func (m *manager) update(fn func(*Config) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.cfg
	next.Profiles = append([]Profile(nil), m.cfg.Profiles...)
	if err := fn(&next); err != nil {
		return err
	}
	if err := m.save(next); err != nil {
		return err
	}
	prevActive, _ := m.cfg.profile(m.cfg.Active)
	newActive, _ := next.profile(next.Active)
	m.cfg = next
	if prevActive != newActive || m.cfg.Active == "" {
		m.applyLocked()
		if m.onSwitch != nil {
			m.onSwitch()
		}
	}
	return nil
}

func (m *manager) tunnelState() tunnelState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tunnel
}

func (m *manager) testRecords() map[string]testRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]testRecord, len(m.tests))
	for k, v := range m.tests {
		out[k] = v
	}
	return out
}

// restart re-dials the active server now instead of waiting for the retry.
func (m *manager) restart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyLocked()
	if m.onSwitch != nil {
		m.onSwitch()
	}
}

func (m *manager) identity() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Active == "" {
		return "no server"
	}
	return m.cfg.Active
}

type testResult struct {
	OK        bool   `json:"ok"`
	ExitIP    string `json:"exit_ip,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	ConnectMs int64  `json:"connect_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// testProfile checks a server without making it active: for SSH it brings
// up a throwaway tunnel on a spare port.
func (m *manager) testProfile(ctx context.Context, name string) testResult {
	res := m.runTest(ctx, name)
	m.mu.Lock()
	if _, ok := m.cfg.profile(name); ok {
		m.tests[name] = testRecord{testResult: res, At: time.Now()}
	}
	m.mu.Unlock()
	return res
}

func (m *manager) runTest(ctx context.Context, name string) testResult {
	cfg := m.config()
	p, ok := cfg.profile(name)
	if !ok {
		return testResult{Error: "нет такого сервера"}
	}
	var up *upstream
	if p.Kind != "ssh" {
		var err error
		if up, err = parseUpstream(p.Target); err != nil {
			return testResult{Error: err.Error()}
		}
		return probe(ctx, up)
	}
	m.mu.Lock()
	if cfg.Active == name && m.tunnel.State == "up" {
		up = m.up
	}
	m.mu.Unlock()
	if up != nil {
		return probe(ctx, up)
	}

	port, err := freePort()
	if err != nil {
		return testResult{Error: err.Error()}
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := make(chan struct{})
	exited, stderr, err := startSSH(sctx, p, port, func() { close(ready) })
	if err != nil {
		return testResult{Error: "ssh: " + err.Error()}
	}
	select {
	case <-ready:
	case err := <-exited:
		msg := stderr.String()
		if msg == "" && err != nil {
			msg = err.Error()
		}
		return testResult{Error: "ssh: " + msg}
	case <-time.After(20 * time.Second):
		return testResult{Error: "ssh: нет ответа за 20 с"}
	}
	return probe(ctx, &upstream{scheme: "socks5", addr: fmt.Sprintf("127.0.0.1:%d", port)})
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// probe measures the round trip to Anthropic through up and asks an echo
// service which IP the traffic leaves from.
func probe(ctx context.Context, up *upstream) testResult {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return up.dial(ctx, addr) },
		},
	}
	defer client.CloseIdleConnections()
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://api.anthropic.com/", nil)
	resp, err := client.Do(req)
	if err != nil {
		return testResult{Error: shortErr(err)}
	}
	resp.Body.Close()
	res := testResult{OK: true, LatencyMs: time.Since(start).Milliseconds()}
	// The first request paid for a new connection: TCP and TLS handshakes,
	// several round trips. Claude keeps its connections open, so what it
	// feels is one round trip on a warm one.
	res.ConnectMs = res.LatencyMs
	start = time.Now()
	req, _ = http.NewRequestWithContext(ctx, http.MethodHead, "https://api.anthropic.com/", nil)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		res.LatencyMs = time.Since(start).Milliseconds()
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org/", nil)
	if resp, err := client.Do(req); err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		res.ExitIP = strings.TrimSpace(string(b))
	}
	return res
}
