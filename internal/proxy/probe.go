package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
	"github.com/VitalyDubovets/claudeguard/internal/tunnel"
)

// TestRecord is a test result and when it was taken.
type TestRecord struct {
	testResult
	At time.Time `json:"at"`
}

type testResult struct {
	OK        bool   `json:"ok"`
	ExitIP    string `json:"exit_ip,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	ConnectMs int64  `json:"connect_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Test checks a server without making it active: for SSH it brings
// up a throwaway tunnel on a spare port.
func (m *Manager) Test(ctx context.Context, name string) testResult {
	res := m.runTest(ctx, name)
	m.mu.Lock()
	if _, ok := m.cfg.Find(name); ok {
		m.tests[name] = TestRecord{testResult: res, At: time.Now()}
	}
	m.mu.Unlock()
	return res
}

func (m *Manager) runTest(ctx context.Context, name string) testResult {
	cfg := m.Config()
	p, ok := cfg.Find(name)
	if !ok {
		return testResult{Error: "нет такого сервера"}
	}
	var up *config.Upstream
	if p.Kind != config.KindSSH {
		var err error
		if up, err = config.ParseUpstream(p.Target); err != nil {
			return testResult{Error: err.Error()}
		}
		return probe(ctx, up)
	}
	m.mu.Lock()
	if cfg.Active == name && m.tunnel.State == StateUp {
		up = m.up
	}
	m.mu.Unlock()
	if up != nil {
		return probe(ctx, up)
	}

	port, err := sysutil.FreePort()
	if err != nil {
		return testResult{Error: err.Error()}
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := make(chan struct{})
	exited, stderr, err := tunnel.Start(sctx, p, port, func() { close(ready) })
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
	return probe(ctx, localSOCKS(port))
}

// probe measures the round trip to Anthropic through up and asks an echo
// service which IP the traffic leaves from.
func probe(ctx context.Context, up *config.Upstream) testResult {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return dial(ctx, up, addr) },
		},
	}
	defer client.CloseIdleConnections()
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://api.anthropic.com/", nil)
	resp, err := client.Do(req)
	if err != nil {
		return testResult{Error: sysutil.ShortErr(err)}
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
