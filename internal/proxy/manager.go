package proxy

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/tunnel"
)

// Where the traffic can go right now. An SSH server walks through
// starting, up and down; a ready-made proxy is "direct": nothing to keep up.
const (
	StateOff      = "off"
	StateDirect   = "direct"
	StateStarting = tunnel.Starting
	StateUp       = tunnel.Up
	StateDown     = tunnel.Down
)

// TunnelState is the state of the way out and since when.
type TunnelState struct {
	State  string    `json:"state"` // off | direct | starting | up | down
	Detail string    `json:"detail,omitempty"`
	Since  time.Time `json:"since"`
}

// Manager owns the live configuration: the bridge asks it for the current
// upstream on every connection, so switching servers needs no restart.
type Manager struct {
	mu      sync.Mutex
	cfg     config.Config
	up      *config.Upstream
	tunnel  TunnelState
	stopSSH context.CancelFunc
	save    func(config.Config) error
	tests   map[string]TestRecord

	// onSwitch runs after the active server changes, e.g. to drop pooled
	// keep-alive connections that still lead to the old one.
	onSwitch func()
}

// NewManager starts whatever the active server of cfg needs. save is
// called with every changed config.
func NewManager(cfg config.Config, save func(config.Config) error) *Manager {
	m := &Manager{cfg: cfg, save: save, tests: map[string]TestRecord{}}
	m.mu.Lock()
	m.applyLocked()
	m.mu.Unlock()
	return m
}

func (m *Manager) setTunnelLocked(state, detail string) {
	m.tunnel = TunnelState{State: state, Detail: detail, Since: time.Now()}
}

// applyLocked (re)starts whatever the active profile needs.
func (m *Manager) applyLocked() {
	if m.stopSSH != nil {
		m.stopSSH()
		m.stopSSH = nil
	}
	m.up = nil
	p, ok := m.cfg.Find(m.cfg.Active)
	if !ok {
		m.setTunnelLocked(StateOff, "сервер не выбран")
		return
	}
	if p.Kind == config.KindSSH {
		// The bridge gets the tunnel's port only while our own ssh is up
		// and listening on it; at any other moment it answers 502.
		ctx, cancel := context.WithCancel(context.Background())
		m.stopSSH = cancel
		go tunnel.Supervise(ctx, p, func(state, detail string, port int) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			m.up = nil
			if state == StateUp {
				m.up = localSOCKS(port)
			}
			m.setTunnelLocked(state, detail)
		})
		return
	}
	up, err := config.ParseUpstream(p.Target)
	if err != nil {
		m.setTunnelLocked(StateOff, err.Error())
		return
	}
	m.up = up
	m.setTunnelLocked(StateDirect, "")
}

// localSOCKS is the SOCKS port of our own ssh -D tunnel.
func localSOCKS(port int) *config.Upstream {
	return &config.Upstream{Scheme: config.KindSOCKS5, Addr: "127.0.0.1:" + strconv.Itoa(port)}
}

// Stop takes the tunnel down (on exit, so no orphaned ssh stays behind).
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopSSH != nil {
		m.stopSSH()
		m.stopSSH = nil
	}
}

func (m *Manager) upstream() (*config.Upstream, error) {
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

// Config returns a copy of the current config.
func (m *Manager) Config() config.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cfg
	c.Profiles = append([]config.Profile(nil), m.cfg.Profiles...)
	return c
}

// Update applies fn to a copy of the config, saves it and, if the active
// server changed, switches to it.
func (m *Manager) Update(fn func(*config.Config) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.cfg
	next.Profiles = append([]config.Profile(nil), m.cfg.Profiles...)
	if err := fn(&next); err != nil {
		return err
	}
	if err := m.save(next); err != nil {
		return err
	}
	prevActive, _ := m.cfg.Find(m.cfg.Active)
	newActive, _ := next.Find(next.Active)
	m.cfg = next
	if prevActive != newActive || m.cfg.Active == "" {
		m.applyLocked()
		if m.onSwitch != nil {
			m.onSwitch()
		}
	}
	return nil
}

// Tunnel returns the state of the way out.
func (m *Manager) Tunnel() TunnelState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tunnel
}

// Tests returns the last test result of every server.
func (m *Manager) Tests() map[string]TestRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]TestRecord, len(m.tests))
	for k, v := range m.tests {
		out[k] = v
	}
	return out
}

// Restart re-dials the active server now instead of waiting for the retry.
func (m *Manager) Restart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyLocked()
	if m.onSwitch != nil {
		m.onSwitch()
	}
}

func (m *Manager) setOnSwitch(f func()) {
	m.mu.Lock()
	m.onSwitch = f
	m.mu.Unlock()
}

// activeName is the active server for the banner and the log.
func (m *Manager) activeName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Active == "" {
		return "no server"
	}
	return m.cfg.Active
}
