package panel

import (
	"net/http"
	"runtime"

	"github.com/VitalyDubovets/claudeguard/internal/browser"
	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/proxy"
	"github.com/VitalyDubovets/claudeguard/internal/tunnel"
	"github.com/VitalyDubovets/claudeguard/internal/version"
)

// ProfileView is a server as the page sees it: without the proxy password,
// with the result of its last test.
type ProfileView struct {
	config.Profile
	Test *proxy.TestRecord `json:"test,omitempty"`
}

// State is the answer of GET /api/state: everything the page and the tray
// icon draw.
type State struct {
	Version      string            `json:"version"`
	OS           string            `json:"os"`
	Listen       string            `json:"listen"`
	Active       string            `json:"active"`
	Profiles     []ProfileView     `json:"profiles"`
	Tunnel       proxy.TunnelState `json:"tunnel"`
	SSHHosts     []string          `json:"ssh_hosts"`
	AllowTunnels bool              `json:"allow_tunnels"`
	ExtraBlock   []string          `json:"extra_block"`
	BrowserProxy bool              `json:"browser_proxy"`
	PACURL       string            `json:"pac_url"`
}

func (h *handler) getState(w http.ResponseWriter, _ *http.Request) {
	cfg := h.m.Config()
	tests := h.m.Tests()
	pac := browser.PACURL(cfg.Listen)
	v := State{
		Version:      version.Version,
		OS:           runtime.GOOS,
		Listen:       cfg.Listen,
		Active:       cfg.Active,
		Profiles:     []ProfileView{},
		Tunnel:       h.m.Tunnel(),
		SSHHosts:     tunnel.SSHConfigHosts(),
		AllowTunnels: cfg.AllowTunnels,
		ExtraBlock:   cfg.ExtraBlock,
		BrowserProxy: browser.Enabled(pac),
		PACURL:       pac,
	}
	for _, p := range cfg.Profiles {
		pv := ProfileView{Profile: p}
		if p.Kind != config.KindSSH {
			pv.Target = config.RedactTarget(p.Target)
		}
		if t, ok := tests[p.Name]; ok {
			pv.Test = &t
		}
		v.Profiles = append(v.Profiles, pv)
	}
	writeJSON(w, v)
}

type checkView struct {
	Firewall string `json:"firewall"`
	DirectV4 string `json:"direct_v4"`
	DirectV6 string `json:"direct_v6"`
	Blocked  bool   `json:"blocked"`
}

// getCheck tries api.anthropic.com directly, bypassing the proxy: with the
// kill switch on, both attempts must fail.
func (h *handler) getCheck(w http.ResponseWriter, _ *http.Request) {
	v := checkView{
		Firewall: firewall.Status(),
		DirectV4: firewall.DirectProbe("tcp4", "api.anthropic.com"),
		DirectV6: firewall.DirectProbe("tcp6", "api.anthropic.com"),
	}
	v.Blocked = !firewall.IsOpen(v.DirectV4) && !firewall.IsOpen(v.DirectV6)
	writeJSON(w, v)
}
