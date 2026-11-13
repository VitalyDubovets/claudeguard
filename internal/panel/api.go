package panel

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/browser"
	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/platform"
)

// Servers: the list, which one is active, tests.

func (h *handler) activate(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name string }
	if !decode(w, r, &req) {
		return
	}
	reply(w, h.m.Update(func(c *config.Config) error { return c.Activate(req.Name) }))
}

func (h *handler) saveProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Old     string         `json:"old"`
		Profile config.Profile `json:"profile"`
	}
	if !decode(w, r, &req) {
		return
	}
	p := req.Profile
	p.Name = strings.TrimSpace(p.Name)
	p.Target = strings.TrimSpace(p.Target)
	// The page never gets a saved proxy password, so an edit that leaves
	// the user as is means "same password".
	if old, ok := h.m.Config().Find(req.Old); ok && old.Kind != config.KindSSH && old.Kind == p.Kind {
		p.Target = config.KeepPassword(old.Target, p.Target)
	}
	reply(w, h.m.Update(func(c *config.Config) error { return c.Add(req.Old, p) }))
}

func (h *handler) deleteProfile(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name string }
	if !decode(w, r, &req) {
		return
	}
	reply(w, h.m.Update(func(c *config.Config) error { c.Remove(req.Name); return nil }))
}

func (h *handler) testProfile(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name string }
	if !decode(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	writeJSON(w, h.m.Test(ctx, req.Name))
}

func (h *handler) restart(w http.ResponseWriter, _ *http.Request) {
	h.m.Restart()
	reply(w, nil)
}

// The machine around the proxy: browsers, the kill switch, Claude itself.

func (h *handler) setBrowserProxy(w http.ResponseWriter, r *http.Request) {
	var req struct{ On bool }
	if !decode(w, r, &req) {
		return
	}
	url := browser.PACURL(h.m.Config().Listen)
	var err error
	if req.On {
		err = browser.Enable(url)
	} else {
		err = browser.Disable(url)
	}
	browser.ForgetState()
	reply(w, err)
}

func (h *handler) setFirewall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AllowTunnels bool   `json:"allow_tunnels"`
		ExtraBlock   string `json:"extra_block"`
	}
	if !decode(w, r, &req) {
		return
	}
	extra, err := firewall.ParseCIDRList(req.ExtraBlock)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	fw := firewall.Options{AllowTunnels: req.AllowTunnels, Extra: extra}
	// Ask for the password first and save only what was really applied.
	// The dialog can stay open for minutes; no lock is held meanwhile.
	if err := platform.ElevateGUI(append([]string{"system-install"}, fw.Args()...)); err != nil {
		jsonError(w, http.StatusBadGateway, "правила не применены: "+err.Error())
		return
	}
	reply(w, h.m.Update(func(c *config.Config) error {
		c.AllowTunnels, c.ExtraBlock = fw.AllowTunnels, fw.Extra
		return nil
	}))
}

func (h *handler) launchClaude(w http.ResponseWriter, _ *http.Request) {
	reply(w, platform.LaunchClaude(h.m.Config().ProxyURL(), ""))
}

func (h *handler) uninstall(w http.ResponseWriter, _ *http.Request) {
	// A separate process: removing claudeguard stops this one.
	reply(w, platform.Detach([]string{"uninstall", "--gui"}))
}
