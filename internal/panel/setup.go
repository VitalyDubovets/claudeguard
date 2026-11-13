package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/proxy"
	"github.com/VitalyDubovets/claudeguard/internal/tunnel"
)

// Setting up an SSH server from the page: look at its host key, trust it,
// put claudeguard's own key on it.

// hostKey shows the key of a server from the list or of the address typed
// in setup.
func (h *handler) hostKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		tunnel.SetupRequest
	}
	if !decode(w, r, &req) {
		return
	}
	p, ok := h.m.Config().Find(req.Name)
	if req.Name == "" {
		p, ok = req.SetupRequest.Profile(), true
	}
	if !ok || p.Kind != config.KindSSH {
		jsonError(w, http.StatusBadRequest, "нет такого SSH-сервера")
		return
	}
	if err := p.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	v, err := h.keys.Inspect(ctx, p)
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, v)
}

func (h *handler) trustHostKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address     string `json:"address"`
		Fingerprint string `json:"fingerprint"`
	}
	if !decode(w, r, &req) {
		return
	}
	key, err := h.keys.Take(req.Address, req.Fingerprint)
	if err == nil {
		err = tunnel.TrustHostKey(req.Address, key)
	}
	if err == nil && h.tunnelDown() {
		// The tunnel may be waiting out a retry after "Host key verification failed".
		h.m.Restart()
	}
	reply(w, err)
}

// tunnelDown: the active server is an SSH one and its tunnel is not up.
func (h *handler) tunnelDown() bool {
	cfg := h.m.Config()
	p, ok := cfg.Find(cfg.Active)
	return ok && p.Kind == config.KindSSH && h.m.Tunnel().State == proxy.StateDown
}

func (h *handler) setupProgress(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]int32{"step": h.setupStep.Load()})
}

// setup logs in with the password once, installs claudeguard's key, adds
// the server to the list and tests it the way the tunnel will use it.
func (h *handler) setup(w http.ResponseWriter, r *http.Request) {
	var req tunnel.SetupRequest
	if !decode(w, r, &req) {
		return
	}
	p := req.Profile()
	if err := h.checkNewServer(p, req.Password); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.setupStep.Store(0)
	fail := func(code int, err error) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "step": h.setupStep.Load()})
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	if err := tunnel.SetupServer(ctx, p, req.Password, func(n int) { h.setupStep.Store(int32(n)) }); err != nil {
		fail(http.StatusBadGateway, err)
		return
	}
	if err := h.m.Update(func(c *config.Config) error { return c.Add("", p) }); err != nil {
		fail(http.StatusBadRequest, err)
		return
	}
	// The real thing: the system ssh logs in with the new key.
	tctx, tcancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer tcancel()
	writeJSON(w, map[string]any{"ok": true, "name": p.Name, "test": h.m.Test(tctx, p.Name)})
}

func (h *handler) checkNewServer(p config.Profile, password string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if password == "" {
		return errors.New("введите пароль")
	}
	if _, taken := h.m.Config().Find(p.Name); taken {
		return errors.New("сервер «" + p.Name + "» уже есть")
	}
	return nil
}
