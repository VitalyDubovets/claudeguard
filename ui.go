package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

//go:embed ui
var uiFiles embed.FS

// uiHandler serves the settings page and its JSON API on the proxy's port.
// Any local program can reach that port, so every API call must carry the
// token from the config (the page gets it in the URL fragment), the Host
// must be ours (no DNS rebinding) and no CORS headers are ever sent.
type uiHandler struct {
	m      *manager
	listen string
	static http.Handler
}

func newUIHandler(m *manager, listen string) http.Handler {
	sub, _ := fs.Sub(uiFiles, "ui")
	return &uiHandler{m: m, listen: listen, static: http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))}
}

func (h *uiHandler) hostOK(host string) bool {
	_, port, err := net.SplitHostPort(h.listen)
	if err != nil {
		return false
	}
	return host == h.listen || host == "127.0.0.1:"+port || host == "localhost:"+port
}

func (h *uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.hostOK(r.Host) {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}
	hd := w.Header()
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")

	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.serveAPI(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/ui" || r.URL.Path == "/ui/" {
		page, _ := uiFiles.ReadFile("ui/index.html")
		hd.Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
		return
	}
	h.static.ServeHTTP(w, r)
}

func (h *uiHandler) serveAPI(w http.ResponseWriter, r *http.Request) {
	token := h.m.config().Token
	got := r.Header.Get("X-Claudeguard-Token")
	if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
		jsonError(w, http.StatusUnauthorized, "нет доступа: откройте панель командой claudeguard ui")
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		jsonError(w, http.StatusForbidden, "чужой origin")
		return
	}
	if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		jsonError(w, http.StatusUnsupportedMediaType, "нужен application/json")
		return
	}

	switch r.Method + " " + r.URL.Path {
	case "GET /api/state":
		writeJSON(w, h.state())
	case "GET /api/check":
		writeJSON(w, h.check(r.Context()))
	case "POST /api/activate":
		var req struct{ Name string }
		if decode(w, r, &req) {
			h.reply(w, h.m.update(func(c *Config) error {
				if req.Name != "" {
					if _, ok := c.profile(req.Name); !ok {
						return errors.New("нет такого сервера")
					}
				}
				c.Active = req.Name
				return nil
			}))
		}
	case "POST /api/profile":
		var req struct {
			Old     string  `json:"old"`
			Profile Profile `json:"profile"`
		}
		if decode(w, r, &req) {
			req.Profile.Name = strings.TrimSpace(req.Profile.Name)
			req.Profile.Target = strings.TrimSpace(req.Profile.Target)
			h.reply(w, h.m.update(func(c *Config) error {
				if err := c.upsert(req.Old, req.Profile); err != nil {
					return err
				}
				if c.Active == "" && len(c.Profiles) == 1 {
					c.Active = req.Profile.Name
				}
				return nil
			}))
		}
	case "POST /api/delete":
		var req struct{ Name string }
		if decode(w, r, &req) {
			h.reply(w, h.m.update(func(c *Config) error { c.remove(req.Name); return nil }))
		}
	case "POST /api/test":
		var req struct{ Name string }
		if decode(w, r, &req) {
			ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
			defer cancel()
			writeJSON(w, h.m.testProfile(ctx, req.Name))
		}
	case "POST /api/restart":
		h.m.restart()
		h.reply(w, nil)
	case "POST /api/firewall":
		var req struct {
			AllowTunnels bool   `json:"allow_tunnels"`
			ExtraBlock   string `json:"extra_block"`
		}
		if !decode(w, r, &req) {
			return
		}
		extra, err := parseCIDRList(req.ExtraBlock)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		fw := FirewallOptions{AllowTunnels: req.AllowTunnels, Extra: extra}
		// Ask for the password first and save only what was really applied.
		// The dialog can stay open for minutes; no lock is held meanwhile.
		if err := elevateGUI(append([]string{"system-install"}, fw.args()...)); err != nil {
			jsonError(w, http.StatusBadGateway, "правила не применены: "+err.Error())
			return
		}
		h.reply(w, h.m.update(func(c *Config) error {
			c.AllowTunnels, c.ExtraBlock = fw.AllowTunnels, fw.Extra
			return nil
		}))
	case "POST /api/launch":
		h.reply(w, launchApp(h.m.config(), ""))
	default:
		jsonError(w, http.StatusNotFound, "нет такого метода")
	}
}

type profileView struct {
	Profile
	Test *testRecord `json:"test,omitempty"`
}

type stateView struct {
	Version      string        `json:"version"`
	OS           string        `json:"os"`
	Listen       string        `json:"listen"`
	Active       string        `json:"active"`
	Profiles     []profileView `json:"profiles"`
	Tunnel       tunnelState   `json:"tunnel"`
	SSHHosts     []string      `json:"ssh_hosts"`
	AllowTunnels bool          `json:"allow_tunnels"`
	ExtraBlock   []string      `json:"extra_block"`
}

func (h *uiHandler) state() stateView {
	cfg := h.m.config()
	tests := h.m.testRecords()
	v := stateView{
		Version:      version,
		OS:           runtime.GOOS,
		Listen:       cfg.Listen,
		Active:       cfg.Active,
		Profiles:     []profileView{},
		Tunnel:       h.m.tunnelState(),
		SSHHosts:     sshConfigHosts(),
		AllowTunnels: cfg.AllowTunnels,
		ExtraBlock:   cfg.ExtraBlock,
	}
	for _, p := range cfg.Profiles {
		pv := profileView{Profile: p}
		if t, ok := tests[p.Name]; ok {
			pv.Test = &t
		}
		v.Profiles = append(v.Profiles, pv)
	}
	return v
}

type checkView struct {
	Firewall string `json:"firewall"`
	DirectV4 string `json:"direct_v4"`
	DirectV6 string `json:"direct_v6"`
	Blocked  bool   `json:"blocked"`
}

// check tries api.anthropic.com directly, bypassing the proxy: with the
// kill switch on, both attempts must fail.
func (h *uiHandler) check(ctx context.Context) checkView {
	v := checkView{Firewall: firewallStatus()}
	v.DirectV4 = directProbe("tcp4", "api.anthropic.com")
	v.DirectV6 = directProbe("tcp6", "api.anthropic.com")
	v.Blocked = !strings.HasPrefix(v.DirectV4, "OPEN") && !strings.HasPrefix(v.DirectV6, "OPEN")
	return v
}

func (h *uiHandler) reply(w http.ResponseWriter, err error) {
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	if err := dec.Decode(v); err != nil {
		jsonError(w, http.StatusBadRequest, "плохой запрос: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
