// Package panel is the settings page: the embedded web UI, its JSON API on
// the proxy's own port, and opening it in a window or a browser.
package panel

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/VitalyDubovets/claudeguard/internal/browser"
	"github.com/VitalyDubovets/claudeguard/internal/proxy"
	"github.com/VitalyDubovets/claudeguard/internal/tunnel"
)

//go:embed ui
var uiFiles embed.FS

// TokenHeader carries the access token of every API call.
const TokenHeader = "X-Claudeguard-Token"

// handler serves the settings page and its JSON API on the proxy's port.
// Any local program can reach that port, so every API call must carry the
// token from the config (the page gets it in the URL fragment), the Host
// must be ours (no DNS rebinding) and no CORS headers are ever sent.
type handler struct {
	m      *proxy.Manager
	listen string
	static http.Handler
	routes map[string]http.HandlerFunc
	keys   tunnel.HostKeys
	// setupStep is how far the running /api/setup has got, for the panel.
	setupStep atomic.Int32
}

// NewHandler returns what the proxy answers on /ui, /api/ and /proxy.pac.
func NewHandler(m *proxy.Manager, listen string) http.Handler {
	sub, _ := fs.Sub(uiFiles, "ui")
	h := &handler{m: m, listen: listen, static: http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))}
	h.routes = map[string]http.HandlerFunc{
		"GET /api/state":      h.getState,
		"GET /api/check":      h.getCheck,
		"POST /api/activate":  h.activate,
		"POST /api/profile":   h.saveProfile,
		"POST /api/delete":    h.deleteProfile,
		"POST /api/test":      h.testProfile,
		"POST /api/restart":   h.restart,
		"POST /api/browser":   h.setBrowserProxy,
		"POST /api/firewall":  h.setFirewall,
		"POST /api/hostkey":   h.hostKey,
		"POST /api/trust":     h.trustHostKey,
		"GET /api/setup":      h.setupProgress,
		"POST /api/setup":     h.setup,
		"POST /api/launch":    h.launchClaude,
		"POST /api/uninstall": h.uninstall,
	}
	return h
}

func (h *handler) hostOK(host string) bool {
	_, port, err := net.SplitHostPort(h.listen)
	if err != nil {
		return false
	}
	return host == h.listen || host == "127.0.0.1:"+port || host == "localhost:"+port
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	switch r.URL.Path {
	case "/proxy.pac":
		// Browsers fetch this without a token; it holds nothing private.
		hd.Set("Content-Type", "application/x-ns-proxy-autoconfig")
		io.WriteString(w, browser.PACFile(h.listen))
	case "/ui", "/ui/":
		page, _ := uiFiles.ReadFile("ui/index.html")
		hd.Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	default:
		h.static.ServeHTTP(w, r)
	}
}

// serveAPI lets a call through to its route only with the token, from our
// own page and, for a POST, with a JSON body.
func (h *handler) serveAPI(w http.ResponseWriter, r *http.Request) {
	token := h.m.Config().Token
	got := r.Header.Get(TokenHeader)
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
	route, ok := h.routes[r.Method+" "+r.URL.Path]
	if !ok {
		jsonError(w, http.StatusNotFound, "нет такого метода")
		return
	}
	route(w, r)
}

// reply answers a call that returns nothing but success or an error.
func reply(w http.ResponseWriter, err error) {
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
