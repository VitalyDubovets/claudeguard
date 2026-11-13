package panel

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/proxy"
	"github.com/VitalyDubovets/claudeguard/internal/testutil"
)

// startPanel runs the bridge plus settings page over a manager, like serve.
func startPanel(t *testing.T, cfg config.Config) (string, *proxy.Manager) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	cfg.Listen = listen
	cfg.Normalize()
	m := proxy.NewManager(cfg, func(config.Config) error { return nil })
	go proxy.Serve(ln, m, NewHandler(m, listen))
	t.Cleanup(func() { ln.Close(); m.Stop() })
	return listen, m
}

func uiRequest(t *testing.T, method, rawURL, host, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, rawURL, strings.NewReader(body))
	if host != "" {
		req.Host = host
	}
	if token != "" {
		req.Header.Set(TokenHeader, token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestUIAuth(t *testing.T) {
	listen, m := startPanel(t, config.Config{})
	token := m.Config().Token
	base := "http://" + listen

	if r := uiRequest(t, "GET", base+"/ui", "", "", ""); r.StatusCode != 200 || r.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("page: %d %v", r.StatusCode, r.Header)
	}
	if r := uiRequest(t, "GET", base+"/ui/app.js", "", "", ""); r.StatusCode != 200 {
		t.Fatalf("app.js: %d", r.StatusCode)
	}
	if r := uiRequest(t, "GET", base+"/api/state", "", "", ""); r.StatusCode != 401 {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	if r := uiRequest(t, "GET", base+"/api/state", "", "wrong", ""); r.StatusCode != 401 {
		t.Fatalf("bad token: %d", r.StatusCode)
	}
	if r := uiRequest(t, "GET", base+"/api/state", "evil.example:80", token, ""); r.StatusCode != 403 {
		t.Fatalf("rebinding host: %d", r.StatusCode)
	}
	req := func(origin string) int {
		rq, _ := http.NewRequest("GET", base+"/api/state", nil)
		rq.Header.Set("X-Claudeguard-Token", token)
		rq.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("must never send CORS headers")
		}
		return resp.StatusCode
	}
	if c := req("https://evil.example"); c != 403 {
		t.Fatalf("foreign origin: %d", c)
	}
	if c := req("http://" + listen); c != 200 {
		t.Fatalf("own origin: %d", c)
	}
	// A cross-site form can only send simple content types.
	form, _ := http.NewRequest("POST", base+"/api/activate", strings.NewReader("name=x"))
	form.Header.Set("X-Claudeguard-Token", token)
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := http.DefaultClient.Do(form); err != nil || resp.StatusCode != 415 {
		t.Fatalf("form post: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	if r := uiRequest(t, "GET", base+"/api/state", "", token, ""); r.StatusCode != 200 {
		t.Fatalf("with token: %d", r.StatusCode)
	}
}

func TestUIViaSelfAsProxy(t *testing.T) {
	listen, _ := startPanel(t, config.Config{})
	pu, _ := url.Parse("http://" + listen)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := c.Get("http://" + listen + "/ui")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "Claudeguard") {
		t.Fatalf("absolute-form request for our own page: %d %s", resp.StatusCode, b)
	}
}

func TestSwitchServerWithoutRestart(t *testing.T) {
	mk := func(msg string) (*httptest.Server, *testutil.SOCKS5) {
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, msg) }))
		t.Cleanup(b.Close)
		return b, testutil.StartSOCKS5(t, b.Listener.Addr().String())
	}
	_, s1 := mk("one")
	_, s2 := mk("two")
	cfg := config.Config{Active: "one", Profiles: []config.Profile{
		{Name: "one", Kind: "socks5", Target: "socks5://" + s1.Addr()},
		{Name: "two", Kind: "socks5", Target: "socks5://" + s2.Addr()},
	}}
	listen, m := startPanel(t, cfg)
	client := testutil.ClientVia(listen)
	get := func() string {
		resp, err := client.Get("http://claude.invalid/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := get(); got != "one" {
		t.Fatalf("got %q", got)
	}
	token := m.Config().Token
	if r := uiRequest(t, "POST", "http://"+listen+"/api/activate", "", token, `{"name":"two"}`); r.StatusCode != 200 {
		t.Fatalf("activate: %d", r.StatusCode)
	}
	// The same client keeps its keep-alive connection to the bridge; the
	// bridge must still send this request to the new server.
	if got := get(); got != "two" {
		t.Fatalf("after switch got %q", got)
	}
	if r := uiRequest(t, "POST", "http://"+listen+"/api/activate", "", token, `{"name":""}`); r.StatusCode != 200 {
		t.Fatalf("deactivate: %d", r.StatusCode)
	}
	resp, err := client.Get("http://claude.invalid/")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("no server selected must fail closed, got %d", resp.StatusCode)
		}
	}
}

func TestProxyPasswordStaysOnServer(t *testing.T) {
	const saved = "http://user:s3cret@proxy.example:3128"
	if got := config.RedactTarget(saved); strings.Contains(got, "s3cret") || got != "http://user@proxy.example:3128" {
		t.Errorf("redact: %s", got)
	}
	for edited, want := range map[string]string{
		"http://user@proxy.example:3128":     saved,
		"http://user@other.example:3128":     "http://user:s3cret@other.example:3128",
		"http://user:new@proxy.example:3128": "http://user:new@proxy.example:3128",
		"http://other@proxy.example:3128":    "http://other@proxy.example:3128",
		"http://proxy.example:3128":          "http://proxy.example:3128",
	} {
		if got := config.KeepPassword(saved, edited); got != want {
			t.Errorf("keepPassword(%s) = %s, want %s", edited, got, want)
		}
	}
}
