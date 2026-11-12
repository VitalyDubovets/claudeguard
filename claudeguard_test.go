package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeSOCKS5 accepts CONNECT requests, records the requested host and
// connects every request to backend.
type fakeSOCKS5 struct {
	ln      net.Listener
	backend string
	mu      sync.Mutex
	hosts   []string
}

func startFakeSOCKS5(t *testing.T, backend string) *fakeSOCKS5 {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSOCKS5{ln: ln, backend: backend}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func (s *fakeSOCKS5) handle(c net.Conn) {
	defer c.Close()
	var h [2]byte
	io.ReadFull(c, h[:])
	io.CopyN(io.Discard, c, int64(h[1]))
	c.Write([]byte{5, 0})
	var req [4]byte
	io.ReadFull(c, req[:])
	var host string
	switch req[3] {
	case 3:
		var l [1]byte
		io.ReadFull(c, l[:])
		b := make([]byte, l[0])
		io.ReadFull(c, b)
		host = string(b)
	case 1:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	}
	var p [2]byte
	io.ReadFull(c, p[:])
	s.mu.Lock()
	s.hosts = append(s.hosts, host+":"+strconv.Itoa(int(binary.BigEndian.Uint16(p[:]))))
	s.mu.Unlock()
	b, err := net.Dial("tcp", s.backend)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	pipe(c, b)
}

func startBridge(t *testing.T, upstreamURL string) string {
	up, err := parseUpstream(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	get := func() (*upstream, error) { return up, nil }
	srv := httptest.NewServer(newProxyServer("127.0.0.1:0", get, func() string { return "test" }, nil))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func clientVia(proxyAddr string) *http.Client {
	pu, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
}

func TestCONNECTThroughSOCKS5PassesHostnameUnresolved(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from backend")
	}))
	defer backend.Close()
	socks := startFakeSOCKS5(t, backend.Listener.Addr().String())
	bridge := startBridge(t, "socks5://"+socks.ln.Addr().String())

	client := clientVia(bridge)
	client.Transport.(*http.Transport).TLSClientConfig = backend.Client().Transport.(*http.Transport).TLSClientConfig
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com"
	resp, err := client.Get("https://api.anthropic.invalid:443/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from backend" {
		t.Fatalf("body = %q", body)
	}
	if len(socks.hosts) != 1 || socks.hosts[0] != "api.anthropic.invalid:443" {
		t.Fatalf("socks saw %v, want the unresolved hostname", socks.hosts)
	}
}

func TestPlainHTTPThroughSOCKS5(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain "+r.Host)
	}))
	defer backend.Close()
	socks := startFakeSOCKS5(t, backend.Listener.Addr().String())
	bridge := startBridge(t, "socks5://"+socks.ln.Addr().String())

	resp, err := clientVia(bridge).Get("http://downloads.example.invalid/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "plain downloads.example.invalid" {
		t.Fatalf("body = %q", body)
	}
}

func TestUpstreamDownFailsClosed(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	bridge := startBridge(t, "socks5://"+dead)
	if err := connectVia(bridge, "api.anthropic.com:443"); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("want 502 when upstream is down, got %v", err)
	}
}

func TestCONNECTThroughHTTPUpstream(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	var seen string
	upstreamProxy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer upstreamProxy.Close()
	go func() {
		c, err := upstreamProxy.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		req, _ := http.ReadRequest(br)
		seen = req.Host + " auth=" + req.Header.Get("Proxy-Authorization")
		b, _ := net.Dial("tcp", echo.Addr().String())
		io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
		pipe(&bufConn{Conn: c, r: br}, b)
	}()
	bridge := startBridge(t, "http://u:p@"+upstreamProxy.Addr().String())

	c, err := net.Dial("tcp", bridge)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	io.WriteString(c, "ping\n")
	line, _ := br.ReadString('\n')
	if line != "ping\n" {
		t.Fatalf("echo = %q", line)
	}
	if seen != "claude.ai:443 auth=Basic dTpw" {
		t.Fatalf("upstream saw %q", seen)
	}
}

func TestParseUpstream(t *testing.T) {
	for _, s := range []string{"socks5://127.0.0.1:1081", "socks5h://h:1", "http://user:pw@proxy:3128"} {
		if _, err := parseUpstream(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"https://proxy:443", "socks5://nohost", "127.0.0.1:1081"} {
		if _, err := parseUpstream(s); err == nil {
			t.Errorf("%s: want error", s)
		}
	}
}

func TestRenderPFRules(t *testing.T) {
	got := renderPFRules(FirewallOptions{Extra: []string{"1.2.3.4"}}.ranges(), []string{"utun4"})
	pass := strings.Index(got, "pass out quick on utun4 to <claudeguard> keep state (if-bound)")
	block := strings.Index(got, "block return out quick to <claudeguard>")
	if pass < 0 || block < 0 || pass > block {
		t.Fatalf("tunnel pass must precede the block rule:\n%s", got)
	}
	for _, r := range append(anthropicRanges, "1.2.3.4") {
		if !strings.Contains(got, r) {
			t.Errorf("missing %s", r)
		}
	}
}

func TestWindowsScript(t *testing.T) {
	s := windowsFirewallScript(FirewallOptions{})
	if !strings.Contains(s, "-Action Block") || !strings.Contains(s, "'2607:6bc0::/48'") || strings.Contains(s, "InterfaceAlias") {
		t.Fatalf("unexpected script:\n%s", s)
	}
	if s := windowsFirewallScript(FirewallOptions{AllowTunnels: true}); !strings.Contains(s, "-InterfaceAlias $phys") || !strings.Contains(s, "Get-NetAdapter -Physical") {
		t.Fatalf("tunnel mode must limit the rule to physical adapters:\n%s", s)
	}
}

func TestSettingsMergeAndRevert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	m := map[string]any{"model": "opus", "env": map[string]any{"FOO": "1", "HTTPS_PROXY": "http://other:1"}}
	setProxyEnv(m, "http://127.0.0.1:41080")
	if err := writeSettings(path, m); err != nil {
		t.Fatal(err)
	}
	m, _ = readSettings(path)
	env := m["env"].(map[string]any)
	if env["HTTPS_PROXY"] != "http://127.0.0.1:41080" || env["FOO"] != "1" || m["model"] != "opus" {
		t.Fatalf("merge lost data: %v", m)
	}
	clearProxyEnv(m, "http://127.0.0.1:41080")
	env = m["env"].(map[string]any)
	if _, ok := env["HTTPS_PROXY"]; ok || env["FOO"] != "1" {
		t.Fatalf("revert wrong: %v", m)
	}
}

func TestParseCIDRList(t *testing.T) {
	got, err := parseCIDRList("1.2.3.0/24, 2001:db8::1")
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := parseCIDRList("1.2.3.0/24; rm -rf"); err == nil {
		t.Fatal("want error")
	}
}

func TestSSHArgs(t *testing.T) {
	args := strings.Join(sshArgs("vd-poland", 41081), " ")
	for _, want := range []string{"-D 127.0.0.1:41081", "BatchMode=yes", "ControlMaster=no", "ControlPath=none"} {
		if !strings.Contains(args, want) {
			t.Fatalf("ssh args lack %q: %s", want, args)
		}
	}
	if !strings.HasSuffix(args, "vd-poland") {
		t.Fatalf("ssh args: %s", args)
	}
}

func TestNormalizeMigratesLegacyConfig(t *testing.T) {
	c := Config{SSHHost: "vd-poland"}
	c.normalize()
	if len(c.Profiles) != 1 || c.Active != "vd-poland" || c.Profiles[0].Kind != "ssh" || c.SSHHost != "" {
		t.Fatalf("%+v", c)
	}
	if c.Listen != defaultListen || len(c.Token) != 32 {
		t.Fatalf("defaults: %+v", c)
	}
	c = Config{Upstream: "socks5://u:p@10.0.0.1:1080"}
	c.normalize()
	if c.Active != "10.0.0.1" || c.Profiles[0].Kind != "socks5" {
		t.Fatalf("%+v", c)
	}
	c = Config{Active: "gone", Profiles: []Profile{{Name: "a", Kind: "ssh", Target: "a"}}}
	c.normalize()
	if c.Active != "" {
		t.Fatal("unknown active profile must be cleared")
	}
}

func TestProfileValidate(t *testing.T) {
	good := []Profile{
		{Name: "p", Kind: "ssh", Target: "vd-poland"},
		{Name: "p", Kind: "ssh", Target: "root@1.2.3.4"},
		{Name: "p", Kind: "socks5", Target: "socks5://127.0.0.1:1080"},
		{Name: "p", Kind: "http", Target: "http://u:p@proxy:3128"},
	}
	for _, p := range good {
		if err := p.validate(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []Profile{
		{Name: "", Kind: "ssh", Target: "x"},
		{Name: "p", Kind: "ssh", Target: "-oProxyCommand=evil"},
		{Name: "p", Kind: "ssh", Target: "host; rm -rf ~"},
		{Name: "p", Kind: "socks5", Target: "http://proxy:3128"},
		{Name: "p", Kind: "http", Target: "proxy"},
		{Name: "p", Kind: "ftp", Target: "ftp://x:1"},
	}
	for _, p := range bad {
		if err := p.validate(); err == nil {
			t.Errorf("%+v: want error", p)
		}
	}
}

func TestUpsertRemove(t *testing.T) {
	var c Config
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.upsert("", Profile{Name: "a", Kind: "ssh", Target: "a"}))
	must(c.upsert("", Profile{Name: "b", Kind: "ssh", Target: "b"}))
	c.Active = "a"
	if err := c.upsert("a", Profile{Name: "b", Kind: "ssh", Target: "a"}); err == nil {
		t.Fatal("renaming onto an existing name must fail")
	}
	must(c.upsert("a", Profile{Name: "a2", Kind: "ssh", Target: "a"}))
	if c.Active != "a2" || len(c.Profiles) != 2 {
		t.Fatalf("rename must follow the active profile: %+v", c)
	}
	c.remove("a2")
	if c.Active != "" || len(c.Profiles) != 1 {
		t.Fatalf("%+v", c)
	}
}

// startPanel runs the bridge plus settings page over a manager, like serve.
func startPanel(t *testing.T, cfg Config) (string, *manager) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	cfg.Listen = listen
	cfg.normalize()
	m := newManager(cfg, func(Config) error { return nil })
	ps := newProxyServer(listen, m.upstream, m.identity, newUIHandler(m, listen))
	m.onSwitch = ps.tr.CloseIdleConnections
	srv := &http.Server{Handler: ps}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return listen, m
}

func uiRequest(t *testing.T, method, rawURL, host, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, rawURL, strings.NewReader(body))
	if host != "" {
		req.Host = host
	}
	if token != "" {
		req.Header.Set("X-Claudeguard-Token", token)
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
	listen, m := startPanel(t, Config{})
	token := m.config().Token
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
	listen, _ := startPanel(t, Config{})
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
	mk := func(msg string) (*httptest.Server, *fakeSOCKS5) {
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, msg) }))
		t.Cleanup(b.Close)
		return b, startFakeSOCKS5(t, b.Listener.Addr().String())
	}
	_, s1 := mk("one")
	_, s2 := mk("two")
	cfg := Config{Active: "one", Profiles: []Profile{
		{Name: "one", Kind: "socks5", Target: "socks5://" + s1.ln.Addr().String()},
		{Name: "two", Kind: "socks5", Target: "socks5://" + s2.ln.Addr().String()},
	}}
	listen, m := startPanel(t, cfg)
	client := clientVia(listen)
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
	token := m.config().Token
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
