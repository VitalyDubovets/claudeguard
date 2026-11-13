package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/testutil"
)

func startBridge(t *testing.T, upstreamURL string) string {
	up, err := config.ParseUpstream(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	get := func() (*config.Upstream, error) { return up, nil }
	srv := httptest.NewServer(NewServer("127.0.0.1:0", get, func() string { return "test" }, nil))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func TestCONNECTThroughSOCKS5PassesHostnameUnresolved(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from backend")
	}))
	defer backend.Close()
	socks := testutil.StartSOCKS5(t, backend.Listener.Addr().String())
	bridge := startBridge(t, "socks5://"+socks.Addr())

	client := testutil.ClientVia(bridge)
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
	if hosts := socks.Hosts(); len(hosts) != 1 || hosts[0] != "api.anthropic.invalid:443" {
		t.Fatalf("socks saw %v, want the unresolved hostname", hosts)
	}
}

func TestPlainHTTPThroughSOCKS5(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain "+r.Host)
	}))
	defer backend.Close()
	socks := testutil.StartSOCKS5(t, backend.Listener.Addr().String())
	bridge := startBridge(t, "socks5://"+socks.Addr())

	resp, err := testutil.ClientVia(bridge).Get("http://downloads.example.invalid/x")
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
	if err := ConnectVia(bridge, "api.anthropic.com:443"); err == nil || !strings.Contains(err.Error(), "502") {
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
