package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/tunnel"
)

// Another program holds the tunnel's port and ssh never binds it: the
// tunnel must not be reported as ready.
func TestTunnelPortTakenByAnotherProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a shell stub for ssh")
	}
	dir := t.TempDir()
	stub := "#!/bin/sh\nsleep 2\necho 'bind [127.0.0.1]: Address already in use' >&2\nexit 255\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ready := false
	exited, _, err := tunnel.Start(context.Background(), config.Profile{Name: "s", Kind: "ssh", Target: "srv.example"}, ln.Addr().(*net.TCPAddr).Port, func() { ready = true })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("stub ssh did not exit")
	}
	if ready {
		t.Fatal("tunnel reported ready on a port another process listens on")
	}
}

func TestBridgeHasNoUpstreamWhileTunnelIsDown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nexit 255\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfg := config.Default()
	cfg.Profiles = []config.Profile{{Name: "s", Kind: "ssh", Target: "srv.example"}}
	cfg.Active = "s"
	m := NewManager(cfg, func(config.Config) error { return nil })
	defer m.Stop()
	for i := 0; i < 20; i++ {
		if up, err := m.upstream(); err == nil {
			t.Fatalf("bridge got upstream %v with no tunnel", up)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestForeignHostIsRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	ps := NewServer(listen, func() (*config.Upstream, error) { return nil, fmt.Errorf("none") }, func() string { return "secret-name" }, nil)
	ps.proof = func(nonce string) string { return identityProof("tok", nonce) }
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: ps}}
	srv.Start()
	defer srv.Close()

	raw := func(req string) string {
		c, err := net.Dial("tcp", listen)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprint(c, req)
		line, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(line)
	}
	for _, req := range []string{
		"GET /claudeguard HTTP/1.1\r\nHost: evil.example\r\n\r\n",
		"GET /ui HTTP/1.1\r\nHost: evil.example\r\n\r\n",
	} {
		if got := raw(req); !strings.Contains(got, "403") {
			t.Errorf("%q: %s", strings.SplitN(req, "\r\n", 2)[0], got)
		}
	}
	if got := raw("GET /claudeguard HTTP/1.1\r\nHost: " + listen + "\r\n\r\n"); !strings.Contains(got, "200") {
		t.Errorf("own host: %s", got)
	}

	cfg := config.Config{Listen: listen, Token: "tok"}
	if id := Identify(cfg); !id.Running() {
		t.Errorf("our proxy: %s", id)
	}
	cfg.Token = "other"
	if id := Identify(cfg); id.Running() || id.Owner != Stranger {
		t.Errorf("a listener without our token passed as ours: %s", id)
	}
}
