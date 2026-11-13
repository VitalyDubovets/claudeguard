// Package proxy is the local HTTP proxy Claude talks to. The Server forwards
// every connection to the active upstream; the Manager owns the live config
// and keeps that upstream (an ssh tunnel or a ready-made proxy) available.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/version"
)

// Server is a local HTTP proxy (CONNECT plus plain HTTP) that sends
// everything to the current upstream. If the upstream is down, requests
// fail; there is no direct fallback. Requests addressed to the proxy itself
// (the settings page, its API, the PAC file) go to the local handler.
type Server struct {
	get     func() (*config.Upstream, error)
	name    func() string
	listen  string
	local   http.Handler
	proof   func(nonce string) string
	tr      *http.Transport
	forward *httputil.ReverseProxy
}

// NewServer builds a proxy on listen. get returns the upstream to use for
// the next connection, name what to call it in the banner; local may be nil.
func NewServer(listen string, get func() (*config.Upstream, error), name func() string, local http.Handler) *Server {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			up, err := get()
			if err != nil {
				return nil, err
			}
			return dial(ctx, up, addr)
		},
		MaxIdleConns:        16,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	return &Server{
		get:    get,
		name:   name,
		listen: listen,
		local:  local,
		tr:     tr,
		forward: &httputil.ReverseProxy{
			Rewrite:   func(*httputil.ProxyRequest) {},
			Transport: tr,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("forward %s: %v", r.URL.Host, err)
				http.Error(w, "claudeguard: "+err.Error(), http.StatusBadGateway)
			},
		},
	}
}

// isSelf reports whether hostport is this proxy's own address. A browser
// pointed at us as a proxy asks for http://127.0.0.1:41080/ui in absolute
// form; forwarding that would reach the remote server's loopback instead.
func (p *Server) isSelf(hostport string) bool {
	_, port, err := net.SplitHostPort(p.listen)
	if err != nil {
		return false
	}
	return hostport == p.listen || hostport == "127.0.0.1:"+port || hostport == "localhost:"+port
}

func (p *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if r.URL.IsAbs() && p.isSelf(r.URL.Host) {
		// net/http already took the Host from the absolute URL, so the
		// checks below see our own name here.
		r.URL.Scheme, r.URL.Host = "", ""
		r.Host = p.listen
	}
	if !r.URL.IsAbs() {
		switch {
		case !p.isSelf(r.Host):
			http.Error(w, "forbidden host", http.StatusForbidden)
		case r.URL.Path == "/claudeguard":
			io.WriteString(w, "claudeguard "+version.Version+" -> "+p.name()+"\n")
			// Proof that this is the user's own claudeguard and not another
			// program on the port: only we know the token.
			if nonce := r.URL.Query().Get("nonce"); nonce != "" && p.proof != nil {
				io.WriteString(w, "proof "+p.proof(nonce)+"\n")
			}
		case p.local != nil && isLocalPath(r.URL.Path):
			p.local.ServeHTTP(w, r)
		default:
			http.Error(w, "claudeguard is a proxy; the settings page is at /ui", http.StatusBadRequest)
		}
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "claudeguard is a proxy; send absolute http:// URLs or CONNECT", http.StatusBadRequest)
		return
	}
	p.forward.ServeHTTP(w, r)
}

// isLocalPath: what the proxy answers itself instead of forwarding.
func isLocalPath(path string) bool {
	return path == "/ui" || path == "/proxy.pac" || strings.HasPrefix(path, "/ui/") || strings.HasPrefix(path, "/api/")
}

func (p *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	up, err := p.get()
	var remote net.Conn
	if err == nil {
		remote, err = dial(ctx, up, target)
	}
	if err != nil {
		log.Printf("CONNECT %s: %v", target, err)
		http.Error(w, "claudeguard: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		remote.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		remote.Close()
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		remote.Close()
		return
	}
	pipe(&bufConn{Conn: client, r: rw.Reader}, remote)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// listenLoopback refuses anything but a loopback address: the proxy has no
// authentication of its own.
func listenLoopback(listen string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", listen, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("listen %q: only loopback addresses are allowed", listen)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s (already running?): %w", listen, err)
	}
	return ln, nil
}

// Run serves the proxy on listen until it fails. Traffic follows the
// manager's active server; local answers the proxy's own pages.
func Run(listen string, m *Manager, local http.Handler) error {
	ln, err := listenLoopback(listen)
	if err != nil {
		return err
	}
	return Serve(ln, m, local)
}

// Serve is Run on a listener the caller opened.
func Serve(ln net.Listener, m *Manager, local http.Handler) error {
	listen := ln.Addr().String()
	ps := NewServer(listen, m.upstream, m.activeName, local)
	// Pooled keep-alive connections still lead to the previous server.
	m.setOnSwitch(ps.tr.CloseIdleConnections)
	log.Printf("claudeguard %s: http://%s -> %s (settings: http://%s/ui)", version.Version, listen, m.activeName(), listen)
	ps.proof = func(nonce string) string { return identityProof(m.Config().Token, nonce) }
	srv := &http.Server{Handler: ps, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second}
	return srv.Serve(ln)
}
