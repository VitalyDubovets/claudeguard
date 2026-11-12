package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// upstream is the real proxy: socks5://[user:pass@]host:port or
// http://[user:pass@]host:port. Hostnames are always handed to the upstream
// unresolved, so DNS for Claude traffic happens on the proxy side.
type upstream struct {
	scheme string
	addr   string
	user   string
	pass   string
}

func parseUpstream(s string) (*upstream, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", s, err)
	}
	up := &upstream{addr: u.Host}
	switch u.Scheme {
	case "socks5", "socks5h":
		up.scheme = "socks5"
	case "http":
		up.scheme = "http"
	default:
		return nil, fmt.Errorf("upstream %q: scheme must be socks5:// or http://", s)
	}
	if _, port, err := net.SplitHostPort(u.Host); err != nil || port == "" {
		return nil, fmt.Errorf("upstream %q: host:port required", s)
	}
	if u.User != nil {
		up.user = u.User.Username()
		up.pass, _ = u.User.Password()
	}
	return up, nil
}

func (u *upstream) String() string { return u.scheme + "://" + u.addr }

func (u *upstream) dial(ctx context.Context, target string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s unreachable: %w", u.addr, err)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	var conn net.Conn
	switch u.scheme {
	case "socks5":
		err = socks5Connect(c, target, u.user, u.pass)
		conn = c
	default:
		conn, err = httpConnect(c, target, u.user, u.pass)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return conn, nil
}

func socks5Connect(c net.Conn, target, user, pass string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("bad port in %q", target)
	}

	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x02}
	}
	if _, err := c.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var hello [2]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	if hello[0] != 5 {
		return errors.New("upstream is not a SOCKS5 proxy")
	}
	switch hello[1] {
	case 0x00:
	case 0x02:
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("socks5 credentials too long")
		}
		req := []byte{1, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := c.Write(req); err != nil {
			return err
		}
		var st [2]byte
		if _, err := io.ReadFull(c, st[:]); err != nil {
			return err
		}
		if st[1] != 0 {
			return errors.New("socks5 authentication failed")
		}
	default:
		return fmt.Errorf("socks5: no acceptable auth method (0x%02x)", hello[1])
	}

	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(append(req, 1), ip4...)
		} else {
			req = append(append(req, 4), ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("hostname too long")
		}
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return err
	}

	var rep [4]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return fmt.Errorf("socks5 reply: %w", err)
	}
	if rep[1] != 0 {
		return fmt.Errorf("socks5 connect to %s refused (code %d)", target, rep[1])
	}
	var skip int
	switch rep[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("socks5: bad address type %d", rep[3])
	}
	_, err = io.CopyN(io.Discard, c, int64(skip+2))
	return err
}

func httpConnect(c net.Conn, target, user, pass string) (net.Conn, error) {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if user != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		return nil, err
	}
	// The proxy's answer is a status line and a few headers; without a cap a
	// hostile proxy could feed us an endless header.
	lr := &io.LimitedReader{R: c, N: 64 << 10}
	br := bufio.NewReader(lr)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("http proxy CONNECT: %w", err)
	}
	lr.N = math.MaxInt64 // the tunnel itself has no limit
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http proxy CONNECT %s: %s", target, resp.Status)
	}
	return &bufConn{Conn: c, r: br}, nil
}

// bufConn keeps bytes a bufio.Reader already pulled off the wire.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}

// proxyServer is a local HTTP proxy (CONNECT plus plain HTTP) that sends
// everything to the current upstream. If the upstream is down, requests
// fail; there is no direct fallback. It also serves the settings UI.
type proxyServer struct {
	get     func() (*upstream, error)
	name    func() string
	listen  string
	ui      http.Handler
	proof   func(nonce string) string
	tr      *http.Transport
	forward *httputil.ReverseProxy
}

func newProxyServer(listen string, get func() (*upstream, error), name func() string, ui http.Handler) *proxyServer {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			up, err := get()
			if err != nil {
				return nil, err
			}
			return up.dial(ctx, addr)
		},
		MaxIdleConns:        16,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	return &proxyServer{
		get:    get,
		name:   name,
		listen: listen,
		ui:     ui,
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
func (p *proxyServer) isSelf(hostport string) bool {
	_, port, err := net.SplitHostPort(p.listen)
	if err != nil {
		return false
	}
	return hostport == p.listen || hostport == "127.0.0.1:"+port || hostport == "localhost:"+port
}

func (p *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
			io.WriteString(w, "claudeguard "+version+" -> "+p.name()+"\n")
			// Proof that this is the user's own claudeguard and not another
			// program on the port: only we know the token.
			if nonce := r.URL.Query().Get("nonce"); nonce != "" && p.proof != nil {
				io.WriteString(w, "proof "+p.proof(nonce)+"\n")
			}
		case p.ui != nil && (r.URL.Path == "/ui" || strings.HasPrefix(r.URL.Path, "/ui/") || strings.HasPrefix(r.URL.Path, "/api/")):
			p.ui.ServeHTTP(w, r)
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

func (p *proxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	up, err := p.get()
	var remote net.Conn
	if err == nil {
		remote, err = up.dial(ctx, target)
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

func runProxy(listen string, m *manager) error {
	ln, err := listenLoopback(listen)
	if err != nil {
		return err
	}
	ps := newProxyServer(listen, m.upstream, m.identity, newUIHandler(m, listen))
	m.mu.Lock()
	m.onSwitch = ps.tr.CloseIdleConnections
	m.mu.Unlock()
	log.Printf("claudeguard %s: http://%s -> %s (settings: http://%s/ui)", version, listen, m.identity(), listen)
	ps.proof = func(nonce string) string { return identityProof(m.config().Token, nonce) }
	srv := &http.Server{Handler: ps, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second}
	return srv.Serve(ln)
}
