package testutil

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

// SOCKS5 is a fake SOCKS5 proxy: it accepts CONNECT requests, records the
// requested host and connects every request to one backend.
type SOCKS5 struct {
	ln      net.Listener
	backend string
	mu      sync.Mutex
	hosts   []string
}

// StartSOCKS5 runs a SOCKS5 until the test ends.
func StartSOCKS5(t *testing.T, backend string) *SOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &SOCKS5{ln: ln, backend: backend}
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

// Addr is where the proxy listens.
func (s *SOCKS5) Addr() string { return s.ln.Addr().String() }

// Hosts returns the host:port of every request so far, as the client sent it.
func (s *SOCKS5) Hosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hosts...)
}

func (s *SOCKS5) handle(c net.Conn) {
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
	defer b.Close()
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, c); done <- struct{}{} }()
	go func() { io.Copy(c, b); done <- struct{}{} }()
	<-done
}

// ClientVia returns an HTTP client that goes through the HTTP proxy at addr.
func ClientVia(addr string) *http.Client {
	pu, _ := url.Parse("http://" + addr)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
}
