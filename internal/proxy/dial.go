package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
)

// dial opens a connection to target through the upstream proxy u.
func dial(ctx context.Context, u *config.Upstream, target string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := d.DialContext(ctx, "tcp", u.Addr)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s unreachable: %w", u.Addr, err)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	var conn net.Conn
	switch u.Scheme {
	case "socks5":
		err = socks5Connect(c, target, u.User, u.Pass)
		conn = c
	default:
		conn, err = httpConnect(c, target, u.User, u.Pass)
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
