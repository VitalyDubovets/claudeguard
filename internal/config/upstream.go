package config

import (
	"fmt"
	"net"
	"net/url"
)

// Upstream is the real proxy: socks5://[user:pass@]host:port or
// http://[user:pass@]host:port. Hostnames are always handed to the upstream
// unresolved, so DNS for Claude traffic happens on the proxy side.
type Upstream struct {
	Scheme string // socks5 | http
	Addr   string // host:port
	User   string
	Pass   string
}

// ParseUpstream reads a proxy address typed by the user.
func ParseUpstream(s string) (*Upstream, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", s, err)
	}
	up := &Upstream{Addr: u.Host}
	switch u.Scheme {
	case "socks5", "socks5h":
		up.Scheme = KindSOCKS5
	case "http":
		up.Scheme = KindHTTP
	default:
		return nil, fmt.Errorf("upstream %q: scheme must be socks5:// or http://", s)
	}
	if _, port, err := net.SplitHostPort(u.Host); err != nil || port == "" {
		return nil, fmt.Errorf("upstream %q: host:port required", s)
	}
	if u.User != nil {
		up.User = u.User.Username()
		up.Pass, _ = u.User.Password()
	}
	return up, nil
}

// String is the address without the credentials.
func (u *Upstream) String() string { return u.Scheme + "://" + u.Addr }
