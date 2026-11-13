package firewall

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// DirectProbe tries host:443 from this machine, past the proxy, and says in
// words how it went. With the kill switch on it must not get through.
func DirectProbe(network, host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip"+strings.TrimPrefix(network, "tcp"), host)
	if err != nil || len(ips) == 0 {
		return "no address (skipped)"
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), "443"))
	if err != nil {
		return "blocked/unreachable (" + sysutil.ShortErr(err) + ")"
	}
	via := ifaceOf(c.LocalAddr())
	c.Close()
	if via != "" {
		via = " via " + via
	}
	return openPrefix + ": direct connection to " + ips[0].String() + " succeeded" + via
}

const openPrefix = "OPEN"

// IsOpen reports whether a DirectProbe result means the connection got
// through.
func IsOpen(result string) bool { return strings.HasPrefix(result, openPrefix) }

// ifaceOf names the network interface that owns a local address: it tells a
// VPN tunnel (utun5, wg0) from the plain network (en0, eth0).
func ifaceOf(local net.Addr) string {
	tcp, ok := local.(*net.TCPAddr)
	if !ok {
		return ""
	}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(tcp.IP) {
				return i.Name
			}
		}
	}
	return ""
}
