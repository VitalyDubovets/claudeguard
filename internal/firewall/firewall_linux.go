package firewall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// The systemd units that load the rules at boot and keep them loaded.
const (
	UnitDir = "/etc/systemd/system"
	Service = "claudeguard-firewall.service"
	Timer   = "claudeguard-firewall.timer"
)

const (
	nftTable = "claudeguard"
	iptChain = "CLAUDEGUARD"
)

// tunnelPatterns are the VPN interface names let through by --allow-tunnels.
// The firewall matches them by prefix, so a VPN that connects later is
// covered without re-applying the rules.
var tunnelPatterns = []string{"tun", "tap", "wg", "ppp", "ipsec"}

// renderNFT builds the nftables table. Everything bound for Anthropic is
// rejected, from this machine and from containers and VMs behind it, unless
// it leaves through a VPN tunnel that --allow-tunnels lets through. The
// first two lines make loading it replace an older copy in one transaction.
func renderNFT(o Options) string {
	var v4, v6 []string
	for _, r := range o.ranges() {
		if strings.Contains(r, ":") {
			v6 = append(v6, r)
		} else {
			v4 = append(v4, r)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", nftTable, nftTable, nftTable)
	fmt.Fprintf(&b, "\tset v4 { type ipv4_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(v4, ", "))
	fmt.Fprintf(&b, "\tset v6 { type ipv6_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(v6, ", "))
	b.WriteString("\tchain guard {\n")
	if o.AllowTunnels {
		for _, p := range tunnelPatterns {
			fmt.Fprintf(&b, "\t\toifname \"%s*\" return\n", p)
		}
	}
	for _, m := range []string{"ip daddr @v4", "ip6 daddr @v6"} {
		fmt.Fprintf(&b, "\t\t%s meta l4proto tcp reject with tcp reset\n\t\t%s reject\n", m, m)
	}
	b.WriteString("\t}\n")
	for _, hook := range []string{"output", "forward"} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority -10; policy accept;\n\t\tjump guard\n\t}\n", hook, hook)
	}
	b.WriteString("}\n")
	return b.String()
}

// renderIPTables is the same rule set for systems without nft, in
// iptables-restore form: with --noflush only our chain is replaced, and it
// is replaced in one commit.
func renderIPTables(o Options, v6 bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n", iptChain)
	if o.AllowTunnels {
		for _, p := range tunnelPatterns {
			fmt.Fprintf(&b, "-A %s -o %s+ -j RETURN\n", iptChain, p)
		}
	}
	for _, r := range o.ranges() {
		if strings.Contains(r, ":") != v6 {
			continue
		}
		fmt.Fprintf(&b, "-A %s -d %s -p tcp -j REJECT --reject-with tcp-reset\n-A %s -d %s -j REJECT\n", iptChain, r, iptChain, r)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// Enable loads the rules that block direct traffic to Anthropic. Needs
// admin rights.
func Enable(o Options) error {
	if sysutil.Tool("nft") != "" {
		return sysutil.RunInput(renderNFT(o), "nft", "-f", "-")
	}
	if sysutil.Tool("iptables-restore") == "" {
		return errors.New("neither nft nor iptables found: install the nftables package")
	}
	for _, fam := range []struct {
		cmd string
		v6  bool
	}{{"iptables", false}, {"ip6tables", true}} {
		if err := sysutil.RunInput(renderIPTables(o, fam.v6), fam.cmd+"-restore", "-w", "--noflush"); err != nil {
			return err
		}
		for _, chain := range []string{"OUTPUT", "FORWARD"} {
			if _, err := sysutil.Run(fam.cmd, "-w", "-C", chain, "-j", iptChain); err == nil {
				continue
			}
			if _, err := sysutil.Run(fam.cmd, "-w", "-I", chain, "1", "-j", iptChain); err != nil {
				return err
			}
		}
	}
	return nil
}

// Disable removes the rules. Needs admin rights.
func Disable() error {
	var err error
	if sysutil.Tool("nft") != "" {
		if _, e := sysutil.Run("nft", "list", "table", "inet", nftTable); e == nil {
			_, err = sysutil.Run("nft", "delete", "table", "inet", nftTable)
		}
	}
	for _, cmd := range []string{"iptables", "ip6tables"} {
		if sysutil.Tool(cmd) == "" {
			continue
		}
		if _, e := sysutil.Run(cmd, "-w", "-S", iptChain); e != nil {
			continue
		}
		for _, chain := range []string{"OUTPUT", "FORWARD"} {
			_, _ = sysutil.Run(cmd, "-w", "-D", chain, "-j", iptChain)
		}
		_, _ = sysutil.Run(cmd, "-w", "-F", iptChain)
		if _, e := sysutil.Run(cmd, "-w", "-X", iptChain); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// Status says in words whether the kill switch is in place.
func Status() string {
	if !sysutil.IsRoot() {
		if _, err := os.Stat(filepath.Join(UnitDir, Service)); err != nil {
			return "not installed"
		}
		return "installed (see direct checks below)"
	}
	if _, err := sysutil.Run("nft", "list", "table", "inet", nftTable); err == nil {
		return "active"
	}
	if _, err := sysutil.Run("iptables", "-w", "-C", "OUTPUT", "-j", iptChain); err == nil {
		return "active"
	}
	return "NOT loaded"
}
