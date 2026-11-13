package firewall

import (
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// StateDir is root-only: the rules, the pf token and the binary the
// LaunchDaemon runs live here.
const StateDir = "/Library/Application Support/claudeguard"

// The LaunchDaemon that loads the rules at boot and keeps them loaded.
const (
	DaemonLabel = "com.claudeguard.firewall"
	DaemonPlist = "/Library/LaunchDaemons/" + DaemonLabel + ".plist"
)

const (
	tokenFile = StateDir + "/pf.token"
	rulesFile = StateDir + "/rules.pf"
)

// tunnelInterfaces lists VPN interfaces that are up right now. The daemon
// re-runs `enable` periodically, so a VPN that connects later gets picked up
// (until then its traffic to Anthropic is blocked, i.e. we fail closed).
func tunnelInterfaces() []string {
	ifs, _ := net.Interfaces()
	var out []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		for _, p := range []string{"utun", "ipsec", "ppp", "tun", "tap", "wg"} {
			if strings.HasPrefix(i.Name, p) {
				out = append(out, i.Name)
				break
			}
		}
	}
	return out
}

// Enable loads the rules that block direct traffic to Anthropic. Needs
// admin rights.
func Enable(o Options) error {
	var tunnels []string
	if o.AllowTunnels {
		tunnels = tunnelInterfaces()
	}
	rules := renderPFRules(o.ranges(), tunnels)
	// The daemon calls this every few seconds; reload (and drop live
	// connections) only when the rules actually change, e.g. a VPN went down.
	loaded, _ := sysutil.Run("pfctl", "-a", PFAnchor, "-s", "rules")
	if prev, err := os.ReadFile(rulesFile); err == nil && string(prev) == rules && strings.Contains(loaded, "<claudeguard>") {
		return ensurePFEnabled()
	}
	f, err := os.CreateTemp("", "claudeguard-*.pf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := io.WriteString(f, rules); err != nil {
		return err
	}
	f.Close()
	// Anchors under com.apple/* are already referenced by the stock
	// /etc/pf.conf, so nothing in system files needs editing.
	if _, err := sysutil.Run("pfctl", "-a", PFAnchor, "-f", f.Name()); err != nil {
		return err
	}
	if err := ensurePFEnabled(); err != nil {
		return err
	}
	_ = os.MkdirAll(StateDir, 0o755)
	_ = os.WriteFile(rulesFile, []byte(rules), 0o644)
	// Drop connections to Anthropic that were open before the rules.
	for _, r := range o.ranges() {
		any := "0.0.0.0/0"
		if strings.Contains(r, ":") {
			any = "::/0"
		}
		_, _ = sysutil.Run("pfctl", "-k", any, "-k", r)
	}
	return nil
}

var tokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// ensurePFEnabled holds our own pf enable reference, so pf stays on even if
// another app that enabled it releases its reference.
func ensurePFEnabled() error {
	info, _ := sysutil.Run("pfctl", "-s", "info")
	saved, _ := os.ReadFile(tokenFile)
	token := strings.TrimSpace(string(saved))
	if token != "" && strings.Contains(info, "Status: Enabled") {
		refs, err := sysutil.Run("pfctl", "-s", "References")
		if err != nil || strings.Contains(refs, token) {
			return nil
		}
	}
	out, err := sysutil.Run("pfctl", "-E")
	if err != nil {
		return err
	}
	if m := tokenRe.FindStringSubmatch(out); m != nil {
		_ = os.MkdirAll(StateDir, 0o755)
		return os.WriteFile(tokenFile, []byte(m[1]+"\n"), 0o600)
	}
	return nil
}

// Disable removes the rules. Needs admin rights.
func Disable() error {
	if _, err := sysutil.Run("pfctl", "-a", PFAnchor, "-F", "all"); err != nil {
		return err
	}
	if saved, err := os.ReadFile(tokenFile); err == nil {
		if t := strings.TrimSpace(string(saved)); t != "" {
			_, _ = sysutil.Run("pfctl", "-X", t)
		}
		_ = os.Remove(tokenFile)
	}
	return nil
}

// Status says in words whether the kill switch is in place.
func Status() string {
	if !sysutil.IsRoot() {
		if _, err := os.Stat(DaemonPlist); err != nil {
			return "not installed"
		}
		return "installed (see direct checks below)"
	}
	out, _ := sysutil.Run("pfctl", "-a", PFAnchor, "-s", "rules")
	if strings.Contains(out, "claudeguard") {
		return "active"
	}
	return "NOT loaded"
}
