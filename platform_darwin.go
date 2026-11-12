package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	stateDir = "/Library/Application Support/claudeguard"
	// The root daemon runs this copy. It sits in a directory only root can
	// write; /usr/local/bin belongs to the user on some Macs.
	binPath      = stateDir + "/claudeguard"
	cliLink      = "/usr/local/bin/claudeguard"
	tokenFile    = stateDir + "/pf.token"
	rulesFile    = stateDir + "/rules.pf"
	daemonLabel  = "com.claudeguard.firewall"
	daemonPlist  = "/Library/LaunchDaemons/" + daemonLabel + ".plist"
	agentLabel   = "com.claudeguard.proxy"
	trayLabel    = "com.claudeguard.tray"
	launcherName = "Claude via Proxy.app"
	uiAppName    = "Claudeguard.app"
	defaultApp   = "/Applications/Claude.app"
)

func isRoot() bool { return os.Geteuid() == 0 }

func elevate(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(systemTools["sudo"], append([]string{exe}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// elevateGUI asks for the admin password in a system dialog; the settings
// page runs in a background process that has no terminal for sudo.
func elevateGUI(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, 0, len(args)+1)
	for _, a := range append([]string{exe}, args...) {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	shell := strings.Join(quoted, " ")
	lit := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(shell)
	out, err := exec.Command(systemTools["osascript"], "-e",
		`do shell script "`+lit+`" with prompt "Claudeguard меняет правила kill switch." with administrator privileges`).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "-128") {
			return errors.New("отменено")
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// listenerPID is the process of this user that listens on 127.0.0.1:port,
// or 0. lsof shows a non-root user only their own sockets, which is the point.
func listenerPID(port int) int {
	out, _ := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-iTCP@127.0.0.1:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fp").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "p") {
			pid, _ := strconv.Atoi(line[1:])
			return pid
		}
	}
	return 0
}

func openBrowser(url string) error { return exec.Command(systemTools["open"], url).Run() }

// systemTools pins the tools we run, some of them as root, to their system
// locations: PATH is the user's and may list a writable directory first.
var systemTools = map[string]string{
	"pfctl": "/sbin/pfctl", "launchctl": "/bin/launchctl", "sudo": "/usr/bin/sudo",
	"osascript": "/usr/bin/osascript", "osacompile": "/usr/bin/osacompile",
	"codesign": "/usr/bin/codesign", "open": "/usr/bin/open", "touch": "/usr/bin/touch", "pgrep": "/usr/bin/pgrep",
	"defaults": "/usr/bin/defaults",
	"pkill":    "/usr/bin/pkill",
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(systemTools[name], args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

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

func enableFirewall(o FirewallOptions) error {
	var tunnels []string
	if o.AllowTunnels {
		tunnels = tunnelInterfaces()
	}
	rules := renderPFRules(o.ranges(), tunnels)
	// The daemon calls this every few seconds; reload (and drop live
	// connections) only when the rules actually change, e.g. a VPN went down.
	loaded, _ := run("pfctl", "-a", pfAnchor, "-s", "rules")
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
	if _, err := run("pfctl", "-a", pfAnchor, "-f", f.Name()); err != nil {
		return err
	}
	if err := ensurePFEnabled(); err != nil {
		return err
	}
	_ = os.MkdirAll(stateDir, 0o755)
	_ = os.WriteFile(rulesFile, []byte(rules), 0o644)
	// Drop connections to Anthropic that were open before the rules.
	for _, r := range o.ranges() {
		any := "0.0.0.0/0"
		if strings.Contains(r, ":") {
			any = "::/0"
		}
		_, _ = run("pfctl", "-k", any, "-k", r)
	}
	return nil
}

var tokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// ensurePFEnabled holds our own pf enable reference, so pf stays on even if
// another app that enabled it releases its reference.
func ensurePFEnabled() error {
	info, _ := run("pfctl", "-s", "info")
	saved, _ := os.ReadFile(tokenFile)
	token := strings.TrimSpace(string(saved))
	if token != "" && strings.Contains(info, "Status: Enabled") {
		refs, err := run("pfctl", "-s", "References")
		if err != nil || strings.Contains(refs, token) {
			return nil
		}
	}
	out, err := run("pfctl", "-E")
	if err != nil {
		return err
	}
	if m := tokenRe.FindStringSubmatch(out); m != nil {
		_ = os.MkdirAll(stateDir, 0o755)
		return os.WriteFile(tokenFile, []byte(m[1]+"\n"), 0o600)
	}
	return nil
}

func disableFirewall() error {
	if _, err := run("pfctl", "-a", pfAnchor, "-F", "all"); err != nil {
		return err
	}
	if saved, err := os.ReadFile(tokenFile); err == nil {
		if t := strings.TrimSpace(string(saved)); t != "" {
			_, _ = run("pfctl", "-X", t)
		}
		_ = os.Remove(tokenFile)
	}
	return nil
}

func firewallStatus() string {
	if !isRoot() {
		if _, err := os.Stat(daemonPlist); err != nil {
			return "not installed"
		}
		return "installed (see direct checks below)"
	}
	out, _ := run("pfctl", "-a", pfAnchor, "-s", "rules")
	if strings.Contains(out, "claudeguard") {
		return "active"
	}
	return "NOT loaded"
}

func plist(label string, args []string, extra string) string {
	var a strings.Builder
	for _, s := range args {
		fmt.Fprintf(&a, "\t\t<string>%s</string>\n", xmlEscape(s))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>RunAtLoad</key>
	<true/>
%s</dict>
</plist>
`, label, a.String(), extra)
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func copyFile(src, dst string, mode os.FileMode) error {
	if src == dst {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// Never write through something that is already there: as root, a
	// planted symlink would overwrite whatever it points at.
	tmp := dst + ".new"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func systemInstall(o FirewallOptions) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	if err := copyFile(exe, binPath, 0o755); err != nil {
		return err
	}
	// `claudeguard` in a terminal; best effort, the app works without it.
	if os.MkdirAll(filepath.Dir(cliLink), 0o755) == nil {
		_ = os.Remove(cliLink)
		_ = os.Symlink(binPath, cliLink)
	}
	if err := enableFirewall(o); err != nil {
		return err
	}
	// The daemon re-applies the rules at boot and every minute (every 15 s
	// with --allow-tunnels, to follow VPN interfaces coming and going).
	interval := 60
	if o.AllowTunnels {
		interval = 15
	}
	extra := fmt.Sprintf("\t<key>StartInterval</key>\n\t<integer>%d</integer>\n", interval)
	p := plist(daemonLabel, append([]string{binPath, "enable"}, o.args()...), extra)
	if err := os.WriteFile(daemonPlist, []byte(p), 0o644); err != nil {
		return err
	}
	_, _ = run("launchctl", "bootout", "system/"+daemonLabel)
	if _, err := run("launchctl", "bootstrap", "system", daemonPlist); err != nil {
		return err
	}
	fmt.Println("   pf anchor", pfAnchor, "loaded; LaunchDaemon", daemonLabel, "installed")
	return nil
}

func systemUninstall() error {
	_, _ = run("launchctl", "bootout", "system/"+daemonLabel)
	_ = os.Remove(daemonPlist)
	err := disableFirewall()
	if dst, e := os.Readlink(cliLink); e == nil && dst == binPath {
		_ = os.Remove(cliLink)
	}
	_ = os.RemoveAll(stateDir)
	return err
}

func agentPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", agentLabel+".plist")
}

func launcherPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", launcherName)
}

func uiAppPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", uiAppName)
}

func userInstall(cfg Config, launcher bool) error {
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, "Library", "Logs", "claudeguard.log")
	extra := "\t<key>KeepAlive</key>\n\t<true/>\n" +
		"\t<key>StandardOutPath</key>\n\t<string>" + xmlEscape(logPath) + "</string>\n" +
		"\t<key>StandardErrorPath</key>\n\t<string>" + xmlEscape(logPath) + "</string>\n"
	p := agentPlistPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(plist(agentLabel, []string{binPath, "serve"}, extra)), 0o644); err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = run("launchctl", "bootout", domain+"/"+agentLabel)
	if _, err := run("launchctl", "bootstrap", domain, p); err != nil {
		return err
	}
	fmt.Println("   local proxy", cfg.proxyURL(), "runs as LaunchAgent", agentLabel, "(log:", logPath+")")

	if launcher {
		for _, l := range []struct {
			path, cmd string
			icon      []byte
		}{
			{launcherPath(), "launch", launcherIcon},
			{uiAppPath(), "ui", uiIcon},
		} {
			_ = os.MkdirAll(filepath.Dir(l.path), 0o755)
			_ = os.RemoveAll(l.path)
			// Claudeguard.app itself opens the settings page.
			if l.cmd == "ui" && launchedFromGUI() {
				continue
			}
			script := fmt.Sprintf(`do shell script quoted form of "%s" & " %s > /dev/null 2>&1 &"`, binPath, l.cmd)
			if _, err := run("osacompile", "-o", l.path, "-e", script); err != nil {
				return err
			}
			// osacompile gives every applet the same script icon.
			if err := os.WriteFile(filepath.Join(l.path, "Contents", "Resources", "applet.icns"), l.icon, 0o644); err == nil {
				_ = os.Remove(filepath.Join(l.path, "Contents", "Resources", "Assets.car"))
				// The applet is ad-hoc signed; seal the changed resources again.
				_, _ = run("codesign", "--force", "--sign", "-", l.path)
				_, _ = run("touch", l.path)
			}
			fmt.Println("   launcher:", l.path)
		}
	}
	return nil
}

func trayPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", trayLabel+".plist")
}

// trayInstall starts the menu bar icon now and at every login. No KeepAlive:
// "Убрать значок" in its menu must be able to quit it until the next login.
func trayInstall() error {
	p := trayPlistPath()
	extra := "\t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>\n"
	if err := os.WriteFile(p, []byte(plist(trayLabel, []string{binPath, "tray"}, extra)), 0o644); err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = run("launchctl", "bootout", domain+"/"+trayLabel)
	if _, err := run("launchctl", "bootstrap", domain, p); err != nil {
		return err
	}
	fmt.Println("   menu bar icon runs as LaunchAgent", trayLabel)
	return nil
}

// userUninstall also clears what macOS keeps for the settings window and
// moves the app itself to the Trash.
func userUninstall() (notes []string, err error) {
	_, _ = run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+agentLabel)
	_, _ = run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+trayLabel)
	_ = os.Remove(trayPlistPath())
	_ = os.Remove(agentPlistPath())
	_ = os.RemoveAll(launcherPath())
	_ = os.RemoveAll(uiAppPath())
	_ = os.Remove(filepath.Dir(uiAppPath())) // ~/Applications, if the install made it
	if home, err := os.UserHomeDir(); err == nil {
		lib := filepath.Join(home, "Library")
		_ = os.Remove(filepath.Join(lib, "Logs", "claudeguard.log"))
		// The window runs inside Claudeguard.app or as a bare binary.
		for _, id := range []string{"com.claudeguard.app", "claudeguard"} {
			for _, p := range []string{
				"WebKit/" + id, "Caches/" + id, "HTTPStorages/" + id, "HTTPStorages/" + id + ".binarycookies",
				"Cookies/" + id + ".binarycookies", "Saved Application State/" + id + ".savedState",
			} {
				_ = os.RemoveAll(filepath.Join(lib, filepath.FromSlash(p)))
			}
			_, _ = run("defaults", "delete", id)
		}
	}
	if app := appBundle(); app != "" && !strings.HasPrefix(app, "/Volumes/") && !trash(app) {
		notes = append(notes, "Осталось перетащить Claudeguard из папки «Программы» в Корзину.")
	}
	return notes, nil
}

// stopProxy ends a proxy that launchd does not know about: one the app
// started on its own outlives the bootout of the agent.
func stopProxy() {
	_, _ = run("pkill", "-u", strconv.Itoa(os.Getuid()), "-f", "/claudeguard serve( |$)")
}

func detachServe(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func claudeRunning() bool {
	return exec.Command(systemTools["pgrep"], "-x", "Claude").Run() == nil
}

// launchApp restarts the desktop app with Chromium's --proxy-server switch.
// Chromium never falls back to a direct connection when that proxy fails.
func launchApp(cfg Config, app string) error {
	if app == "" {
		app = defaultApp
	}
	if _, err := os.Stat(app); err != nil {
		return fmt.Errorf("Claude app not found at %s (use --app)", app)
	}
	if claudeRunning() {
		fmt.Println("Quitting Claude...")
		_, _ = run("osascript", "-e", `quit app "Claude"`)
		for i := 0; i < 30 && claudeRunning(); i++ {
			time.Sleep(500 * time.Millisecond)
		}
		if claudeRunning() {
			return errors.New("Claude is still running; quit it and try again")
		}
	}
	_, err := run("open", "-a", app, "--args", "--proxy-server="+cfg.proxyURL())
	return err
}

func hideChildWindow(*exec.Cmd) {}

// launchedFromGUI: the binary inside Claudeguard.app, started by Finder.
func launchedFromGUI() bool {
	exe, _ := os.Executable()
	return strings.Contains(exe, ".app/Contents/MacOS/")
}

func hideConsole() {}

// misplaced catches the app being run straight from the disk image: it
// would install fine, but the app itself would be gone after ejecting.
func misplaced() string {
	exe, _ := os.Executable()
	if strings.HasPrefix(exe, "/Volumes/") || strings.Contains(exe, "/AppTranslocation/") {
		return "Сначала перетащите Claudeguard в папку «Программы» и запустите его оттуда."
	}
	return ""
}

// installed reports whether both halves are in place and run this binary.
func installed() bool {
	for _, p := range []string{daemonPlist, agentPlistPath()} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	exe, _ := os.Executable()
	return sameFile(exe, binPath)
}

func dialog(kind, text string) bool {
	buttons, icon := `{"OK"} default button 1`, "note"
	switch kind {
	case "ask":
		buttons = `{"Отмена", "Установить"} default button 2 cancel button 1`
	case "error":
		icon = "stop"
	}
	lit := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(text)
	return exec.Command(systemTools["osascript"], "-e",
		`display dialog "`+lit+`" with title "Claudeguard" buttons `+buttons+` with icon `+icon).Run() == nil
}
