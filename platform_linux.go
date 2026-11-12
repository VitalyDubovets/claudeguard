package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	optDir      = "/opt/claudeguard"
	optBin      = optDir + "/claudeguard"
	unitDir     = "/etc/systemd/system"
	fwService   = "claudeguard-firewall.service"
	fwTimer     = "claudeguard-firewall.timer"
	userService = "claudeguard.service"
	nftTable    = "claudeguard"
	iptChain    = "CLAUDEGUARD"
	// A package puts its own menu entry here; then we do not add a second one.
	packagedDesktop = "/usr/share/applications/claudeguard.desktop"
)

// tunnelPatterns are the VPN interface names let through by --allow-tunnels.
// The firewall matches them by prefix, so a VPN that connects later is
// covered without re-applying the rules.
var tunnelPatterns = []string{"tun", "tap", "wg", "ppp", "ipsec"}

func isRoot() bool { return os.Geteuid() == 0 }

// tool finds a system program in the system directories only: PATH is the
// user's and may list a writable directory first, and some of these run as
// root.
func tool(name string) string {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func run(name string, args ...string) (string, error) {
	p := tool(name)
	if p == "" {
		return "", fmt.Errorf("%s: not found on this system", name)
	}
	out, err := exec.Command(p, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

func runInput(input, name string, args ...string) error {
	p := tool(name)
	if p == "" {
		return fmt.Errorf("%s: not found on this system", name)
	}
	cmd := exec.Command(p, args...)
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w\n%s", name, err, out)
	}
	return nil
}

func elevate(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if tool("sudo") == "" {
		return elevateGUI(args)
	}
	cmd := exec.Command(tool("sudo"), append([]string{exe}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// elevateGUI asks for the password in the desktop's own polkit dialog; the
// settings page and the menu entry have no terminal for sudo.
func elevateGUI(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if tool("pkexec") == "" {
		return fmt.Errorf("pkexec не найден; выполните в терминале: sudo %s %s", exe, strings.Join(args, " "))
	}
	out, err := exec.Command(tool("pkexec"), append([]string{exe}, args...)...).CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 126 {
			return errors.New("отменено")
		}
		if errors.As(err, &ee) && ee.ExitCode() == 127 {
			return fmt.Errorf("окно ввода пароля не открылось; выполните в терминале: sudo %s %s", exe, strings.Join(args, " "))
		}
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

var ssPidRe = regexp.MustCompile(`pid=(\d+)`)

// listenerPID is the process that listens on 127.0.0.1:port, or 0.
func listenerPID(port int) int {
	out, _ := run("ss", "-H", "-ltnp", "src", "127.0.0.1", "sport", "=", ":"+strconv.Itoa(port))
	if m := ssPidRe.FindStringSubmatch(out); m != nil {
		pid, _ := strconv.Atoi(m[1])
		return pid
	}
	return 0
}

func openBrowser(url string) error {
	p, err := exec.LookPath("xdg-open")
	if err != nil {
		return err
	}
	return exec.Command(p, url).Start()
}

// renderNFT builds the nftables table. Everything bound for Anthropic is
// rejected, from this machine and from containers and VMs behind it, unless
// it leaves through a VPN tunnel that --allow-tunnels lets through. The
// first two lines make loading it replace an older copy in one transaction.
func renderNFT(o FirewallOptions) string {
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
func renderIPTables(o FirewallOptions, v6 bool) string {
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

func enableFirewall(o FirewallOptions) error {
	if tool("nft") != "" {
		return runInput(renderNFT(o), "nft", "-f", "-")
	}
	if tool("iptables-restore") == "" {
		return errors.New("neither nft nor iptables found: install the nftables package")
	}
	for _, fam := range []struct {
		cmd string
		v6  bool
	}{{"iptables", false}, {"ip6tables", true}} {
		if err := runInput(renderIPTables(o, fam.v6), fam.cmd+"-restore", "-w", "--noflush"); err != nil {
			return err
		}
		for _, chain := range []string{"OUTPUT", "FORWARD"} {
			if _, err := run(fam.cmd, "-w", "-C", chain, "-j", iptChain); err == nil {
				continue
			}
			if _, err := run(fam.cmd, "-w", "-I", chain, "1", "-j", iptChain); err != nil {
				return err
			}
		}
	}
	return nil
}

func disableFirewall() error {
	var err error
	if tool("nft") != "" {
		if _, e := run("nft", "list", "table", "inet", nftTable); e == nil {
			_, err = run("nft", "delete", "table", "inet", nftTable)
		}
	}
	for _, cmd := range []string{"iptables", "ip6tables"} {
		if tool(cmd) == "" {
			continue
		}
		if _, e := run(cmd, "-w", "-S", iptChain); e != nil {
			continue
		}
		for _, chain := range []string{"OUTPUT", "FORWARD"} {
			_, _ = run(cmd, "-w", "-D", chain, "-j", iptChain)
		}
		_, _ = run(cmd, "-w", "-F", iptChain)
		if _, e := run(cmd, "-w", "-X", iptChain); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func firewallStatus() string {
	if !isRoot() {
		if _, err := os.Stat(filepath.Join(unitDir, fwService)); err != nil {
			return "not installed"
		}
		return "installed (see direct checks below)"
	}
	if _, err := run("nft", "list", "table", "inet", nftTable); err == nil {
		return "active"
	}
	if _, err := run("iptables", "-w", "-C", "OUTPUT", "-j", iptChain); err == nil {
		return "active"
	}
	return "NOT loaded"
}

// installedBin is what the services run. A packaged binary under /usr
// belongs to root already; anything else is copied to /opt, so that the root
// unit never executes a file the user can replace.
func installedBin() string {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err == nil && strings.HasPrefix(exe, "/usr/") && !strings.HasPrefix(exe, "/usr/local/") {
		return exe
	}
	return optBin
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
	if tool("systemctl") == "" {
		return errors.New("systemd is required to keep the kill switch on after a reboot")
	}
	bin := installedBin()
	if bin == optBin {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(optDir, 0o755); err != nil {
			return err
		}
		if err := copyFile(exe, optBin, 0o755); err != nil {
			return err
		}
	}
	if err := enableFirewall(o); err != nil {
		return err
	}
	// The service applies the rules before the network comes up; the timer
	// puts them back if another tool flushed the whole ruleset.
	service := fmt.Sprintf(`[Unit]
Description=Claudeguard kill switch: block direct traffic to Anthropic
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=%s

[Install]
WantedBy=multi-user.target
`, strings.Join(append([]string{bin, "enable"}, o.args()...), " "))
	timer := `[Unit]
Description=Claudeguard kill switch: keep the rules loaded

[Timer]
OnCalendar=minutely
AccuracySec=10s

[Install]
WantedBy=timers.target
`
	if err := os.WriteFile(filepath.Join(unitDir, fwService), []byte(service), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(unitDir, fwTimer), []byte(timer), 0o644); err != nil {
		return err
	}
	if _, err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := run("systemctl", "enable", fwService, fwTimer); err != nil {
		return err
	}
	if _, err := run("systemctl", "restart", fwTimer); err != nil {
		return err
	}
	fmt.Println("   firewall rules loaded; systemd units", fwService, "and", fwTimer, "installed")
	return nil
}

func systemUninstall() error {
	_, _ = run("systemctl", "disable", "--now", fwTimer, fwService)
	_ = os.Remove(filepath.Join(unitDir, fwService))
	_ = os.Remove(filepath.Join(unitDir, fwTimer))
	_, _ = run("systemctl", "daemon-reload")
	err := disableFirewall()
	_ = os.RemoveAll(optDir)
	return err
}

func userDir(parts ...string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(append([]string{home}, parts...)...)
}

func userUnitPath() string { return userDir(".config", "systemd", "user", userService) }
func desktopPath(name string) string {
	return userDir(".local", "share", "applications", name+".desktop")
}
func autostartPath() string { return userDir(".config", "autostart", "claudeguard-tray.desktop") }
func iconDir() string       { return userDir(".local", "share", "claudeguard") }

// userSystemctl talks to the user's own systemd. A shell without a login
// session (ssh, su) has no XDG_RUNTIME_DIR, and systemctl needs it.
func userSystemctl(args ...string) (string, error) {
	p := tool("systemctl")
	if p == "" {
		return "", errors.New("systemctl: not found on this system")
	}
	cmd := exec.Command(p, append([]string{"--user"}, args...)...)
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR=/run/user/"+strconv.Itoa(os.Getuid()))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("systemctl --user %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

func desktopEntry(name, comment, exec, icon string) string {
	return fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=%s
Comment=%s
Exec=%s
Icon=%s
Terminal=false
Categories=Network;
`, name, comment, exec, icon)
}

var plainPathRe = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)

func userInstall(cfg Config, launcher bool) error {
	bin := installedBin()
	// ssh inside the service finds the user's key agent only if it is told
	// where the socket is.
	env := ""
	if sock := os.Getenv("SSH_AUTH_SOCK"); plainPathRe.MatchString(sock) {
		env = "Environment=SSH_AUTH_SOCK=" + sock + "\n"
	}
	unit := fmt.Sprintf(`[Unit]
Description=Claudeguard local proxy

[Service]
ExecStart=%s serve
%sRestart=always
RestartSec=2

[Install]
WantedBy=default.target
`, bin, env)
	p := userUnitPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(unit), 0o644); err != nil {
		return err
	}
	if _, err := userSystemctl("daemon-reload"); err != nil {
		return err
	}
	if _, err := userSystemctl("enable", userService); err != nil {
		return err
	}
	if _, err := userSystemctl("restart", userService); err != nil {
		return err
	}
	fmt.Println("   local proxy", cfg.proxyURL(), "runs as the user service", userService, "(log: journalctl --user -u claudeguard)")

	if launcher {
		if err := os.MkdirAll(iconDir(), 0o755); err != nil {
			return err
		}
		uiPNG, launchPNG := filepath.Join(iconDir(), "claudeguard.png"), filepath.Join(iconDir(), "launcher.png")
		_ = os.WriteFile(uiPNG, uiIcon, 0o644)
		_ = os.WriteFile(launchPNG, launcherIcon, 0o644)
		_ = os.MkdirAll(filepath.Dir(desktopPath("x")), 0o755)
		if _, err := os.Stat(packagedDesktop); err != nil {
			entry := desktopEntry("Claudeguard", "Прокси и kill switch для Claude", bin+" app", uiPNG)
			if err := os.WriteFile(desktopPath("claudeguard"), []byte(entry), 0o644); err != nil {
				return err
			}
			fmt.Println("   menu entry: Claudeguard")
		}
		// There is no official Claude desktop app for Linux; the launcher is
		// for the community builds and only appears if one is installed.
		if findClaudeApp() != "" {
			entry := desktopEntry("Claude via Proxy", "Запустить Claude через прокси", bin+" launch", launchPNG)
			if err := os.WriteFile(desktopPath("claude-via-proxy"), []byte(entry), 0o644); err != nil {
				return err
			}
			fmt.Println("   menu entry: Claude via Proxy")
		}
	}
	return nil
}

// trayInstall starts the tray icon now and at every login.
func trayInstall() error {
	p := autostartPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	entry := desktopEntry("Claudeguard", "Значок Claudeguard в трее", installedBin()+" tray", filepath.Join(iconDir(), "claudeguard.png")) +
		"X-GNOME-Autostart-enabled=true\nNoDisplay=true\n"
	if err := os.WriteFile(p, []byte(entry), 0o644); err != nil {
		return err
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Println("   tray icon starts at the next desktop login")
		return nil
	}
	_, _ = run("pkill", "-u", strconv.Itoa(os.Getuid()), "-f", "claudeguard tray$")
	cmd := exec.Command(installedBin(), "tray")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Println("   tray icon starts at login")
	return nil
}

// userUninstall leaves the proxy running: when the settings page asked for
// the removal, this process is part of that service and goes down with it.
// stopProxy does that as the very last step.
func userUninstall() (notes []string, err error) {
	_, _ = run("pkill", "-u", strconv.Itoa(os.Getuid()), "-f", "claudeguard tray$")
	_ = os.Remove(autostartPath())
	_ = os.Remove(desktopPath("claudeguard"))
	_ = os.Remove(desktopPath("claude-via-proxy"))
	_ = os.RemoveAll(iconDir())
	_, _ = userSystemctl("disable", userService)
	_ = os.Remove(userUnitPath())
	_, _ = userSystemctl("daemon-reload")
	// Folders the install made go too, unless something else lives in them.
	for _, d := range []string{
		filepath.Dir(autostartPath()), filepath.Dir(desktopPath("x")),
		filepath.Dir(userUnitPath()), userDir(".config", "systemd"),
	} {
		_ = os.Remove(d)
	}
	if _, err := os.Stat("/usr/bin/claudeguard"); err == nil {
		notes = append(notes, "Сам пакет claudeguard удаляется менеджером пакетов: apt remove, dnf remove или pacman -R.")
	}
	return notes, nil
}

func stopProxy() { _, _ = userSystemctl("stop", userService) }

func detachServe(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func findClaudeApp() string {
	for _, name := range []string{"claude-desktop", "claude-desktop-native"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// launchApp starts a community build of the desktop app with Chromium's
// --proxy-server switch. Claude Code needs no launcher: it reads the proxy
// from ~/.claude/settings.json.
func launchApp(cfg Config, app string) error {
	if app == "" {
		app = findClaudeApp()
	}
	if app == "" {
		return errors.New("приложение Claude для Linux не найдено (Claude Code уже идёт через прокси); укажите путь: claudeguard launch --app ПУТЬ")
	}
	if _, err := run("pgrep", "-u", strconv.Itoa(os.Getuid()), "-f", "claude-desktop"); err == nil {
		return errors.New("Claude уже запущен без прокси; закройте его и запустите снова")
	}
	cmd := exec.Command(app, "--proxy-server="+cfg.proxyURL())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func hideChildWindow(*exec.Cmd) {}

func launchedFromGUI() bool { return false }
func hideConsole()          {}
func misplaced() string     { return "" }

// installed reports whether both halves are in place and run this binary.
func installed() bool {
	if _, err := os.Stat(filepath.Join(unitDir, fwService)); err != nil {
		return false
	}
	if _, err := os.Stat(userUnitPath()); err != nil {
		return false
	}
	exe, _ := os.Executable()
	return installedBin() != optBin || sameFile(exe, optBin)
}

// previousInstall reports whether some version, this one or another, is set up.
func previousInstall() bool {
	_, err := os.Stat(filepath.Join(unitDir, fwService))
	return err == nil
}

func dialog(kind, text string) bool {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Fprintln(os.Stderr, text)
		return true
	}
	flags := map[string][2]string{"ask": {"--question", "--yesno"}, "update": {"--question", "--yesno"}, "error": {"--error", "--error"}, "info": {"--info", "--msgbox"}}[kind]
	if p, err := exec.LookPath("zenity"); err == nil {
		return exec.Command(p, flags[0], "--title=Claudeguard", "--width=420", "--text="+text).Run() == nil
	}
	if p, err := exec.LookPath("kdialog"); err == nil {
		return exec.Command(p, "--title", "Claudeguard", flags[1], text).Run() == nil
	}
	// No dialog tool: the password prompt that follows is the question.
	fmt.Fprintln(os.Stderr, text)
	return true
}
