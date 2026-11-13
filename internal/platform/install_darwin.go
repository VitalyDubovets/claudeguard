package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/icons"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

const (
	// The root daemon runs this copy. It sits in a directory only root can
	// write; /usr/local/bin belongs to the user on some Macs.
	binPath      = firewall.StateDir + "/claudeguard"
	cliLink      = "/usr/local/bin/claudeguard"
	agentLabel   = "com.claudeguard.proxy"
	trayLabel    = "com.claudeguard.tray"
	launcherName = "Claude via Proxy.app"
	uiAppName    = "Claudeguard.app"
	defaultApp   = "/Applications/Claude.app"
)

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

// SystemInstall is the root half of an install: the firewall rules and
// whatever loads them again at boot.
func SystemInstall(o firewall.Options) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(firewall.StateDir, 0o755); err != nil {
		return err
	}
	if err := sysutil.CopyFile(exe, binPath, 0o755); err != nil {
		return err
	}
	// `claudeguard` in a terminal; best effort, the app works without it.
	if os.MkdirAll(filepath.Dir(cliLink), 0o755) == nil {
		_ = os.Remove(cliLink)
		_ = os.Symlink(binPath, cliLink)
	}
	if err := firewall.Enable(o); err != nil {
		return err
	}
	// The daemon re-applies the rules at boot and every minute (every 15 s
	// with --allow-tunnels, to follow VPN interfaces coming and going).
	interval := 60
	if o.AllowTunnels {
		interval = 15
	}
	extra := fmt.Sprintf("\t<key>StartInterval</key>\n\t<integer>%d</integer>\n", interval)
	p := plist(firewall.DaemonLabel, append([]string{binPath, "enable"}, o.Args()...), extra)
	if err := os.WriteFile(firewall.DaemonPlist, []byte(p), 0o644); err != nil {
		return err
	}
	_, _ = sysutil.Run("launchctl", "bootout", "system/"+firewall.DaemonLabel)
	if _, err := sysutil.Run("launchctl", "bootstrap", "system", firewall.DaemonPlist); err != nil {
		return err
	}
	fmt.Println("   pf anchor", firewall.PFAnchor, "loaded; LaunchDaemon", firewall.DaemonLabel, "installed")
	return nil
}

// SystemUninstall removes what SystemInstall set up.
func SystemUninstall() error {
	_, _ = sysutil.Run("launchctl", "bootout", "system/"+firewall.DaemonLabel)
	_ = os.Remove(firewall.DaemonPlist)
	err := firewall.Disable()
	if dst, e := os.Readlink(cliLink); e == nil && dst == binPath {
		_ = os.Remove(cliLink)
	}
	_ = os.RemoveAll(firewall.StateDir)
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

// UserInstall is the user's half: the proxy as a background service and,
// with launcher, the shortcuts that start Claude and the settings page.
func UserInstall(proxyURL string, launcher bool) error {
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
	// A proxy the old version started on its own would keep the port.
	_, _ = sysutil.Run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+agentLabel)
	StopProxy()
	if err := loadAgent(agentLabel, p); err != nil {
		return err
	}
	fmt.Println("   local proxy", proxyURL, "runs as LaunchAgent", agentLabel, "(log:", logPath+")")

	if launcher {
		for _, l := range []struct {
			path, cmd string
			icon      []byte
		}{
			{launcherPath(), "launch", icons.Launcher},
			{uiAppPath(), "ui", icons.UI},
		} {
			_ = os.MkdirAll(filepath.Dir(l.path), 0o755)
			_ = os.RemoveAll(l.path)
			// Claudeguard.app itself opens the settings page.
			if l.cmd == "ui" && LaunchedFromGUI() {
				continue
			}
			script := fmt.Sprintf(`do shell script quoted form of "%s" & " %s > /dev/null 2>&1 &"`, binPath, l.cmd)
			if _, err := sysutil.Run("osacompile", "-o", l.path, "-e", script); err != nil {
				return err
			}
			// osacompile gives every applet the same script icon.
			if err := os.WriteFile(filepath.Join(l.path, "Contents", "Resources", "applet.icns"), l.icon, 0o644); err == nil {
				_ = os.Remove(filepath.Join(l.path, "Contents", "Resources", "Assets.car"))
				// The applet is ad-hoc signed; seal the changed resources again.
				_, _ = sysutil.Run("codesign", "--force", "--sign", "-", l.path)
				_, _ = sysutil.Run("touch", l.path)
			}
			fmt.Println("   launcher:", l.path)
		}
	}
	return nil
}

// loadAgent loads a LaunchAgent and starts it. RunAtLoad alone is not
// enough: a login session that launchd keeps in on-demand-only mode leaves
// the job loaded but never spawned.
func loadAgent(label, plistPath string) error {
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_, _ = sysutil.Run("launchctl", "bootout", domain+"/"+label)
	// bootout returns before a running job is gone, and bootstrap fails
	// while it is still there.
	var err error
	for i := 0; i < 20; i++ {
		if _, err = sysutil.Run("launchctl", "bootstrap", domain, plistPath); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	_, _ = sysutil.Run("launchctl", "kickstart", domain+"/"+label)
	return nil
}

func trayPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", trayLabel+".plist")
}

// TrayInstall starts the menu bar icon now and at every login. No KeepAlive:
// "Убрать значок" in its menu must be able to quit it until the next login.
func TrayInstall() error {
	p := trayPlistPath()
	extra := "\t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>\n"
	if err := os.WriteFile(p, []byte(plist(trayLabel, []string{binPath, "tray"}, extra)), 0o644); err != nil {
		return err
	}
	if err := loadAgent(trayLabel, p); err != nil {
		return err
	}
	fmt.Println("   menu bar icon runs as LaunchAgent", trayLabel)
	return nil
}

// UserUninstall also clears what macOS keeps for the settings window and
// moves the app itself to the Trash.
func UserUninstall() (notes []string, err error) {
	_, _ = sysutil.Run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+agentLabel)
	_, _ = sysutil.Run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+trayLabel)
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
			_, _ = sysutil.Run("defaults", "delete", id)
		}
	}
	if app := appBundle(); app != "" && !strings.HasPrefix(app, "/Volumes/") && !trash(app) {
		notes = append(notes, "Осталось перетащить Claudeguard из папки «Программы» в Корзину.")
	}
	return notes, nil
}

// StopProxy ends a proxy that launchd does not know about: one the app
// started on its own outlives the bootout of the agent.
func StopProxy() {
	_, _ = sysutil.Run("pkill", "-u", strconv.Itoa(os.Getuid()), "-f", "/claudeguard serve( |$)")
}

// Misplaced catches the app being run straight from the disk image: it
// would install fine, but the app itself would be gone after ejecting.
func Misplaced() string {
	exe, _ := os.Executable()
	if strings.HasPrefix(exe, "/Volumes/") || strings.Contains(exe, "/AppTranslocation/") {
		return "Сначала перетащите Claudeguard в папку «Программы» и запустите его оттуда."
	}
	return ""
}

// Installed reports whether both halves are in place and run this binary.
func Installed() bool {
	for _, p := range []string{firewall.DaemonPlist, agentPlistPath()} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	exe, _ := os.Executable()
	return sysutil.SameFile(exe, binPath)
}

// PreviousInstall reports whether some version, this one or another, is set up.
func PreviousInstall() bool {
	_, err := os.Stat(firewall.DaemonPlist)
	return err == nil
}
