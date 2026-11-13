package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/icons"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

const (
	optDir      = "/opt/claudeguard"
	optBin      = optDir + "/claudeguard"
	userService = "claudeguard.service"
	// A package puts its own menu entry here; then we do not add a second one.
	packagedDesktop = "/usr/share/applications/claudeguard.desktop"
)

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

// SystemInstall is the root half of an install: the firewall rules and
// whatever loads them again at boot.
func SystemInstall(o firewall.Options) error {
	if sysutil.Tool("systemctl") == "" {
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
		if err := sysutil.CopyFile(exe, optBin, 0o755); err != nil {
			return err
		}
	}
	if err := firewall.Enable(o); err != nil {
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
`, strings.Join(append([]string{bin, "enable"}, o.Args()...), " "))
	timer := `[Unit]
Description=Claudeguard kill switch: keep the rules loaded

[Timer]
OnCalendar=minutely
AccuracySec=10s

[Install]
WantedBy=timers.target
`
	if err := os.WriteFile(filepath.Join(firewall.UnitDir, firewall.Service), []byte(service), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(firewall.UnitDir, firewall.Timer), []byte(timer), 0o644); err != nil {
		return err
	}
	if _, err := sysutil.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := sysutil.Run("systemctl", "enable", firewall.Service, firewall.Timer); err != nil {
		return err
	}
	if _, err := sysutil.Run("systemctl", "restart", firewall.Timer); err != nil {
		return err
	}
	fmt.Println("   firewall rules loaded; systemd units", firewall.Service, "and", firewall.Timer, "installed")
	return nil
}

// SystemUninstall removes what SystemInstall set up.
func SystemUninstall() error {
	_, _ = sysutil.Run("systemctl", "disable", "--now", firewall.Timer, firewall.Service)
	_ = os.Remove(filepath.Join(firewall.UnitDir, firewall.Service))
	_ = os.Remove(filepath.Join(firewall.UnitDir, firewall.Timer))
	_, _ = sysutil.Run("systemctl", "daemon-reload")
	err := firewall.Disable()
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

func iconDir() string { return userDir(".local", "share", "claudeguard") }

// userSystemctl talks to the user's own systemd. A shell without a login
// session (ssh, su) has no XDG_RUNTIME_DIR, and systemctl needs it.
func userSystemctl(args ...string) (string, error) {
	p := sysutil.Tool("systemctl")
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

// UserInstall is the user's half: the proxy as a background service and,
// with launcher, the shortcuts that start Claude and the settings page.
func UserInstall(proxyURL string, launcher bool) error {
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
	fmt.Println("   local proxy", proxyURL, "runs as the user service", userService, "(log: journalctl --user -u claudeguard)")

	if launcher {
		if err := os.MkdirAll(iconDir(), 0o755); err != nil {
			return err
		}
		uiPNG, launchPNG := filepath.Join(iconDir(), "claudeguard.png"), filepath.Join(iconDir(), "launcher.png")
		_ = os.WriteFile(uiPNG, icons.UI, 0o644)
		_ = os.WriteFile(launchPNG, icons.Launcher, 0o644)
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

// TrayInstall starts the tray icon now and at every login.
func TrayInstall() error {
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
	_, _ = sysutil.Run("pkill", "-u", strconv.Itoa(os.Getuid()), "-f", "claudeguard tray$")
	cmd := exec.Command(installedBin(), "tray")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Println("   tray icon starts at login")
	return nil
}

// UserUninstall leaves the proxy running: when the settings page asked for
// the removal, this process is part of that service and goes down with it.
// StopProxy does that as the very last step.
func UserUninstall() (notes []string, err error) {
	_, _ = sysutil.Run("pkill", "-u", strconv.Itoa(os.Getuid()), "-f", "claudeguard tray$")
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

// StopProxy ends a running proxy that the service manager does not know about.
func StopProxy() { _, _ = userSystemctl("stop", userService) }

// Misplaced returns what to tell the user when the app runs from a place
// it cannot be installed from; empty if all is well.
func Misplaced() string { return "" }

// Installed reports whether both halves are in place and run this binary.
func Installed() bool {
	if _, err := os.Stat(filepath.Join(firewall.UnitDir, firewall.Service)); err != nil {
		return false
	}
	if _, err := os.Stat(userUnitPath()); err != nil {
		return false
	}
	exe, _ := os.Executable()
	return installedBin() != optBin || sysutil.SameFile(exe, optBin)
}

// PreviousInstall reports whether some version, this one or another, is set up.
func PreviousInstall() bool {
	_, err := os.Stat(filepath.Join(firewall.UnitDir, firewall.Service))
	return err == nil
}
