package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/icons"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
	"github.com/VitalyDubovets/claudeguard/internal/version"
)

const (
	runKey       = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	runValue     = "claudeguard"
	trayRunValue = "claudeguard-tray"
	shortcutName = "Claude via Proxy.lnk"
	uiShortcut   = "Claudeguard.lnk"
	// The entry in "Apps & features".
	uninstallKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Claudeguard`
)

// SystemInstall only needs the firewall rule on Windows: rules are stored by
// the OS and survive reboots, so no service has to keep them alive.
func SystemInstall(o firewall.Options) error { return firewall.Enable(o) }

// SystemUninstall removes what SystemInstall set up.
func SystemUninstall() error { return firewall.Disable() }

func installDir() string {
	dir, _ := os.UserCacheDir() // %LOCALAPPDATA%
	return filepath.Join(dir, "claudeguard")
}

func installedExe() string { return filepath.Join(installDir(), "claudeguard.exe") }

func stopOtherInstances() {
	_, _ = sysutil.PowerShell(fmt.Sprintf("Get-Process claudeguard -ErrorAction SilentlyContinue | Where-Object Id -ne %d | Stop-Process -Force", os.Getpid()))
}

// UserInstall is the user's half: the proxy as a background service and,
// with launcher, the shortcuts that start Claude and the settings page.
func UserInstall(proxyURL string, launcher bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(installDir(), 0o755); err != nil {
		return err
	}
	stopOtherInstances()
	if err := sysutil.CopyFile(exe, installedExe()); err != nil {
		return err
	}
	cmdline := fmt.Sprintf(`"%s" serve --detach`, installedExe())
	if out, err := exec.Command("reg", "add", runKey, "/v", runValue, "/t", "REG_SZ", "/d", cmdline, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("reg add: %w\n%s", err, out)
	}
	start := exec.Command(installedExe(), "serve", "--detach")
	if out, err := start.CombinedOutput(); err != nil {
		return fmt.Errorf("start proxy: %w\n%s", err, out)
	}
	fmt.Println("   local proxy", proxyURL, "starts at logon (log:", filepath.Join(installDir(), "claudeguard.log")+")")

	if launcher {
		launchIco := filepath.Join(installDir(), "launcher.ico")
		uiIco := filepath.Join(installDir(), "claudeguard.ico")
		_ = os.WriteFile(launchIco, icons.Launcher, 0o644)
		_ = os.WriteFile(uiIco, icons.UI, 0o644)
		script := fmt.Sprintf(`$w = New-Object -ComObject WScript.Shell
foreach ($d in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
  foreach ($l in @(@(%s, 'launch', %s), @(%s, 'ui', %s))) {
    $s = $w.CreateShortcut((Join-Path $d $l[0]))
    $s.TargetPath = %s
    $s.Arguments = $l[1]
    $s.IconLocation = $l[2]
    $s.WindowStyle = 7
    $s.Save()
  }
}`, firewall.PSQuote(shortcutName), firewall.PSQuote(launchIco), firewall.PSQuote(uiShortcut), firewall.PSQuote(uiIco), firewall.PSQuote(installedExe()))
		if _, err := sysutil.PowerShell(script); err != nil {
			return err
		}
		fmt.Println("   shortcuts 'Claude via Proxy' and 'Claudeguard' added to the Desktop and Start menu")
	}
	for _, v := range [][3]string{
		{"DisplayName", "REG_SZ", "Claudeguard"},
		{"DisplayVersion", "REG_SZ", version.Version},
		{"DisplayIcon", "REG_SZ", installedExe()},
		{"InstallLocation", "REG_SZ", installDir()},
		{"UninstallString", "REG_SZ", fmt.Sprintf(`"%s" uninstall --gui`, installedExe())},
		{"NoModify", "REG_DWORD", "1"},
		{"NoRepair", "REG_DWORD", "1"},
	} {
		_ = exec.Command("reg", "add", uninstallKey, "/v", v[0], "/t", v[1], "/d", v[2], "/f").Run()
	}
	return nil
}

// TrayInstall starts the tray icon now and at every logon.
func TrayInstall() error {
	cmdline := fmt.Sprintf(`"%s" tray --detach`, installedExe())
	if out, err := exec.Command("reg", "add", runKey, "/v", trayRunValue, "/t", "REG_SZ", "/d", cmdline, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("reg add: %w\n%s", err, out)
	}
	if out, err := exec.Command(installedExe(), "tray", "--detach").CombinedOutput(); err != nil {
		return fmt.Errorf("start tray: %w\n%s", err, out)
	}
	fmt.Println("   tray icon starts at logon")
	return nil
}

// UserUninstall removes what UserInstall and TrayInstall set up. The notes
// are what is left for the user to do by hand.
func UserUninstall() (notes []string, err error) {
	_ = exec.Command("reg", "delete", runKey, "/v", runValue, "/f").Run()
	_ = exec.Command("reg", "delete", runKey, "/v", trayRunValue, "/f").Run()
	stopOtherInstances()
	_, _ = sysutil.PowerShell(fmt.Sprintf(`foreach ($d in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
  Remove-Item -ErrorAction SilentlyContinue (Join-Path $d %s), (Join-Path $d %s)
}`, firewall.PSQuote(shortcutName), firewall.PSQuote(uiShortcut)))
	_ = exec.Command("reg", "delete", uninstallKey, "/f").Run()
	// A running program cannot delete its own file: leave that to a command
	// that outlives this process by a few seconds.
	if dir := installDir(); filepath.IsAbs(dir) {
		line := `cmd.exe /d /c ping -n 4 127.0.0.1 >nul & rmdir /s /q "` + dir + `"`
		// The web view lets go of its files a moment after the window dies.
		if data, err := config.File("webview"); err == nil {
			line += ` & rmdir /s /q "` + data + `" & rmdir "` + filepath.Dir(data) + `"`
		}
		cmd := exec.Command("cmd.exe")
		const createNoWindow = 0x08000000
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CmdLine:       line,
			HideWindow:    true,
			CreationFlags: createNoWindow,
		}
		cmd.Dir = os.TempDir()
		_ = cmd.Start()
	}
	return nil, nil
}

// ClosePanel has nothing to do: UserUninstall stops every claudeguard
// process, the window among them.
func ClosePanel() {}

// StopProxy ends a running proxy that the service manager does not know about.
func StopProxy() {}

// Misplaced returns what to tell the user when the app runs from a place
// it cannot be installed from; empty if all is well.
func Misplaced() string { return "" }

// Installed reports whether both halves are in place and run this binary.
func Installed() bool {
	exe, _ := os.Executable()
	return sysutil.SameFile(exe, installedExe()) && firewall.Status() == "active"
}

// PreviousInstall reports whether some version, this one or another, is set up.
func PreviousInstall() bool {
	_, err := os.Stat(installedExe())
	return err == nil
}
