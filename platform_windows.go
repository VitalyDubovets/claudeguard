package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
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

// elevateGUI is the same UAC prompt without console windows, for the
// settings page running in the background.
func elevateGUI(args []string) error { return elevateWith(args, true) }

// listenerPID is the process that listens on 127.0.0.1:port, or 0.
func listenerPID(port int) int {
	cmd := exec.Command("netstat", "-ano", "-p", "TCP")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()
	want := "127.0.0.1:" + strconv.Itoa(port)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 5 && f[1] == want && f[3] == "LISTENING" {
			pid, _ := strconv.Atoi(f[4])
			return pid
		}
	}
	return 0
}

func openBrowser(url string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func powershell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("powershell: %w\n%s", err, out)
	}
	return string(out), nil
}

func isRoot() bool {
	out, err := powershell(`([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`)
	return err == nil && strings.TrimSpace(out) == "True"
}

// elevate re-runs claudeguard through a UAC prompt and waits for it.
func elevate(args []string) error { return elevateWith(args, false) }

func elevateWith(args []string, hidden bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	style := ""
	if hidden {
		style = " -WindowStyle Hidden"
	}
	script := fmt.Sprintf("$p = Start-Process -FilePath %s -ArgumentList %s -Verb RunAs%s -Wait -PassThru; exit $p.ExitCode",
		psQuote(exe), psQuote(strings.Join(args, " ")), style)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if hidden {
		hideChildWindow(cmd)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("UAC: %w", err)
	}
	return nil
}

func enableFirewall(o FirewallOptions) error {
	out, err := powershell(windowsFirewallScript(o))
	fmt.Print(out)
	if err != nil {
		return err
	}
	fmt.Println("   Windows Firewall rule group", winRuleGroup, "applied (persists across reboots)")
	return nil
}

func disableFirewall() error {
	_, err := powershell(windowsRemoveScript())
	return err
}

func firewallStatus() string {
	out, err := powershell(fmt.Sprintf("(Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True' | Measure-Object).Count", psQuote(winRuleGroup)))
	if err != nil {
		return "unknown"
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(out)); n > 0 {
		return "active"
	}
	return "NOT installed"
}

// systemInstall only needs the firewall rule on Windows: rules are stored by
// the OS and survive reboots, so no service has to keep them alive.
func systemInstall(o FirewallOptions) error { return enableFirewall(o) }

func systemUninstall() error { return disableFirewall() }

func installDir() string {
	dir, _ := os.UserCacheDir() // %LOCALAPPDATA%
	return filepath.Join(dir, "claudeguard")
}

func installedExe() string { return filepath.Join(installDir(), "claudeguard.exe") }

func copyFile(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func stopOtherInstances() {
	_, _ = powershell(fmt.Sprintf("Get-Process claudeguard -ErrorAction SilentlyContinue | Where-Object Id -ne %d | Stop-Process -Force", os.Getpid()))
}

func userInstall(cfg Config, launcher bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(installDir(), 0o755); err != nil {
		return err
	}
	stopOtherInstances()
	if err := copyFile(exe, installedExe()); err != nil {
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
	fmt.Println("   local proxy", cfg.proxyURL(), "starts at logon (log:", filepath.Join(installDir(), "claudeguard.log")+")")

	if launcher {
		launchIco := filepath.Join(installDir(), "launcher.ico")
		uiIco := filepath.Join(installDir(), "claudeguard.ico")
		_ = os.WriteFile(launchIco, launcherIcon, 0o644)
		_ = os.WriteFile(uiIco, uiIcon, 0o644)
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
}`, psQuote(shortcutName), psQuote(launchIco), psQuote(uiShortcut), psQuote(uiIco), psQuote(installedExe()))
		if _, err := powershell(script); err != nil {
			return err
		}
		fmt.Println("   shortcuts 'Claude via Proxy' and 'Claudeguard' added to the Desktop and Start menu")
	}
	for _, v := range [][3]string{
		{"DisplayName", "REG_SZ", "Claudeguard"},
		{"DisplayVersion", "REG_SZ", version},
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

// trayInstall starts the tray icon now and at every logon.
func trayInstall() error {
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

func userUninstall() (notes []string, err error) {
	_ = exec.Command("reg", "delete", runKey, "/v", runValue, "/f").Run()
	_ = exec.Command("reg", "delete", runKey, "/v", trayRunValue, "/f").Run()
	stopOtherInstances()
	_, _ = powershell(fmt.Sprintf(`foreach ($d in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
  Remove-Item -ErrorAction SilentlyContinue (Join-Path $d %s), (Join-Path $d %s)
}`, psQuote(shortcutName), psQuote(uiShortcut)))
	_ = exec.Command("reg", "delete", uninstallKey, "/f").Run()
	// A running program cannot delete its own file: leave that to a command
	// that outlives this process by a few seconds.
	if dir := installDir(); filepath.IsAbs(dir) {
		line := `cmd.exe /d /c ping -n 4 127.0.0.1 >nul & rmdir /s /q "` + dir + `"`
		// The web view lets go of its files a moment after the window dies.
		if data, err := appSSHFile("webview"); err == nil {
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

// closePanel has nothing to do: userUninstall stops every claudeguard
// process, the window among them.
func closePanel() {}

func stopProxy() {}

func detachServe(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	_ = os.MkdirAll(installDir(), 0o755)
	logf, err := os.OpenFile(filepath.Join(installDir(), "claudeguard.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	const createNoWindow, detachedProcess = 0x08000000, 0x00000008
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow | detachedProcess}
	return cmd.Start()
}

func findClaudeApp() string {
	local, _ := os.UserCacheDir()
	for _, p := range []string{
		filepath.Join(local, "AnthropicClaude", "claude.exe"),
		filepath.Join(local, "Programs", "Claude", "Claude.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Claude", "Claude.exe"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// launchApp starts the desktop app with Chromium's --proxy-server switch.
// Claude Code's own claude.exe lives elsewhere, so only the desktop app's
// folder is checked for a running instance.
func launchApp(cfg Config, app string) error {
	if app == "" {
		app = findClaudeApp()
	}
	if app == "" {
		return errors.New("Claude desktop app not found; pass --app <path to Claude.exe>")
	}
	dir := filepath.Dir(app)
	out, _ := powershell(fmt.Sprintf("@(Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith(%s, 'OrdinalIgnoreCase') }).Count", psQuote(dir+`\`)))
	if n, _ := strconv.Atoi(strings.TrimSpace(out)); n > 0 {
		return errors.New("Claude is already running without the proxy flag; quit it (tray icon > Quit) and launch again")
	}
	cmd := exec.Command(app, "--proxy-server="+cfg.proxyURL())
	return cmd.Start()
}

func hideChildWindow(cmd *exec.Cmd) {
	const createNoWindow = 0x08000000
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
)

// launchedFromGUI: a double click in Explorer gives the program a console of
// its own; started from a shell, it shares the shell's.
func launchedFromGUI() bool {
	var pids [2]uint32
	n, _, _ := kernel32.NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	return n == 1
}

// hideConsole closes that console window: the dialogs are the interface.
func hideConsole() {
	if launchedFromGUI() {
		kernel32.NewProc("FreeConsole").Call()
	}
}

func misplaced() string { return "" }

// installed reports whether both halves are in place and run this binary.
func installed() bool {
	exe, _ := os.Executable()
	return sameFile(exe, installedExe()) && firewallStatus() == "active"
}

// previousInstall reports whether some version, this one or another, is set up.
func previousInstall() bool {
	_, err := os.Stat(installedExe())
	return err == nil
}

func dialog(kind, text string) bool {
	const (
		mbOKCancel, mbIconError, mbIconQuestion, mbIconInfo = 0x1, 0x10, 0x20, 0x40
		mbSetForeground, idOK                               = 0x10000, 1
	)
	flags := uintptr(mbIconInfo)
	switch kind {
	case "ask", "update":
		flags = mbOKCancel | mbIconQuestion
	case "error":
		flags = mbIconError
	}
	t, _ := syscall.UTF16PtrFromString(text)
	title, _ := syscall.UTF16PtrFromString("Claudeguard")
	r, _, _ := user32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(title)), flags|mbSetForeground)
	return r == idOK
}
