package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// ElevateGUI is the same UAC prompt without console windows, for the
// settings page running in the background.
func ElevateGUI(args []string) error { return elevateWith(args, true) }

func openBrowser(url string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// Elevate re-runs claudeguard through a UAC prompt and waits for it.
func Elevate(args []string) error { return elevateWith(args, false) }

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
		firewall.PSQuote(exe), firewall.PSQuote(strings.Join(args, " ")), style)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if hidden {
		sysutil.HideChildWindow(cmd)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("UAC: %w", err)
	}
	return nil
}

// Detach starts this binary with args as a background process of its own.
func Detach(args []string) error {
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

// LaunchClaude starts the desktop app with Chromium's --proxy-server switch.
// Claude Code's own claude.exe lives elsewhere, so only the desktop app's
// folder is checked for a running instance.
func LaunchClaude(proxyURL, app string) error {
	if app == "" {
		app = findClaudeApp()
	}
	if app == "" {
		return errors.New("Claude desktop app not found; pass --app <path to Claude.exe>")
	}
	dir := filepath.Dir(app)
	out, _ := sysutil.PowerShell(fmt.Sprintf("@(Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith(%s, 'OrdinalIgnoreCase') }).Count", firewall.PSQuote(dir+`\`)))
	if n, _ := strconv.Atoi(strings.TrimSpace(out)); n > 0 {
		return errors.New("Claude is already running without the proxy flag; quit it (tray icon > Quit) and launch again")
	}
	cmd := exec.Command(app, "--proxy-server="+proxyURL)
	return cmd.Start()
}

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
)

// LaunchedFromGUI: a double click in Explorer gives the program a console of
// its own; started from a shell, it shares the shell's.
func LaunchedFromGUI() bool {
	var pids [2]uint32
	n, _, _ := kernel32.NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	return n == 1
}

// HideConsole closes that console window: the dialogs are the interface.
func HideConsole() {
	if LaunchedFromGUI() {
		kernel32.NewProc("FreeConsole").Call()
	}
}

// Dialog shows a system dialog of the given kind and reports whether the
// user agreed.
func Dialog(kind, text string) bool {
	const (
		mbOKCancel, mbIconError, mbIconQuestion, mbIconInfo = 0x1, 0x10, 0x20, 0x40
		mbSetForeground, idOK                               = 0x10000, 1
	)
	flags := uintptr(mbIconInfo)
	switch kind {
	case DialogInstall, DialogUpdate:
		flags = mbOKCancel | mbIconQuestion
	case DialogError:
		flags = mbIconError
	}
	t, _ := syscall.UTF16PtrFromString(text)
	title, _ := syscall.UTF16PtrFromString("Claudeguard")
	r, _, _ := user32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(title)), flags|mbSetForeground)
	return r == idOK
}
