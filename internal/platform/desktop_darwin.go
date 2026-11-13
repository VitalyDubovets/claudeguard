package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// Elevate runs this binary with args and admin rights, asking for the
// password in the terminal.
func Elevate(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(sysutil.SystemTools["sudo"], append([]string{exe}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// ElevateGUI asks for the admin password in a system dialog; the settings
// page runs in a background process that has no terminal for sudo.
func ElevateGUI(args []string) error {
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
	out, err := exec.Command(sysutil.SystemTools["osascript"], "-e",
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

func openBrowser(url string) error { return exec.Command(sysutil.SystemTools["open"], url).Run() }

// Detach starts this binary with args as a background process of its own.
func Detach(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func claudeRunning() bool {
	return exec.Command(sysutil.SystemTools["pgrep"], "-x", "Claude").Run() == nil
}

// LaunchClaude restarts the desktop app with Chromium's --proxy-server switch.
// Chromium never falls back to a direct connection when that proxy fails.
func LaunchClaude(proxyURL, app string) error {
	if app == "" {
		app = defaultApp
	}
	if _, err := os.Stat(app); err != nil {
		return fmt.Errorf("Claude app not found at %s (use --app)", app)
	}
	if claudeRunning() {
		fmt.Println("Quitting Claude...")
		_, _ = sysutil.Run("osascript", "-e", `quit app "Claude"`)
		for i := 0; i < 30 && claudeRunning(); i++ {
			time.Sleep(500 * time.Millisecond)
		}
		if claudeRunning() {
			return errors.New("Claude is still running; quit it and try again")
		}
	}
	_, err := sysutil.Run("open", "-a", app, "--args", "--proxy-server="+proxyURL)
	return err
}

// LaunchedFromGUI: the binary inside Claudeguard.app, started by Finder.
func LaunchedFromGUI() bool {
	exe, _ := os.Executable()
	return strings.Contains(exe, ".app/Contents/MacOS/")
}

// HideConsole closes the console window a double click gave the program.
func HideConsole() {}

// Dialog shows a system dialog of the given kind and reports whether the
// user agreed.
func Dialog(kind, text string) bool {
	buttons, icon := `{"OK"} default button 1`, "note"
	switch kind {
	case DialogInstall:
		buttons = `{"Отмена", "Установить"} default button 2 cancel button 1`
	case DialogUpdate:
		buttons = `{"Отмена", "Обновить"} default button 2 cancel button 1`
	case DialogError:
		icon = "stop"
	}
	lit := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(text)
	return exec.Command(sysutil.SystemTools["osascript"], "-e",
		`display dialog "`+lit+`" with title "Claudeguard" buttons `+buttons+` with icon `+icon).Run() == nil
}
