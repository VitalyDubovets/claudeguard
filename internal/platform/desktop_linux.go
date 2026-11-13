package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// Elevate runs this binary with args and admin rights, asking for the
// password in the terminal.
func Elevate(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if sysutil.Tool("sudo") == "" {
		return ElevateGUI(args)
	}
	cmd := exec.Command(sysutil.Tool("sudo"), append([]string{exe}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// ElevateGUI asks for the password in the desktop's own polkit dialog; the
// settings page and the menu entry have no terminal for sudo.
func ElevateGUI(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if sysutil.Tool("pkexec") == "" {
		return fmt.Errorf("pkexec не найден; выполните в терминале: sudo %s %s", exe, strings.Join(args, " "))
	}
	out, err := exec.Command(sysutil.Tool("pkexec"), append([]string{exe}, args...)...).CombinedOutput()
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

func openBrowser(url string) error {
	p, err := exec.LookPath("xdg-open")
	if err != nil {
		return err
	}
	return exec.Command(p, url).Start()
}

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

func findClaudeApp() string {
	for _, name := range []string{"claude-desktop", "claude-desktop-native"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// LaunchClaude starts a community build of the desktop app with Chromium's
// --proxy-server switch. Claude Code needs no launcher: it reads the proxy
// from ~/.claude/settings.json.
func LaunchClaude(proxyURL, app string) error {
	if app == "" {
		app = findClaudeApp()
	}
	if app == "" {
		return errors.New("приложение Claude для Linux не найдено (Claude Code уже идёт через прокси); укажите путь: claudeguard launch --app ПУТЬ")
	}
	if _, err := sysutil.Run("pgrep", "-u", strconv.Itoa(os.Getuid()), "-f", "claude-desktop"); err == nil {
		return errors.New("Claude уже запущен без прокси; закройте его и запустите снова")
	}
	cmd := exec.Command(app, "--proxy-server="+proxyURL)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// LaunchedFromGUI reports whether a double click started the program.
func LaunchedFromGUI() bool { return false }

// HideConsole closes the console window a double click gave the program.
func HideConsole() {}

// Dialog shows a system dialog of the given kind and reports whether the
// user agreed.
func Dialog(kind, text string) bool {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Fprintln(os.Stderr, text)
		return true
	}
	flags := map[string][2]string{DialogInstall: {"--question", "--yesno"}, DialogUpdate: {"--question", "--yesno"}, DialogError: {"--error", "--error"}, DialogInfo: {"--info", "--msgbox"}}[kind]
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
