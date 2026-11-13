//go:build !darwin && !windows && !linux

package platform

import (
	"os/exec"

	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

func Elevate([]string) error { return sysutil.ErrUnsupported }

func SystemInstall(firewall.Options) error { return sysutil.ErrUnsupported }

func SystemUninstall() error { return sysutil.ErrUnsupported }

func UserInstall(string, bool) error { return sysutil.ErrUnsupported }

func TrayInstall() error { return sysutil.ErrUnsupported }

func UserUninstall() ([]string, error) { return nil, sysutil.ErrUnsupported }

func ClosePanel() {}

func StopProxy() {}

func Detach([]string) error { return sysutil.ErrUnsupported }

func LaunchClaude(string, string) error { return sysutil.ErrUnsupported }

func ElevateGUI([]string) error { return sysutil.ErrUnsupported }

func LaunchedFromGUI() bool { return false }

func Installed() bool { return false }

func PreviousInstall() bool { return false }

func HideConsole() {}

func Misplaced() string { return "" }

func Dialog(string, string) bool { return false }

func ShowWindow(string) error { return ErrNoWindow }

func OpenPanel() error { return sysutil.ErrUnsupported }

func openBrowser(url string) error { return exec.Command("xdg-open", url).Start() }
