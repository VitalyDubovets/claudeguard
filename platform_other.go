//go:build !darwin && !windows && !linux

package main

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

var errUnsupported = errors.New("only macOS, Windows and Linux are supported; `serve` works everywhere")

func isRoot() bool                         { return false }
func elevate([]string) error               { return errUnsupported }
func enableFirewall(FirewallOptions) error { return errUnsupported }
func disableFirewall() error               { return errUnsupported }
func firewallStatus() string               { return "unsupported OS" }
func systemInstall(FirewallOptions) error  { return errUnsupported }
func systemUninstall() error               { return errUnsupported }
func userInstall(Config, bool) error       { return errUnsupported }
func trayInstall() error                   { return errUnsupported }
func userUninstall() ([]string, error)     { return nil, errUnsupported }
func closePanel()                          {}
func stopProxy()                           {}
func detachServe([]string) error           { return errUnsupported }
func launchApp(Config, string) error       { return errUnsupported }
func elevateGUI([]string) error            { return errUnsupported }
func launchedFromGUI() bool                { return false }
func installed() bool                      { return false }
func hideConsole()                         {}
func misplaced() string                    { return "" }
func dialog(string, string) bool           { return false }
func showWindow(string) error              { return errNoWindow }
func openPanel() error                     { return cmdWindow() }

func openBrowser(url string) error { return exec.Command("xdg-open", url).Start() }

func hideChildWindow(*exec.Cmd) {}

func listenerPID(port int) int {
	out, _ := exec.Command("lsof", "-nP", "-a", "-iTCP@127.0.0.1:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fp").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "p") {
			pid, _ := strconv.Atoi(line[1:])
			return pid
		}
	}
	return 0
}
