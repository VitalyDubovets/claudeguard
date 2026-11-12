//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"
)

// appBrowsers can show a page in a window of its own, without tabs and an
// address bar.
var appBrowsers = []string{
	"chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
	"brave-browser", "brave", "microsoft-edge", "microsoft-edge-stable", "vivaldi",
}

// showWindow shows the settings page in an app window of a Chromium-family
// browser, with a profile of its own. Without one the default browser takes
// over. The window outlives this process.
func showWindow(url string) error {
	page, err := redirectPage(url)
	if err != nil {
		return err
	}
	profile, err := appSSHFile("window")
	if err != nil {
		return err
	}
	for _, name := range appBrowsers {
		bin, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		cmd := exec.Command(bin, "--app=file://"+page, "--user-data-dir="+profile, "--class=claudeguard",
			"--window-size=1040,780", "--no-first-run", "--no-default-browser-check")
		if cmd.Start() == nil {
			return nil
		}
	}
	return errNoWindow
}

// openPanel opens the settings window in a process of its own.
func openPanel() error { return detachServe([]string{"window"}) }

// closePanel closes the settings window: the browser that runs on our
// profile.
func closePanel() {
	if profile, err := appSSHFile("window"); err == nil {
		_, _ = run("pkill", "-u", strconv.Itoa(os.Getuid()), "-f", "user-data-dir="+profile)
	}
}
