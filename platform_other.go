//go:build !darwin && !windows

package main

import (
	"errors"
	"os/exec"
)

var errUnsupported = errors.New("only macOS and Windows are supported; `serve` works everywhere")

func isRoot() bool                         { return false }
func elevate([]string) error               { return errUnsupported }
func enableFirewall(FirewallOptions) error { return errUnsupported }
func disableFirewall() error               { return errUnsupported }
func firewallStatus() string               { return "unsupported OS" }
func systemInstall(FirewallOptions) error  { return errUnsupported }
func systemUninstall() error               { return errUnsupported }
func userInstall(Config, bool) error       { return errUnsupported }
func userUninstall() error                 { return errUnsupported }
func detachServe([]string) error           { return errUnsupported }
func launchApp(Config, string) error       { return errUnsupported }
func elevateGUI([]string) error            { return errUnsupported }

func openBrowser(url string) error { return exec.Command("xdg-open", url).Start() }

func hideChildWindow(*exec.Cmd) {}
