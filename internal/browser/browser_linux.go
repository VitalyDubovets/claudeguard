package browser

import (
	"strings"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// GNOME's proxy settings are what Chrome and Firefox follow on GNOME and
// most GTK desktops. KDE keeps its own; there the address goes in by hand.
const gnomeProxy = "org.gnome.system.proxy"

func gsettings(args ...string) (string, error) {
	if sysutil.Tool("gsettings") == "" {
		return "", errNoSystemPAC
	}
	out, err := sysutil.Run("gsettings", args...)
	if err != nil {
		return "", errNoSystemPAC
	}
	return strings.Trim(strings.TrimSpace(out), "'"), nil
}

func gnomePAC() (mode, url string, err error) {
	if mode, err = gsettings("get", gnomeProxy, "mode"); err != nil {
		return "", "", err
	}
	url, err = gsettings("get", gnomeProxy, "autoconfig-url")
	return mode, url, err
}

func systemPAC(ours string) (pacState, string, error) {
	mode, url, err := gnomePAC()
	if err != nil {
		return nil, "", err
	}
	if mode == "auto" && url == ours {
		return pacState{}, "", nil
	}
	foreign := ""
	switch {
	case mode == "manual":
		foreign = "задан вручную"
	case mode == "auto" && url != "":
		foreign = url
	}
	return pacState{"mode": mode, "url": url}, foreign, nil
}

func setSystemPAC(url string) error {
	if _, err := gsettings("set", gnomeProxy, "autoconfig-url", url); err != nil {
		return err
	}
	_, err := gsettings("set", gnomeProxy, "mode", "auto")
	return err
}

func restoreSystemPAC(prev pacState, ours string) error {
	mode, url, err := gnomePAC()
	if err != nil {
		return err
	}
	if mode != "auto" || url != ours {
		return nil
	}
	old := prev["mode"]
	if old == "" {
		old = "none"
	}
	if _, err := gsettings("set", gnomeProxy, "autoconfig-url", prev["url"]); err != nil {
		return err
	}
	_, err = gsettings("set", gnomeProxy, "mode", old)
	return err
}

func systemPACIs(ours string) bool {
	mode, url, err := gnomePAC()
	return err == nil && mode == "auto" && url == ours
}
