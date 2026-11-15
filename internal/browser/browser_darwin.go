package browser

import (
	"errors"
	"strings"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// networkServices lists the enabled ones: Wi-Fi, Ethernet, VPN entries.
func networkServices() []string {
	out, err := sysutil.Run("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil
	}
	var list []string
	for i, l := range strings.Split(strings.TrimSpace(out), "\n") {
		// The first line is a note about the asterisk; an asterisk marks a
		// disabled service.
		if i == 0 || l == "" || strings.HasPrefix(l, "*") {
			continue
		}
		list = append(list, l)
	}
	return list
}

func servicePAC(service string) (url string, enabled bool) {
	out, err := sysutil.Run("networksetup", "-getautoproxyurl", service)
	if err != nil {
		return "", false
	}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "URL: "); ok && v != "(null)" {
			url = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "Enabled: "); ok {
			enabled = strings.TrimSpace(v) == "Yes"
		}
	}
	return url, enabled
}

func systemPAC(ours string) (pacState, string, error) {
	services := networkServices()
	if len(services) == 0 {
		return nil, "", errors.New("не удалось прочитать сетевые службы macOS")
	}
	st := pacState{}
	foreign := ""
	for _, s := range services {
		url, on := servicePAC(s)
		if url == ours {
			continue
		}
		st[s] = map[bool]string{true: "1", false: "0"}[on] + url
		if on && url != "" {
			foreign = url
		}
	}
	if foreign == "" {
		if out, err := sysutil.Run("scutil", "--proxy"); err == nil {
			if m := scutilManual(out); m != "" {
				foreign = manualNote(m)
			}
		}
	}
	return st, foreign, nil
}

func setSystemPAC(url string) error {
	var last error
	done := 0
	for _, s := range networkServices() {
		if _, err := sysutil.Run("networksetup", "-setautoproxyurl", s, url); err != nil {
			last = err
			continue
		}
		done++
	}
	if done == 0 {
		if last == nil {
			last = errors.New("нет сетевых служб")
		}
		return last
	}
	return nil
}

// restoreSystemPAC touches only the services that still carry our address.
func restoreSystemPAC(prev pacState, ours string) error {
	for _, s := range networkServices() {
		if url, _ := servicePAC(s); url != ours {
			continue
		}
		old := prev[s]
		if len(old) > 1 {
			_, _ = sysutil.Run("networksetup", "-setautoproxyurl", s, old[1:])
			_, _ = sysutil.Run("networksetup", "-setautoproxystate", s, map[bool]string{true: "on", false: "off"}[old[0] == '1'])
			continue
		}
		// networksetup has no way to unset the address; a blank one is how
		// the field is emptied.
		_, _ = sysutil.Run("networksetup", "-setautoproxyurl", s, " ")
		_, _ = sysutil.Run("networksetup", "-setautoproxystate", s, "off")
	}
	return nil
}

func systemPACIs(ours string) bool {
	for _, s := range networkServices() {
		if url, on := servicePAC(s); on && url == ours {
			return true
		}
	}
	return false
}

// carried is the services seen with our address, for systemPACWhole. Keep
// is its only caller and holds switchMu.
var carried = map[string]bool{}

// systemPACWhole reports whether our address is still on every service it
// was on. Keep goes by this one: a program that clears the service in use
// leaves the address on the idle ones, and "on somewhere" would never
// notice. Services that never took the address (some VPN entries refuse
// it) do not count, or Keep would rewrite the setting on every tick.
func systemPACWhole(ours string) bool {
	now := map[string]bool{}
	for _, s := range networkServices() {
		url, on := servicePAC(s)
		now[s] = on && url == ours
	}
	return stillWhole(carried, now)
}
