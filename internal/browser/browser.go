// Package browser makes the system's browsers reach Claude through the local
// proxy: it serves a PAC file for the Claude domains and switches the
// system's "automatic proxy configuration" to it.
package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
)

// Browsers reach Claude's sites through the proxy with a PAC file: the
// system setting "automatic proxy configuration" points at /proxy.pac on the
// local proxy, and that file sends only these domains our way. Everything
// else stays direct.
var pacDomains = []string{"claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com"}

// PACURL is the address of the PAC file the local proxy serves.
func PACURL(listen string) string { return "http://" + listen + "/proxy.pac" }

// PACFile has no DIRECT fallback for Claude's sites: with the proxy down
// they fail, like Claude itself does.
func PACFile(listen string) string {
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  var domains = ["%s"];
  for (var i = 0; i < domains.length; i++) {
    var d = domains[i];
    if (host === d || host.slice(-d.length - 1) === "." + d) return "PROXY %s";
  }
  return "DIRECT";
}
`, strings.Join(pacDomains, `", "`), listen)
}

// pacState is what the system setting held before we changed it, in the
// platform's own terms; uninstall and the switch put it back.
type pacState map[string]string

// PrevPath is where the system setting from before Enable is kept.
func PrevPath() (string, error) { return config.File("browser.prev.json") }

// Enable points the system at our PAC file and remembers what was set
// before. It refuses to replace a proxy setting that is not ours.
func Enable(url string) error {
	switchMu.Lock()
	defer switchMu.Unlock()
	prev, foreign, err := systemPAC(url)
	if err != nil {
		return err
	}
	if foreign != "" {
		return fmt.Errorf("в системе уже настроен другой прокси (%s). Claudeguard его не трогает: отключите его в настройках сети и включите переключатель снова", foreign)
	}
	// Keep the first snapshot: a second switch-on must not record our own
	// address as the original.
	if p, err := PrevPath(); err == nil {
		if _, err := os.Stat(p); err != nil {
			data, _ := json.Marshal(prev)
			if err := os.WriteFile(p, data, 0o600); err != nil {
				return err
			}
		}
	}
	return setSystemPAC(url)
}

// Disable puts back the setting Enable replaced, if ours is still in place.
func Disable(url string) error {
	switchMu.Lock()
	defer switchMu.Unlock()
	var prev pacState
	var saved []byte
	p, perr := PrevPath()
	if perr == nil {
		if data, err := os.ReadFile(p); err == nil {
			saved = data
			_ = json.Unmarshal(data, &prev)
		}
		// The snapshot goes before the setting does. Uninstall runs Disable
		// in a process of its own while the background proxy still runs
		// Keep, and Keep reads "snapshot there, setting cleared" as another
		// program's doing.
		_ = os.Remove(p)
	}
	if err := restoreSystemPAC(prev, url); err != nil && !errors.Is(err, errNoSystemPAC) {
		if saved != nil {
			_ = os.WriteFile(p, saved, 0o600)
		}
		return err
	}
	return nil
}

// switchMu keeps Keep from putting the setting back halfway through Disable.
var switchMu sync.Mutex

// The system calls behind Keep, replaced in tests.
var (
	readPAC  = systemPAC
	pacIsOn  = systemPACWhole
	writePAC = setSystemPAC
	undoPAC  = restoreSystemPAC
)

// Keep puts our PAC address back when something else wiped it while the
// switch is on. Other proxy tools clear the system proxy as they start or
// stop, and with the kill switch up that leaves browsers with no way to
// Claude. A setting someone pointed elsewhere is theirs and stays.
func Keep(url string, every time.Duration) {
	// One line per incident: a setting that will not stay put must not fill
	// the log every tick.
	again := false
	for range time.Tick(every) {
		restored, err := keepOnce(url)
		switch {
		case err != nil:
			log.Printf("browser proxy: could not put the system setting back: %v", err)
		case restored && !again:
			log.Printf("browser proxy: the system setting was cleared by another program, put back")
		}
		again = restored
	}
}

func keepOnce(url string) (restored bool, err error) {
	switchMu.Lock()
	defer switchMu.Unlock()
	// The snapshot exists exactly while the switch is on.
	p, err := PrevPath()
	if err != nil {
		return false, nil
	}
	if _, err := os.Stat(p); err != nil {
		return false, nil
	}
	if pacIsOn(url) {
		return false, nil
	}
	if _, foreign, err := readPAC(url); err != nil || foreign != "" {
		return false, nil
	}
	if err := writePAC(url); err != nil {
		return false, err
	}
	ForgetState()
	// Disable in another process may have run since the check above: with
	// the snapshot gone the switch is off, and our address must not stay.
	if _, err := os.Stat(p); err != nil {
		_ = undoPAC(nil, url)
		return false, nil
	}
	return true, nil
}

var errNoSystemPAC = errors.New("на этой системе Claudeguard не умеет менять настройки прокси сам")

// pacCache keeps the panel's two-second poll from running system tools
// every time.
var pacCache struct {
	sync.Mutex
	at time.Time
	on bool
}

// Enabled reports whether the system uses our PAC file. The answer is
// cached for a few seconds: asking runs a system tool.
func Enabled(url string) bool {
	pacCache.Lock()
	defer pacCache.Unlock()
	if time.Since(pacCache.at) > 15*time.Second {
		pacCache.on, pacCache.at = systemPACIs(url), time.Now()
	}
	return pacCache.on
}

// ForgetState drops the cached answer of Enabled.
func ForgetState() {
	pacCache.Lock()
	pacCache.at = time.Time{}
	pacCache.Unlock()
}

// manualNote is how a proxy set by hand is named as the foreign setting.
func manualNote(addr string) string { return "задан вручную: " + addr }

// regValue picks one value out of `reg query` output.
func regValue(out, name string) string {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && strings.EqualFold(f[0], name) && strings.HasPrefix(f[1], "REG_") {
			_, v, _ := strings.Cut(l, f[1])
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// scutilManual finds a proxy set by hand and switched on in the output of
// `scutil --proxy`, or returns "".
func scutilManual(out string) string {
	vals := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, " : "); ok {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	for _, kind := range []string{"HTTP", "HTTPS", "SOCKS"} {
		if host := vals[kind+"Proxy"]; vals[kind+"Enable"] == "1" && host != "" {
			if port := vals[kind+"Port"]; port != "" {
				host += ":" + port
			}
			return host
		}
	}
	return ""
}

// stillWhole compares the services that carry our address now with the
// ones that carried it before, and brings carried up to date: a service
// that is gone is forgotten, one that lost the address stays until it has
// it again.
func stillWhole(carried, now map[string]bool) bool {
	some, whole := false, true
	for s, has := range now {
		switch {
		case has:
			some, carried[s] = true, true
		case carried[s]:
			whole = false
		}
	}
	for s := range carried {
		if _, there := now[s]; !there {
			delete(carried, s)
		}
	}
	return some && whole
}
