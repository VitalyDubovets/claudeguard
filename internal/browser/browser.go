// Package browser makes the system's browsers reach Claude through the local
// proxy: it serves a PAC file for the Claude domains and switches the
// system's "automatic proxy configuration" to it.
package browser

import (
	"encoding/json"
	"errors"
	"fmt"
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
	var prev pacState
	p, err := PrevPath()
	if err == nil {
		if data, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(data, &prev)
		}
	}
	if err := restoreSystemPAC(prev, url); err != nil && !errors.Is(err, errNoSystemPAC) {
		return err
	}
	if p != "" {
		_ = os.Remove(p)
	}
	return nil
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
