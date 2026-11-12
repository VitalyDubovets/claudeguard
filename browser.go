package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Browsers reach Claude's sites through the proxy with a PAC file: the
// system setting "automatic proxy configuration" points at /proxy.pac on the
// local proxy, and that file sends only these domains our way. Everything
// else stays direct.
var pacDomains = []string{"claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com"}

func pacURL(listen string) string { return "http://" + listen + "/proxy.pac" }

// pacFile has no DIRECT fallback for Claude's sites: with the proxy down
// they fail, like Claude itself does.
func pacFile(listen string) string {
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

func pacPrevPath() (string, error) { return appSSHFile("browser.prev.json") }

func enableBrowserProxy(url string) error {
	prev, foreign, err := systemPAC(url)
	if err != nil {
		return err
	}
	if foreign != "" {
		return fmt.Errorf("в системе уже настроен другой прокси (%s). Claudeguard его не трогает: отключите его в настройках сети и включите переключатель снова", foreign)
	}
	// Keep the first snapshot: a second switch-on must not record our own
	// address as the original.
	if p, err := pacPrevPath(); err == nil {
		if _, err := os.Stat(p); err != nil {
			data, _ := json.Marshal(prev)
			if err := os.WriteFile(p, data, 0o600); err != nil {
				return err
			}
		}
	}
	return setSystemPAC(url)
}

func disableBrowserProxy(url string) error {
	var prev pacState
	p, err := pacPrevPath()
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

func browserProxyOn(url string) bool {
	pacCache.Lock()
	defer pacCache.Unlock()
	if time.Since(pacCache.at) > 15*time.Second {
		pacCache.on, pacCache.at = systemPACIs(url), time.Now()
	}
	return pacCache.on
}

func forgetBrowserProxyState() {
	pacCache.Lock()
	pacCache.at = time.Time{}
	pacCache.Unlock()
}
