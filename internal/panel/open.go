package panel

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/platform"
	"github.com/VitalyDubovets/claudeguard/internal/proxy"
)

// URL returns the address of the settings page, starting the proxy first if
// needed. The access token rides in the URL fragment, which is never sent
// over the network.
func URL() (string, error) {
	cfg, err := config.Load()
	if err != nil {
		return "", err
	}
	id := proxy.Identify(cfg)
	if id.Owner == proxy.Nobody {
		if err := platform.Detach([]string{"serve"}); err != nil {
			return "", err
		}
		for i := 0; i < 50 && !proxy.Listening(cfg.Listen); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		id = proxy.Identify(cfg)
	}
	if !id.Running() {
		return "", fmt.Errorf("local proxy %s: %s", cfg.Listen, id)
	}
	return "http://" + cfg.Listen + "/ui#token=" + cfg.Token, nil
}

// OpenInBrowser shows the settings page in the default browser, or prints
// its address if no browser could be started.
func OpenInBrowser() error {
	url, err := URL()
	if err != nil {
		return err
	}
	openInBrowser(url)
	return nil
}

func openInBrowser(url string) {
	if err := platform.OpenInBrowser(url); err != nil {
		fmt.Println("Open this in a browser:", url)
	}
}

// Show shows the settings page in a window of its own and returns when the
// window is closed. Without a web view on this system the browser takes over.
func Show() error {
	url, err := URL()
	if err != nil {
		return err
	}
	if err := platform.ShowWindow(url); err != nil {
		if !errors.Is(err, platform.ErrNoWindow) {
			log.Println("window:", err)
		}
		openInBrowser(url)
	}
	return nil
}
