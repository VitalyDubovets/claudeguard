// Package platform is everything that differs between macOS, Windows and
// Linux: installing the services and launchers, asking for admin rights,
// system dialogs, the settings window, starting Claude.
package platform

import (
	"errors"
	"os"

	"github.com/VitalyDubovets/claudeguard/internal/config"
)

// ErrNoWindow means this system has nothing to show the page in a window of
// its own; the browser takes over.
var ErrNoWindow = errors.New("no web view on this system")

// Kinds of Dialog: a note, an error, or a question with the button that
// starts an install or an update.
const (
	DialogInfo    = "info"
	DialogError   = "error"
	DialogInstall = "ask"
	DialogUpdate  = "update"
)

// redirectPage writes a private file that sends a browser to url. The
// access token in the URL must not show up in `ps` as an argument of
// whatever opens the page.
func redirectPage(url string) (string, error) {
	page, err := config.File("open.html")
	if err == nil {
		err = os.WriteFile(page, []byte(`<!doctype html><meta charset="utf-8"><title>Claudeguard</title>`+
			`<meta http-equiv="refresh" content="0;url=`+url+`"><a href="`+url+`">Открыть Claudeguard</a>`), 0o600)
	}
	return page, err
}

// OpenInBrowser opens url in the default browser.
func OpenInBrowser(url string) error {
	page, err := redirectPage(url)
	if err != nil {
		return err
	}
	return openBrowser(page)
}
