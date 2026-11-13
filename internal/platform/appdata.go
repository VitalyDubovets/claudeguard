package platform

import (
	"os"
	"path/filepath"

	"github.com/VitalyDubovets/claudeguard/internal/config"
)

// RemoveAppData deletes what claudeguard keeps next to config.json: its key
// and the host keys trusted in the panel, the snapshot of Claude Code's
// settings, the data of the settings window.
func RemoveAppData() {
	cfg, err := config.Path()
	if err != nil {
		return
	}
	dir := filepath.Dir(cfg)
	for _, name := range []string{"id_ed25519", "id_ed25519.pub", "known_hosts", "settings.prev.json", "browser.prev.json", "open.html", "window.lock", "window", "webview"} {
		_ = os.RemoveAll(filepath.Join(dir, name))
	}
	_ = os.Remove(cfg)
	_ = os.Remove(cfg + ".new")
	_ = os.Remove(dir) // goes only if nothing else is in it
}
