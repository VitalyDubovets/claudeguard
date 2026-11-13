// Package testutil holds what the tests of several packages share.
package testutil

import (
	"path/filepath"
	"testing"
)

// Home points the home directory and the config at temp folders, so a test
// can install and uninstall without touching the real ones. It returns the
// path of Claude Code's settings.json and the config directory.
func Home(t *testing.T) (settings, confDir string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	confDir = filepath.Join(home, "conf")
	t.Setenv("CLAUDEGUARD_CONFIG", filepath.Join(confDir, "config.json"))
	return filepath.Join(home, ".claude", "settings.json"), confDir
}
