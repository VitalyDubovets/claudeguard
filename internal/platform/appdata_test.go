package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/VitalyDubovets/claudeguard/internal/browser"
	"github.com/VitalyDubovets/claudeguard/internal/testutil"
)

func TestRemoveAppData(t *testing.T) {
	_, dir := testutil.Home(t)
	if err := os.MkdirAll(filepath.Join(dir, "window", "Default"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.json", "id_ed25519", "id_ed25519.pub", "known_hosts", "settings.prev.json", "open.html", "window.lock", "window/Default/x"} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	RemoveAppData()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		left, _ := os.ReadDir(dir)
		t.Fatalf("left behind: %v", left)
	}

	// A folder that holds something of the user's is not ours to delete.
	_ = os.MkdirAll(dir, 0o700)
	keep := filepath.Join(dir, "notes.txt")
	_ = os.WriteFile(keep, []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600)
	RemoveAppData()
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("removed a file that is not ours")
	}
}

func TestBrowserPrevIsRemovedWithAppData(t *testing.T) {
	testutil.Home(t)
	p, err := browser.PrevPath()
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	RemoveAppData()
	if _, err := os.Stat(p); err == nil {
		t.Error("browser.prev.json survived removeAppData")
	}
}
