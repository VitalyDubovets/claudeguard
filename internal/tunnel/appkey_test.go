package tunnel

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The scripts run on the server under sh; here the same sh edits a file in
// a temp home.
func TestAuthorizedKeysScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	home := t.TempDir()
	file := filepath.Join(home, ".ssh", "authorized_keys")
	sh := func(script, stdin string) {
		t.Helper()
		cmd := exec.Command("sh", "-c", script)
		cmd.Env = append(os.Environ(), "HOME="+home)
		cmd.Stdin = strings.NewReader(stdin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	content := func() string {
		b, _ := os.ReadFile(file)
		return string(b)
	}
	const ours = "ssh-ed25519 AAAAours claudeguard\n"
	const theirs = "ssh-ed25519 AAAAtheirs me@laptop\nssh-rsa AAAAold claudeguard-not-ours"

	sh(removeKeyScript, ours) // no file yet: nothing to do
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("remove created the file")
	}
	_ = os.MkdirAll(filepath.Dir(file), 0o700)
	_ = os.WriteFile(file, []byte(theirs), 0o640)
	sh(installKeyScript, ours)
	sh(installKeyScript, ours)
	if got := content(); got != theirs+"\n"+ours {
		t.Fatalf("after install: %q", got)
	}
	sh(removeKeyScript, ours)
	if got := content(); got != theirs+"\n" {
		t.Fatalf("after remove: %q", got)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed: %v", st.Mode())
	}
	if left, _ := os.ReadDir(filepath.Dir(file)); len(left) != 1 {
		t.Fatalf("temp file left: %v", left)
	}

	// Only our key in the file: it ends up empty, not broken.
	_ = os.WriteFile(file, []byte(ours), 0o600)
	sh(removeKeyScript, ours)
	if got := content(); got != "" {
		t.Fatalf("got %q", got)
	}
}
