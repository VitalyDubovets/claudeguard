package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// uninstallHome points the home directory and the config at temp folders.
func uninstallHome(t *testing.T) (settings, confDir string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	confDir = filepath.Join(home, "conf")
	t.Setenv("CLAUDEGUARD_CONFIG", filepath.Join(confDir, "config.json"))
	return filepath.Join(home, ".claude", "settings.json"), confDir
}

func TestSettingsRestore(t *testing.T) {
	const proxy = "http://127.0.0.1:41080"
	// Odd spacing and key order: a rewrite through encoding/json would show.
	const before = "{\"model\":\"opus\",\n   \"env\": {\"HTTPS_PROXY\":\"http://corp:3128\", \"FOO\":\"1\"}}\n"
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	toggle := func(enable bool) {
		t.Helper()
		if err := configureClaudeCode(proxy, enable); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("untouched file comes back byte for byte", func(t *testing.T) {
		path, _ := uninstallHome(t)
		write(path, before)
		toggle(true)
		toggle(true) // an update installs again; the snapshot must not move
		if got := read(path); !strings.Contains(got, proxy) || strings.Contains(got, "corp") {
			t.Fatalf("proxy not set: %s", got)
		}
		toggle(false)
		if got := read(path); got != before {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("a file we made goes away", func(t *testing.T) {
		path, _ := uninstallHome(t)
		toggle(true)
		toggle(false)
		if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
			t.Fatalf("~/.claude is still there: %v", err)
		}
	})

	t.Run("later edits stay, old proxy returns", func(t *testing.T) {
		path, _ := uninstallHome(t)
		write(path, before)
		toggle(true)
		m, _ := readSettings(path)
		m["theme"] = "dark"
		if err := writeSettings(path, m); err != nil {
			t.Fatal(err)
		}
		toggle(false)
		m, _ = readSettings(path)
		env, _ := m["env"].(map[string]any)
		if m["theme"] != "dark" || m["model"] != "opus" || env["HTTPS_PROXY"] != "http://corp:3128" || env["FOO"] != "1" {
			t.Fatalf("got %v", m)
		}
		if _, ok := env["HTTP_PROXY"]; ok {
			t.Fatalf("HTTP_PROXY was not there before: %v", env)
		}
	})

	t.Run("a proxy the user set later is not replaced", func(t *testing.T) {
		path, _ := uninstallHome(t)
		write(path, before)
		toggle(true)
		m, _ := readSettings(path)
		m["env"].(map[string]any)["HTTPS_PROXY"] = "http://mine:1"
		if err := writeSettings(path, m); err != nil {
			t.Fatal(err)
		}
		toggle(false)
		m, _ = readSettings(path)
		if env := m["env"].(map[string]any); env["HTTPS_PROXY"] != "http://mine:1" {
			t.Fatalf("got %v", env)
		}
	})

	t.Run("install from before 0.4.1: the backup is the original", func(t *testing.T) {
		path, _ := uninstallHome(t)
		write(path+".claudeguard.bak", before)
		write(path, "{\n  \"env\": {\n    \"FOO\": \"1\",\n    \"HTTPS_PROXY\": \""+proxy+"\",\n    \"HTTP_PROXY\": \""+proxy+"\"\n  },\n  \"model\": \"opus\"\n}\n")
		toggle(false)
		if got := read(path); got != before {
			t.Fatalf("got %q", got)
		}
		if _, err := os.Stat(path + ".claudeguard.bak"); !os.IsNotExist(err) {
			t.Fatal("backup left behind")
		}
	})

	t.Run("install from before 0.4.1 that made the file", func(t *testing.T) {
		path, _ := uninstallHome(t)
		write(path, "{\"env\":{\"HTTPS_PROXY\":\""+proxy+"\",\"HTTP_PROXY\":\""+proxy+"\"}}")
		toggle(true)
		toggle(false)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("file is still there: %v", err)
		}
	})
}

func TestRemoveAppData(t *testing.T) {
	_, dir := uninstallHome(t)
	if err := os.MkdirAll(filepath.Join(dir, "window", "Default"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.json", "id_ed25519", "id_ed25519.pub", "known_hosts", "settings.prev.json", "open.html", "window.lock", "window/Default/x"} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removeAppData()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		left, _ := os.ReadDir(dir)
		t.Fatalf("left behind: %v", left)
	}

	// A folder that holds something of the user's is not ours to delete.
	_ = os.MkdirAll(dir, 0o700)
	keep := filepath.Join(dir, "notes.txt")
	_ = os.WriteFile(keep, []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600)
	removeAppData()
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("removed a file that is not ours")
	}
}

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
