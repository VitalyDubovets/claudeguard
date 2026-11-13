package claudecode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VitalyDubovets/claudeguard/internal/testutil"
)

func TestSettingsMergeAndRevert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	m := map[string]any{"model": "opus", "env": map[string]any{"FOO": "1", "HTTPS_PROXY": "http://other:1"}}
	setProxyEnv(m, "http://127.0.0.1:41080")
	if err := writeSettings(path, m); err != nil {
		t.Fatal(err)
	}
	m, _ = readSettings(path)
	env := m["env"].(map[string]any)
	if env["HTTPS_PROXY"] != "http://127.0.0.1:41080" || env["FOO"] != "1" || m["model"] != "opus" {
		t.Fatalf("merge lost data: %v", m)
	}
	clearProxyEnv(m, "http://127.0.0.1:41080")
	env = m["env"].(map[string]any)
	if _, ok := env["HTTPS_PROXY"]; ok || env["FOO"] != "1" {
		t.Fatalf("revert wrong: %v", m)
	}
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
		if err := Configure(proxy, enable); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("untouched file comes back byte for byte", func(t *testing.T) {
		path, _ := testutil.Home(t)
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
		path, _ := testutil.Home(t)
		toggle(true)
		toggle(false)
		if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
			t.Fatalf("~/.claude is still there: %v", err)
		}
	})

	t.Run("later edits stay, old proxy returns", func(t *testing.T) {
		path, _ := testutil.Home(t)
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
		path, _ := testutil.Home(t)
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
		path, _ := testutil.Home(t)
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
		path, _ := testutil.Home(t)
		write(path, "{\"env\":{\"HTTPS_PROXY\":\""+proxy+"\",\"HTTP_PROXY\":\""+proxy+"\"}}")
		toggle(true)
		toggle(false)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("file is still there: %v", err)
		}
	})
}
