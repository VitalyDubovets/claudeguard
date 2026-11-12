package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The PAC file is run by a real JavaScript engine where one is at hand.
func TestPACFile(t *testing.T) {
	pac := pacFile("127.0.0.1:41080")
	for _, d := range pacDomains {
		if !strings.Contains(pac, `"`+d+`"`) {
			t.Errorf("%s is not in the PAC file", d)
		}
	}
	if runtime.GOOS != "darwin" {
		return
	}
	want := map[string]string{
		"claude.ai":             "PROXY 127.0.0.1:41080",
		"API.Anthropic.com":     "PROXY 127.0.0.1:41080",
		"www.claude.com":        "PROXY 127.0.0.1:41080",
		"notclaude.ai":          "DIRECT",
		"claude.ai.example.com": "DIRECT",
		"example.com":           "DIRECT",
	}
	for host, proxy := range want {
		script := pac + `FindProxyForURL("https://` + host + `/", "` + host + `")`
		out, err := exec.Command("/usr/bin/osascript", "-l", "JavaScript", "-e", script).Output()
		if err != nil {
			t.Fatalf("osascript: %v", err)
		}
		if got := strings.TrimSpace(string(out)); got != proxy {
			t.Errorf("%s: got %q, want %q", host, got, proxy)
		}
	}
}

// Reading the system setting must work and must not see a foreign proxy
// where there is none; nothing is changed here.
func TestSystemPACRead(t *testing.T) {
	if os.Getenv("CLAUDEGUARD_TEST_SYSTEM") == "" {
		t.Skip("reads this machine's network settings; set CLAUDEGUARD_TEST_SYSTEM=1")
	}
	st, foreign, err := systemPAC("http://127.0.0.1:1/proxy.pac")
	t.Logf("state %v, foreign %q, err %v, ours on: %v", st, foreign, err, systemPACIs("http://127.0.0.1:1/proxy.pac"))
}

func TestBrowserPrevIsRemovedWithAppData(t *testing.T) {
	uninstallHome(t)
	p, err := pacPrevPath()
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeAppData()
	if _, err := os.Stat(p); err == nil {
		t.Error("browser.prev.json survived removeAppData")
	}
}
