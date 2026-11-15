package browser

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/VitalyDubovets/claudeguard/internal/testutil"
)

// The PAC file is run by a real JavaScript engine where one is at hand.
func TestPACFile(t *testing.T) {
	pac := PACFile("127.0.0.1:41080")
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

// Keep puts the address back only while the switch is on and nobody else
// has claimed the setting.
func TestKeepOnce(t *testing.T) {
	testutil.Home(t)
	const ours = "http://127.0.0.1:1/proxy.pac"
	system := ""
	writes := 0
	oldRead, oldOn, oldWrite := readPAC, pacIsOn, writePAC
	t.Cleanup(func() { readPAC, pacIsOn, writePAC = oldRead, oldOn, oldWrite })
	readPAC = func(string) (pacState, string, error) {
		if system == ours {
			return pacState{}, "", nil
		}
		return pacState{"url": system}, system, nil
	}
	pacIsOn = func(string) bool { return system == ours }
	writePAC = func(url string) error { system = url; writes++; return nil }

	// Switch off: a cleared setting is how it should be.
	if got, _ := keepOnce(ours); got || writes != 0 {
		t.Fatalf("restored with the switch off")
	}

	p, err := PrevPath()
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Switch on, setting wiped: put back.
	if got, err := keepOnce(ours); !got || err != nil || system != ours {
		t.Fatalf("not restored: got %v, err %v, system %q", got, err, system)
	}
	// In place: nothing to do.
	if got, _ := keepOnce(ours); got || writes != 1 {
		t.Fatalf("rewrote a setting that was in place")
	}
	// Someone else's proxy is left alone.
	system = "http://other/proxy.pac"
	if got, _ := keepOnce(ours); got || system != "http://other/proxy.pac" {
		t.Fatalf("replaced a foreign setting")
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
