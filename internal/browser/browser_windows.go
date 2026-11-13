package browser

import (
	"os/exec"
	"strings"
	"syscall"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

const inetKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func inetPAC() string {
	cmd := exec.Command("reg", "query", inetKey, "/v", "AutoConfigURL")
	sysutil.HideChildWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(out), "\n") {
		if _, v, ok := strings.Cut(l, "REG_SZ"); ok && strings.Contains(l, "AutoConfigURL") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func inetSet(url string) error {
	cmd := exec.Command("reg", "delete", inetKey, "/v", "AutoConfigURL", "/f")
	if url != "" {
		cmd = exec.Command("reg", "add", inetKey, "/v", "AutoConfigURL", "/t", "REG_SZ", "/d", url, "/f")
	}
	sysutil.HideChildWindow(cmd)
	err := cmd.Run()
	// Tell running programs that the settings changed, as the system dialog does.
	const settingsChanged, refresh = 39, 37
	opt := syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")
	opt.Call(0, settingsChanged, 0, 0)
	opt.Call(0, refresh, 0, 0)
	return err
}

func systemPAC(ours string) (pacState, string, error) {
	url := inetPAC()
	if url == ours {
		return pacState{}, "", nil
	}
	return pacState{"url": url}, url, nil
}

func setSystemPAC(url string) error { return inetSet(url) }

func restoreSystemPAC(prev pacState, ours string) error {
	if inetPAC() != ours {
		return nil
	}
	return inetSet(prev["url"])
}

func systemPACIs(ours string) bool { return inetPAC() == ours }
