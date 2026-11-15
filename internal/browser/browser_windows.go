package browser

import (
	"os/exec"
	"syscall"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

const inetKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func inetValue(name string) string {
	cmd := exec.Command(sysutil.SysTool("reg.exe"), "query", inetKey, "/v", name)
	sysutil.HideChildWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return regValue(string(out), name)
}

func inetPAC() string { return inetValue("AutoConfigURL") }

// manualProxy is the proxy typed into the system settings and switched on.
// A PAC address wins over it, so ours on top would take that proxy away
// from every site that is not Claude's.
func manualProxy() string {
	if inetValue("ProxyEnable") != "0x1" {
		return ""
	}
	return inetValue("ProxyServer")
}

func inetSet(url string) error {
	cmd := exec.Command(sysutil.SysTool("reg.exe"), "delete", inetKey, "/v", "AutoConfigURL", "/f")
	if url != "" {
		cmd = exec.Command(sysutil.SysTool("reg.exe"), "add", inetKey, "/v", "AutoConfigURL", "/t", "REG_SZ", "/d", url, "/f")
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
	foreign := url
	if foreign == "" {
		if m := manualProxy(); m != "" {
			foreign = manualNote(m)
		}
	}
	return pacState{"url": url}, foreign, nil
}

func setSystemPAC(url string) error { return inetSet(url) }

func restoreSystemPAC(prev pacState, ours string) error {
	if inetPAC() != ours {
		return nil
	}
	return inetSet(prev["url"])
}

func systemPACIs(ours string) bool { return inetPAC() == ours }

func systemPACWhole(ours string) bool { return systemPACIs(ours) }
