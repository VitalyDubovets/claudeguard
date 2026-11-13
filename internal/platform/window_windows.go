//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"

	"github.com/VitalyDubovets/claudeguard/internal/config"
)

const windowTitle = "Claudeguard"

// focusWindow brings an already open settings window to the front.
func focusWindow() bool {
	// "webview" is the window class of go-webview2.
	class, _ := syscall.UTF16PtrFromString("webview")
	title, _ := syscall.UTF16PtrFromString(windowTitle)
	hwnd, _, _ := user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return false
	}
	const swRestore = 9
	user32.NewProc("ShowWindow").Call(hwnd, swRestore)
	user32.NewProc("SetForegroundWindow").Call(hwnd)
	return true
}

// ShowWindow shows the settings page in a WebView2 window and returns when
// the window is closed. WebView2 ships with Windows 11 and with Edge on
// Windows 10; without it the browser takes over.
func ShowWindow(url string) error {
	if focusWindow() {
		return nil
	}
	data := ""
	if p, err := config.File("webview"); err == nil {
		data = p
	}
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus:     true,
		DataPath:      data,
		WindowOptions: webview2.WindowOptions{Title: windowTitle, Width: 1040, Height: 780, Center: true},
	})
	if w == nil {
		return ErrNoWindow
	}
	defer w.Destroy()
	// The window takes the icon of the exe.
	if exe, err := os.Executable(); err == nil {
		if path, err := syscall.UTF16PtrFromString(exe); err == nil {
			icon, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("ExtractIconW").Call(0, uintptr(unsafe.Pointer(path)), 0)
			if icon > 1 {
				const wmSetIcon, iconSmall, iconBig = 0x0080, 0, 1
				send := user32.NewProc("SendMessageW")
				send.Call(uintptr(w.Window()), wmSetIcon, iconSmall, icon)
				send.Call(uintptr(w.Window()), wmSetIcon, iconBig, icon)
			}
		}
	}
	w.SetSize(560, 480, webview2.HintMin)
	w.Navigate(url)
	w.Run()
	return nil
}

// OpenPanel opens the settings window in a process of its own. It is not
// started hidden, unlike the background proxy: the window must show up.
func OpenPanel() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	_ = os.MkdirAll(installDir(), 0o755)
	cmd := exec.Command(exe, "window")
	if logf, err := os.OpenFile(filepath.Join(installDir(), "claudeguard.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		cmd.Stdout, cmd.Stderr = logf, logf
	}
	const detachedProcess = 0x00000008
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess}
	return cmd.Start()
}
