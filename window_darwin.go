//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa -framework WebKit
#include <stdlib.h>
int cgShowWindow(const char *url, const void *icon, int iconLen, int selftest);
void cgActivate(int pid);
int cgTrash(const char *path);
*/
import "C"

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed icons/claudeguard.png
var windowIcon []byte

// AppKit only works on the main thread, and init runs on it: this keeps
// main() there for the window.
func init() { runtime.LockOSThread() }

// showWindow shows the settings page in a window and returns when the window
// is closed. A second window is not opened: the first one comes to the front.
func showWindow(url string) error {
	selftest := os.Getenv("CLAUDEGUARD_WINDOW_SELFTEST") != ""
	if lock, err := appSSHFile("window.lock"); err == nil && !selftest {
		if f, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
			if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
				b, _ := os.ReadFile(lock)
				if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
					C.cgActivate(C.int(pid))
				}
				return nil
			}
			// Held until the process exits.
			_ = f.Truncate(0)
			_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
		}
	}
	curl := C.CString(url)
	defer C.free(unsafe.Pointer(curl))
	test := C.int(0)
	if selftest {
		test = 1
	}
	if C.cgShowWindow(curl, unsafe.Pointer(&windowIcon[0]), C.int(len(windowIcon)), test) != 0 {
		return errNoWindow
	}
	return nil
}

// appBundle finds Claudeguard.app, so that the window belongs to the app the
// user installed (its name in the menu bar, its icon in the Dock). The
// launchers made by osacompile carry no claudeguard binary and do not count.
func appBundle() string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		if i := strings.Index(exe, ".app/Contents/MacOS/"); i >= 0 {
			dirs = append(dirs, exe[:i+len(".app")])
		}
	}
	dirs = append(dirs, "/Applications/Claudeguard.app")
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications", "Claudeguard.app"))
	}
	for _, d := range dirs {
		if st, err := os.Stat(filepath.Join(d, "Contents", "MacOS", "claudeguard")); err == nil && !st.IsDir() {
			return d
		}
	}
	return ""
}

// openPanel opens the settings window in a process of its own.
func openPanel() error {
	if app := appBundle(); app != "" {
		if _, err := run("open", "-a", app, "--args", "window"); err == nil {
			return nil
		}
	}
	return detachServe([]string{"window"})
}

// closePanel closes the settings window of another process: the one that
// holds the lock.
func closePanel() {
	lock, err := appSSHFile("window.lock")
	if err != nil {
		return
	}
	f, err := os.OpenFile(lock, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer f.Close()
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		return
	}
	b, _ := os.ReadFile(lock)
	if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
}

// trash moves a file or a folder to the Trash.
func trash(path string) bool {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	return C.cgTrash(cpath) == 0
}
