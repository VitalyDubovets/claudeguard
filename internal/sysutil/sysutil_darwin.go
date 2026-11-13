package sysutil

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// IsRoot reports whether the process has admin rights.
func IsRoot() bool { return os.Geteuid() == 0 }

// ListenerPID is the process of this user that listens on 127.0.0.1:port,
// or 0. lsof shows a non-root user only their own sockets, which is the point.
func ListenerPID(port int) int {
	out, _ := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-iTCP@127.0.0.1:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fp").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "p") {
			pid, _ := strconv.Atoi(line[1:])
			return pid
		}
	}
	return 0
}

// SystemTools pins the tools we run, some of them as root, to their system
// locations: PATH is the user's and may list a writable directory first.
var SystemTools = map[string]string{
	"pfctl": "/sbin/pfctl", "launchctl": "/bin/launchctl", "sudo": "/usr/bin/sudo",
	"osascript": "/usr/bin/osascript", "osacompile": "/usr/bin/osacompile",
	"codesign": "/usr/bin/codesign", "open": "/usr/bin/open", "touch": "/usr/bin/touch", "pgrep": "/usr/bin/pgrep",
	"defaults":     "/usr/bin/defaults",
	"pkill":        "/usr/bin/pkill",
	"networksetup": "/usr/sbin/networksetup",
}

// Run runs a system tool and returns its combined output; the error
// carries the output too.
func Run(name string, args ...string) (string, error) {
	out, err := exec.Command(SystemTools[name], args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// CopyFile copies src over dst atomically.
func CopyFile(src, dst string, mode os.FileMode) error {
	if src == dst {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// Never write through something that is already there: as root, a
	// planted symlink would overwrite whatever it points at.
	tmp := dst + ".new"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// HideChildWindow keeps a console child from flashing a window (Windows).
func HideChildWindow(*exec.Cmd) {}
