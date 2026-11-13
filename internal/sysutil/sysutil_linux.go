package sysutil

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// IsRoot reports whether the process has admin rights.
func IsRoot() bool { return os.Geteuid() == 0 }

// Tool finds a system program in the system directories only: PATH is the
// user's and may list a writable directory first, and some of these run as
// root.
func Tool(name string) string {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// Run runs a system tool and returns its combined output; the error
// carries the output too.
func Run(name string, args ...string) (string, error) {
	p := Tool(name)
	if p == "" {
		return "", fmt.Errorf("%s: not found on this system", name)
	}
	out, err := exec.Command(p, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// RunInput runs a system tool with input on its stdin.
func RunInput(input, name string, args ...string) error {
	p := Tool(name)
	if p == "" {
		return fmt.Errorf("%s: not found on this system", name)
	}
	cmd := exec.Command(p, args...)
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w\n%s", name, err, out)
	}
	return nil
}

var ssPidRe = regexp.MustCompile(`pid=(\d+)`)

// ListenerPID is the process that listens on 127.0.0.1:port, or 0.
func ListenerPID(port int) int {
	out, _ := Run("ss", "-H", "-ltnp", "src", "127.0.0.1", "sport", "=", ":"+strconv.Itoa(port))
	if m := ssPidRe.FindStringSubmatch(out); m != nil {
		pid, _ := strconv.Atoi(m[1])
		return pid
	}
	return 0
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
