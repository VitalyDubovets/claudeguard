package sysutil

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SysTool is the full path of a tool that ships with Windows, so that a
// program of the same name earlier in PATH is never run instead, least of
// all with admin rights. If the file is not where it should be, the bare
// name is returned and PATH decides, as before.
func SysTool(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	dir := filepath.Join(root, "System32")
	if strings.EqualFold(name, "powershell.exe") {
		dir = filepath.Join(dir, "WindowsPowerShell", "v1.0")
	}
	if st, err := os.Stat(filepath.Join(dir, name)); err == nil && !st.IsDir() {
		return filepath.Join(dir, name)
	}
	return name
}

// ListenerPID is the process that listens on 127.0.0.1:port, or 0.
func ListenerPID(port int) int {
	cmd := exec.Command(SysTool("netstat.exe"), "-ano", "-p", "TCP")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()
	want := "127.0.0.1:" + strconv.Itoa(port)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 5 && f[1] == want && f[3] == "LISTENING" {
			pid, _ := strconv.Atoi(f[4])
			return pid
		}
	}
	return 0
}

// PowerShell runs a script without a profile and returns its output.
func PowerShell(script string) (string, error) {
	cmd := exec.Command(SysTool("powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("powershell: %w\n%s", err, out)
	}
	return string(out), nil
}

// IsRoot reports whether the process has admin rights.
func IsRoot() bool {
	out, err := PowerShell(`([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`)
	return err == nil && strings.TrimSpace(out) == "True"
}

// CopyFile copies src over dst atomically: the copy is written next to dst
// and renamed over it, so a failed copy never leaves a truncated dst.
func CopyFile(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// A process that was just stopped may hold dst for a moment longer.
	for i := 0; ; i++ {
		if err = os.Rename(tmp, dst); err == nil || i == 9 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// HideChildWindow keeps a console child from flashing a window (Windows).
func HideChildWindow(cmd *exec.Cmd) {
	const createNoWindow = 0x08000000
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
