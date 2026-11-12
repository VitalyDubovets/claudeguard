//go:build darwin

package main

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestClosePanel(t *testing.T) {
	_, dir := uninstallHome(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, _ := appSSHFile("window.lock")

	// A stale lock file names a process, but nobody holds the lock: that
	// process is not a window of ours and must live.
	bystander := exec.Command("sleep", "30")
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	defer bystander.Process.Kill()
	_ = os.WriteFile(lock, []byte(strconv.Itoa(bystander.Process.Pid)), 0o600)
	closePanel()
	if err := bystander.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("killed a process that held no lock")
	}

	window := exec.Command("sleep", "30")
	if err := window.Start(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lock, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(lock, []byte(strconv.Itoa(window.Process.Pid)), 0o600)
	closePanel()
	done := make(chan error, 1)
	go func() { done <- window.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		window.Process.Kill()
		t.Fatal("the window process was not stopped")
	}
}
