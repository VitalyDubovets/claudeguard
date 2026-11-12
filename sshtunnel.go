package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

func sshArgs(host string, port int) []string {
	return []string{
		"-N", "-D", fmt.Sprintf("127.0.0.1:%d", port),
		"-o", "BatchMode=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=15",
		// Our own connection: a shared master would keep the forward alive
		// after we kill ssh, and traffic would stay on the old server.
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		host,
	}
}

// tailBuffer keeps the last bytes ssh wrote to stderr, for error messages.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	os.Stderr.Write(p)
	t.mu.Lock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > 400 {
		t.buf = t.buf[len(t.buf)-400:]
	}
	t.mu.Unlock()
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(string(t.buf)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// startSSH runs one ssh -D and reports once its SOCKS port accepts
// connections. The returned channel yields ssh's exit error.
func startSSH(ctx context.Context, host string, port int, ready func()) (<-chan error, *tailBuffer, error) {
	stderr := &tailBuffer{}
	cmd := exec.CommandContext(ctx, "ssh", sshArgs(host, port)...)
	cmd.Stderr = stderr
	hideChildWindow(cmd)
	if err := cmd.Start(); err != nil {
		return nil, stderr, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited := make(chan error, 1)
	go func() {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		for {
			select {
			case err := <-done:
				exited <- err
				return
			case <-time.After(300 * time.Millisecond):
				if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
					c.Close()
					if ready != nil {
						ready()
					}
					exited <- <-done
					return
				}
			}
		}
	}()
	return exited, stderr, nil
}

// superviseSSH keeps the SOCKS tunnel up until ctx is cancelled: after
// sleep, a network change or a dropped connection ssh exits and is restarted.
// While it is down the bridge answers 502, so nothing goes direct.
func superviseSSH(ctx context.Context, host string, port int, report func(state, detail string)) {
	for ctx.Err() == nil {
		start := time.Now()
		report("starting", "")
		log.Printf("ssh tunnel %s -> 127.0.0.1:%d: starting", host, port)
		exited, stderr, err := startSSH(ctx, host, port, func() { report("up", "") })
		if err == nil {
			err = <-exited
		}
		if ctx.Err() != nil {
			return
		}
		detail := stderr.String()
		if detail == "" && err != nil {
			detail = err.Error()
		}
		log.Printf("ssh tunnel %s exited: %v %s", host, err, detail)
		report("down", detail)
		delay := time.Second
		if time.Since(start) < 30*time.Second {
			delay = 3 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// sshConfigHosts lists concrete Host aliases from ~/.ssh/config (and files
// it includes), for the "add server" suggestions in the UI.
func sshConfigHosts() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		f, err := os.Open(path)
		if err != nil || depth > 3 {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			switch strings.ToLower(fields[0]) {
			case "host":
				for _, h := range fields[1:] {
					if !strings.ContainsAny(h, "*?!") {
						seen[h] = true
					}
				}
			case "include":
				for _, inc := range fields[1:] {
					if strings.HasPrefix(inc, "~/") {
						inc = filepath.Join(home, inc[2:])
					} else if !filepath.IsAbs(inc) {
						inc = filepath.Join(home, ".ssh", inc)
					}
					matches, _ := filepath.Glob(inc)
					for _, m := range matches {
						walk(m, depth+1)
					}
				}
			}
		}
	}
	walk(filepath.Join(home, ".ssh", "config"), 0)
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
