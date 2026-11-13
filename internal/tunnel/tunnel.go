// Package tunnel does everything about SSH servers: it keeps the ssh -D
// tunnel running, sets a new server up with claudeguard's own key and
// checks host keys.
package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

func sshArgs(p config.Profile, port int) []string {
	args := []string{
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
		// The panel decides which host keys to trust; a lax ~/.ssh/config
		// must not let the tunnel accept a new or changed key on its own.
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
	}
	return append(args, sshTargetArgs(p)...)
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

// Start runs one ssh -D and reports once its SOCKS port accepts
// connections and it is this ssh that listens there: the port number is
// visible to every local user, and whoever grabs it before ssh binds would
// otherwise receive Claude's traffic. The returned channel yields ssh's
// exit error.
func Start(ctx context.Context, p config.Profile, port int, ready func()) (<-chan error, fmt.Stringer, error) {
	stderr := &tailBuffer{}
	cmd := exec.CommandContext(ctx, "ssh", sshArgs(p, port)...)
	cmd.Stderr = stderr
	sysutil.HideChildWindow(cmd)
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
					if sysutil.ListenerPID(port) != cmd.Process.Pid {
						continue
					}
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

// States Supervise reports.
const (
	Starting = "starting"
	Up       = "up"
	Down     = "down"
)

// Supervise keeps the SOCKS tunnel up until ctx is cancelled: after
// sleep, a network change or a dropped connection ssh exits and is restarted.
// While it is down the bridge answers 502, so nothing goes direct. Every
// attempt gets a fresh port, reported with "up": a port a dead ssh left
// behind is never used again.
func Supervise(ctx context.Context, p config.Profile, report func(state, detail string, port int)) {
	host := p.Target
	for ctx.Err() == nil {
		start := time.Now()
		report(Starting, "", 0)
		var exited <-chan error
		var stderr fmt.Stringer = &tailBuffer{}
		port, err := sysutil.FreePort()
		if err == nil {
			log.Printf("ssh tunnel %s -> 127.0.0.1:%d: starting", host, port)
			exited, stderr, err = Start(ctx, p, port, func() { report(Up, "", port) })
		}
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
		report(Down, detail, 0)
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
