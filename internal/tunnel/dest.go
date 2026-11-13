package tunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// sshPath is how a path goes into an ssh -o option: quoted (Application
// Support has a space), with forward slashes on Windows.
func sshPath(p string) string {
	if runtime.GOOS == "windows" {
		p = filepath.ToSlash(p)
	}
	return `"` + p + `"`
}

// sshTargetArgs are the options that pick the server: everything ssh needs
// besides the tunnel itself. Hosts trusted in the panel live in our own
// known_hosts, which ssh reads in addition to the user's.
func sshTargetArgs(p config.Profile) []string {
	var a []string
	if kh, err := appKnownHostsPath(); err == nil {
		global := sshPath(kh)
		if runtime.GOOS != "windows" {
			global += " /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2"
		}
		a = append(a, "-o", "GlobalKnownHostsFile="+global)
	}
	if p.Managed {
		if key, err := appKeyPath(); err == nil {
			a = append(a, "-i", key, "-o", "IdentitiesOnly=yes")
		}
	}
	if p.User != "" {
		a = append(a, "-l", p.User)
	}
	if p.Port != 0 {
		a = append(a, "-p", strconv.Itoa(p.Port))
	}
	return append(a, p.Target)
}

// sshDest is where ssh would really connect for a profile, after
// ~/.ssh/config: `ssh -G` answers that without connecting.
type sshDest struct {
	Host      string
	Port      int
	User      string
	KeyAlias  string
	UserFiles []string
	Jump      bool
}

// address is the known_hosts name of the server, as ssh looks it up.
func (d sshDest) address() string {
	return knownhosts.Normalize(d.hostPort())
}

// hostPort is the same name with the port always present, as the knownhosts
// callback wants it: Normalize drops the default :22.
func (d sshDest) hostPort() string {
	h := d.Host
	if d.KeyAlias != "" {
		h = d.KeyAlias
	}
	return net.JoinHostPort(h, strconv.Itoa(d.Port))
}

func resolveSSH(ctx context.Context, p config.Profile) (sshDest, error) {
	cmd := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, sshTargetArgs(p)...)...)
	sysutil.HideChildWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return sshDest{}, fmt.Errorf("ssh -G: %w", err)
	}
	return parseSSHG(out), nil
}

func parseSSHG(out []byte) sshDest {
	d := sshDest{Port: 22}
	home, _ := os.UserHomeDir()
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch k {
		case "hostname":
			d.Host = v
		case "port":
			if n, err := strconv.Atoi(v); err == nil {
				d.Port = n
			}
		case "user":
			d.User = v
		case "hostkeyalias":
			d.KeyAlias = v
		case "userknownhostsfile":
			// ssh -G prints the paths unquoted, so one with a space falls
			// apart here. The default files are added by name as well, or a
			// home directory like "C:\Users\John Smith" would silently drop
			// the user's known_hosts and a known server would look new.
			for _, f := range append(strings.Fields(v), "~/.ssh/known_hosts", "~/.ssh/known_hosts2") {
				if strings.HasPrefix(f, "~/") {
					f = filepath.Join(home, f[2:])
				}
				if !slices.Contains(d.UserFiles, f) {
					d.UserFiles = append(d.UserFiles, f)
				}
			}
		case "proxyjump", "proxycommand":
			if v != "none" {
				d.Jump = true
			}
		}
	}
	return d
}
