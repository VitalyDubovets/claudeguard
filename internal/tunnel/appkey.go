package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

func appKeyPath() (string, error) { return config.File("id_ed25519") }

// ensureAppKey returns claudeguard's own ed25519 key, creating it once.
func ensureAppKey() (ssh.PublicKey, error) {
	path, err := appKeyPath()
	if err != nil {
		return nil, err
	}
	if data, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return signer.PublicKey(), nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	comment := "claudeguard@" + host
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment + "\n"
	_ = os.WriteFile(path+".pub", []byte(line), 0o644)
	return sshPub, nil
}

// installKeyScript appends the key read from stdin to authorized_keys once.
// It runs under sh whatever the login shell is, and fixes a missing final
// newline so the key never glues onto the previous line.
const installKeyScript = `sh -c 'umask 077; f="$HOME/.ssh/authorized_keys"; mkdir -p "$HOME/.ssh" && touch "$f" && IFS= read -r k && { grep -qxF "$k" "$f" || { [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ] && echo >> "$f"; printf "%s\n" "$k" >> "$f"; }; }'`

// removeKeyScript takes the key read from stdin out of authorized_keys again.
// The file is rewritten in place, so its owner, mode and links stay as they
// were.
const removeKeyScript = `sh -c 'f="$HOME/.ssh/authorized_keys"; [ -f "$f" ] && IFS= read -r k && [ -n "$k" ] || exit 0; umask 077; t="$f.claudeguard.$$"; grep -vxF -e "$k" "$f" > "$t"; [ $? -le 1 ] && cat "$t" > "$f"; r=$?; rm -f "$t"; exit $r'`

// appKeyLine is the line a server set up in the panel has in authorized_keys.
func appKeyLine(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " claudeguard\n"
}

// ForgetServerKeys removes claudeguard's key from the servers that were set
// up in the panel, before uninstall deletes the key itself. It returns the
// servers it could not reach: there the line stays.
func ForgetServerKeys(cfg config.Config) (left []string) {
	path, err := appKeyPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil
	}
	// One server at a time: two profiles may point at the same file.
	for _, p := range cfg.Profiles {
		if !p.Managed {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		args := []string{
			"-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
			"-o", "ControlMaster=no", "-o", "ControlPath=none",
			"-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
		}
		cmd := exec.CommandContext(ctx, "ssh", append(append(args, sshTargetArgs(p)...), removeKeyScript)...)
		sysutil.HideChildWindow(cmd)
		cmd.Stdin = strings.NewReader(appKeyLine(signer.PublicKey()))
		if err := cmd.Run(); err != nil {
			left = append(left, p.Name)
		}
		cancel()
	}
	return left
}
