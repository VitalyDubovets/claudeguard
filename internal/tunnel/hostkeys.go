package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

func appKnownHostsPath() (string, error) { return config.File("known_hosts") }

var errGotKey = errors.New("host key received")

// scanHostKey connects only far enough to see the server's host key.
func scanHostKey(ctx context.Context, d sshDest) (ssh.PublicKey, error) {
	if d.Jump {
		return nil, errors.New("сервер доступен только через ProxyJump или ProxyCommand: подтвердите его ключ командой ssh в терминале")
	}
	addr := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("нет соединения с %s: %s", addr, sysutil.ShortErr(err))
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	var key ssh.PublicKey
	_, _, _, err = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              "claudeguard",
		HostKeyAlgorithms: hostKeyAlgos(d),
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errGotKey
		},
	})
	if key == nil {
		return nil, fmt.Errorf("%s не ответил как SSH-сервер: %s", addr, sysutil.ShortErr(err))
	}
	return key, nil
}

// hostKeyAlgos asks the server for the kind of key we already know for d,
// as ssh does: a server known by its ed25519 key that also has an ecdsa one
// must not look like a changed host. For a new host it is ssh's own order.
func hostKeyAlgos(d sshDest) []string {
	byType := map[string][]string{
		ssh.KeyAlgoED25519:  {ssh.KeyAlgoED25519},
		ssh.KeyAlgoECDSA256: {ssh.KeyAlgoECDSA256},
		ssh.KeyAlgoECDSA384: {ssh.KeyAlgoECDSA384},
		ssh.KeyAlgoECDSA521: {ssh.KeyAlgoECDSA521},
		ssh.KeyAlgoRSA:      {ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA},
	}
	order := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA}
	known := map[string]bool{}
	if files := d.knownFiles(); len(files) > 0 {
		if cb, err := knownhosts.New(files...); err == nil {
			// Any key that cannot match makes the callback list the ones it has.
			var ke *knownhosts.KeyError
			if errors.As(cb(d.hostPort(), addrString(d.hostPort()), probeKey{}), &ke) {
				for _, k := range ke.Want {
					known[k.Key.Type()] = true
				}
			}
		}
	}
	var algos []string
	for _, t := range order {
		if known[t] || len(known) == 0 {
			algos = append(algos, byType[t]...)
		}
	}
	if len(algos) == 0 { // only key types we do not speak are on file
		for _, t := range order {
			algos = append(algos, byType[t]...)
		}
	}
	return algos
}

// probeKey is a key no known_hosts file holds.
type probeKey struct{}

func (probeKey) Type() string { return "claudeguard-probe" }

func (probeKey) Marshal() []byte { return []byte("claudeguard-probe") }

func (probeKey) Verify([]byte, *ssh.Signature) error { return errors.New("not a key") }

// knownFiles are the known_hosts files ssh would consult for d.
func (d sshDest) knownFiles() []string {
	files := append([]string(nil), d.UserFiles...)
	if kh, err := appKnownHostsPath(); err == nil {
		files = append(files, kh)
	}
	if runtime.GOOS != "windows" {
		files = append(files, "/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2")
	}
	var out []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	return out
}

// hostKeyCheck answers "known", "unknown" or "changed" for key at d.
func hostKeyCheck(d sshDest, key ssh.PublicKey) (string, error) {
	files := d.knownFiles()
	if len(files) == 0 {
		return "unknown", nil
	}
	cb, err := knownhosts.New(files...)
	if err != nil {
		return "", err
	}
	err = cb(d.hostPort(), addrString(d.hostPort()), key)
	var ke *knownhosts.KeyError
	switch {
	case err == nil:
		return "known", nil
	case errors.As(err, &ke) && len(ke.Want) == 0:
		return "unknown", nil
	case errors.As(err, &ke):
		return "changed", nil
	}
	return "", err
}

// addrString lets knownhosts match the name we pass, not a resolved IP:
// ssh itself does the same with CheckHostIP off (the default).
type addrString string

func (a addrString) Network() string { return "tcp" }

func (a addrString) String() string { return string(a) }

var knownHostsMu sync.Mutex

// TrustHostKey adds a host key to claudeguard's own known_hosts.
func TrustHostKey(address string, key ssh.PublicKey) error {
	kh, err := appKnownHostsPath()
	if err != nil {
		return err
	}
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(kh), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(kh, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(knownhosts.Line([]string{address}, key) + "\n")
	return err
}

// hostKeyOffer is a key the panel has shown; trusting it later must name
// the same fingerprint, so what is saved is exactly what the user saw.
type hostKeyOffer struct {
	key ssh.PublicKey
	at  time.Time
}

// HostKeys remembers the keys servers showed in Inspect, so that Take can
// hand out exactly the key the user looked at.
type HostKeys struct {
	mu     sync.Mutex
	offers map[string]hostKeyOffer
}

func (h *HostKeys) offer(address string, key ssh.PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.offers == nil {
		h.offers = map[string]hostKeyOffer{}
	}
	h.offers[address] = hostKeyOffer{key: key, at: time.Now()}
}

// Take returns the key offered for address if its fingerprint is the one
// the user confirmed.
func (h *HostKeys) Take(address, fingerprint string) (ssh.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	o, ok := h.offers[address]
	if !ok || time.Since(o.at) > 10*time.Minute {
		return nil, errors.New("ключ устарел, проверьте сервер ещё раз")
	}
	if ssh.FingerprintSHA256(o.key) != fingerprint {
		return nil, errors.New("отпечаток не совпадает с показанным")
	}
	delete(h.offers, address)
	return o.key, nil
}

// HostKeyView is a server's host key as the settings page shows it.
type HostKeyView struct {
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"key_type"`
	Status      string `json:"status"` // known | unknown | changed
}

// Inspect fetches the host key of p and says whether it is already trusted.
func (h *HostKeys) Inspect(ctx context.Context, p config.Profile) (HostKeyView, error) {
	d, err := resolveSSH(ctx, p)
	if err != nil {
		return HostKeyView{}, err
	}
	key, err := scanHostKey(ctx, d)
	if err != nil {
		return HostKeyView{}, err
	}
	status, err := hostKeyCheck(d, key)
	if err != nil {
		return HostKeyView{}, err
	}
	v := HostKeyView{Address: d.address(), Fingerprint: ssh.FingerprintSHA256(key), KeyType: key.Type(), Status: status}
	if status == "unknown" {
		h.offer(v.Address, key)
	}
	return v, nil
}
