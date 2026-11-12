package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Setting up a new server happens in-process with x/crypto/ssh: it is the
// only step that needs a password, and that password never touches disk or
// the system ssh. The tunnel itself keeps running on the system ssh, with
// the key and known_hosts that claudeguard owns (next to config.json).

func appSSHFile(name string) (string, error) {
	cfg, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), name), nil
}

func appKeyPath() (string, error)        { return appSSHFile("id_ed25519") }
func appKnownHostsPath() (string, error) { return appSSHFile("known_hosts") }

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
func sshTargetArgs(p Profile) []string {
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

func resolveSSH(ctx context.Context, p Profile) (sshDest, error) {
	cmd := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, sshTargetArgs(p)...)...)
	hideChildWindow(cmd)
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

var errGotKey = errors.New("host key received")

// scanHostKey connects only far enough to see the server's host key.
func scanHostKey(ctx context.Context, d sshDest) (ssh.PublicKey, error) {
	if d.Jump {
		return nil, errors.New("сервер доступен только через ProxyJump или ProxyCommand: подтвердите его ключ командой ssh в терминале")
	}
	addr := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("нет соединения с %s: %s", addr, shortErr(err))
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
		return nil, fmt.Errorf("%s не ответил как SSH-сервер: %s", addr, shortErr(err))
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

func (probeKey) Type() string                        { return "claudeguard-probe" }
func (probeKey) Marshal() []byte                     { return []byte("claudeguard-probe") }
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
func (a addrString) String() string  { return string(a) }

var knownHostsMu sync.Mutex

func trustHostKey(address string, key ssh.PublicKey) error {
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

type hostKeys struct {
	mu     sync.Mutex
	offers map[string]hostKeyOffer
}

func (h *hostKeys) offer(address string, key ssh.PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.offers == nil {
		h.offers = map[string]hostKeyOffer{}
	}
	h.offers[address] = hostKeyOffer{key: key, at: time.Now()}
}

func (h *hostKeys) take(address, fingerprint string) (ssh.PublicKey, error) {
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

type hostKeyView struct {
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"key_type"`
	Status      string `json:"status"` // known | unknown | changed
}

func (h *hostKeys) inspect(ctx context.Context, p Profile) (hostKeyView, error) {
	d, err := resolveSSH(ctx, p)
	if err != nil {
		return hostKeyView{}, err
	}
	key, err := scanHostKey(ctx, d)
	if err != nil {
		return hostKeyView{}, err
	}
	status, err := hostKeyCheck(d, key)
	if err != nil {
		return hostKeyView{}, err
	}
	v := hostKeyView{Address: d.address(), Fingerprint: ssh.FingerprintSHA256(key), KeyType: key.Type(), Status: status}
	if status == "unknown" {
		h.offer(v.Address, key)
	}
	return v, nil
}

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

// forgetServerKeys removes claudeguard's key from the servers that were set
// up in the panel, before uninstall deletes the key itself. It returns the
// servers it could not reach: there the line stays.
func forgetServerKeys(cfg Config) (left []string) {
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
		hideChildWindow(cmd)
		cmd.Stdin = strings.NewReader(appKeyLine(signer.PublicKey()))
		if err := cmd.Run(); err != nil {
			left = append(left, p.Name)
		}
		cancel()
	}
	return left
}

// removeAppData deletes what claudeguard keeps next to config.json: its key
// and the host keys trusted in the panel, the snapshot of Claude Code's
// settings, the data of the settings window.
func removeAppData() {
	cfg, err := configPath()
	if err != nil {
		return
	}
	dir := filepath.Dir(cfg)
	for _, name := range []string{"id_ed25519", "id_ed25519.pub", "known_hosts", "settings.prev.json", "open.html", "window.lock", "window", "webview"} {
		_ = os.RemoveAll(filepath.Join(dir, name))
	}
	_ = os.Remove(cfg)
	_ = os.Remove(cfg + ".new")
	_ = os.Remove(dir) // goes only if nothing else is in it
}

type setupRequest struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
}

func (r setupRequest) profile() Profile {
	p := Profile{Name: strings.TrimSpace(r.Name), Kind: "ssh", Target: strings.TrimSpace(r.Host), User: strings.TrimSpace(r.User), Port: r.Port, Managed: true}
	if p.Port == 22 {
		p.Port = 0
	}
	if p.Name == "" {
		p.Name = p.Target
	}
	return p
}

// setupServer logs in with the password, installs claudeguard's key and
// checks that the server forwards connections to Anthropic. The host key
// must already be trusted: setup never accepts an unknown key on its own.
// step reports progress: 1 logged in, 2 key installed, 3 forwarding works.
func setupServer(ctx context.Context, p Profile, password string, step func(int)) error {
	d, err := resolveSSH(ctx, p)
	if err != nil {
		return err
	}
	if d.Jump {
		return errors.New("серверы за ProxyJump так не настроить: добавьте ключ вручную")
	}
	files := d.knownFiles()
	if len(files) == 0 {
		return errors.New("ключ хоста не подтверждён")
	}
	known, err := knownhosts.New(files...)
	if err != nil {
		return err
	}
	pub, err := ensureAppKey()
	if err != nil {
		return fmt.Errorf("ключ claudeguard: %w", err)
	}

	addr := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("нет соединения с %s: %s", addr, shortErr(err))
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	// Cancelling in the panel must drop the session at once.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              d.User,
		HostKeyAlgorithms: hostKeyAlgos(d),
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if err := known(d.hostPort(), addrString(d.hostPort()), key); err != nil {
				var ke *knownhosts.KeyError
				if errors.As(err, &ke) && len(ke.Want) > 0 {
					return errors.New("ключ хоста изменился")
				}
				return errors.New("ключ хоста не подтверждён")
			}
			return nil
		},
	})
	if err != nil {
		return setupAuthError(err, d.User)
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()
	step(1)

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("сервер не открыл сессию: %s", shortErr(err))
	}
	sess.Stdin = strings.NewReader(appKeyLine(pub))
	stderr := &tailBuffer{} // bounded: the server decides how much it writes
	sess.Stderr = stderr
	err = sess.Run(installKeyScript)
	sess.Close()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = shortErr(err)
		}
		return fmt.Errorf("не удалось записать ключ в ~/.ssh/authorized_keys: %s", msg)
	}

	step(2)

	c, err := client.Dial("tcp", "api.anthropic.com:443")
	if err != nil {
		if strings.Contains(err.Error(), "prohibited") {
			return errors.New("ключ установлен, но сервер запрещает туннели: включите AllowTcpForwarding yes в /etc/ssh/sshd_config")
		}
		return fmt.Errorf("ключ установлен, но сервер не достучался до api.anthropic.com: %s", shortErr(err))
	}
	c.Close()
	step(3)
	return nil
}

func setupAuthError(err error, user string) error {
	msg := err.Error()
	switch {
	// Message 51 is USERAUTH_FAILURE: some servers answer a keyboard-interactive
	// attempt with it right away, and the library reports that as a protocol error.
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "unexpected message type 51"):
		if user == "root" {
			return errors.New("пароль не подошёл. Если он верный, на сервере может быть запрещён вход root по паролю (PermitRootLogin) или вход по паролю вообще (PasswordAuthentication)")
		}
		return errors.New("пароль не подошёл. Если он верный, на сервере может быть выключен вход по паролю (PasswordAuthentication)")
	}
	if i := strings.LastIndex(msg, "ключ хоста"); i >= 0 {
		return errors.New(msg[i:])
	}
	return fmt.Errorf("ssh: %s", shortErr(err))
}
