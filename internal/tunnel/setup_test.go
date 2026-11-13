package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/VitalyDubovets/claudeguard/internal/config"
)

// testSSHD is a password-only SSH server whose exec requests really run
// under sh with HOME set to a temp dir, so the key install script is tested
// as is.
type testSSHD struct {
	addr     string
	port     int
	key      ssh.Signer
	home     string
	forwards bool
}

func startTestSSHD(t *testing.T, forwards bool) *testSSHD {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	s := &testSSHD{key: signer, home: t.TempDir(), forwards: forwards}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "root" && string(pw) == "secret" {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s.addr = ln.Addr().String()
	s.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg)
		}
	}()
	return s
}

func (s *testSSHD) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "direct-tcpip":
			if !s.forwards {
				nc.Reject(ssh.Prohibited, "administratively prohibited")
				continue
			}
			ch, rq, _ := nc.Accept()
			go ssh.DiscardRequests(rq)
			ch.Close()
		case "session":
			ch, rq, _ := nc.Accept()
			go func() {
				for r := range rq {
					if r.Type != "exec" {
						r.Reply(false, nil)
						continue
					}
					n := binary.BigEndian.Uint32(r.Payload)
					r.Reply(true, nil)
					cmd := exec.Command("sh", "-c", string(r.Payload[4:4+n]))
					cmd.Env = []string{"HOME=" + s.home, "PATH=" + os.Getenv("PATH")}
					cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
					status := 0
					if err := cmd.Run(); err != nil {
						status = 1
					}
					ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, uint32(status)))
					ch.Close()
				}
			}()
		default:
			nc.Reject(ssh.UnknownChannelType, "")
		}
	}
}

func (s *testSSHD) profile() config.Profile {
	return SetupRequest{Host: "127.0.0.1", Port: s.port, User: "root"}.Profile()
}

func useTempConfig(t *testing.T) string {
	dir := t.TempDir()
	t.Setenv("CLAUDEGUARD_CONFIG", filepath.Join(dir, "config.json"))
	return dir
}

func TestSSHSetupFlow(t *testing.T) {
	dir := useTempConfig(t)
	s := startTestSSHD(t, true)
	p := s.profile()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := SetupServer(ctx, p, "secret", func(int) {}); err == nil || !strings.Contains(err.Error(), "не подтверждён") {
		t.Fatalf("setup with an untrusted key: %v", err)
	}

	var keys HostKeys
	v, err := keys.Inspect(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	want := ssh.FingerprintSHA256(s.key.PublicKey())
	if v.Status != "unknown" || v.Fingerprint != want || v.Address != "[127.0.0.1]:"+itoa(s.port) {
		t.Fatalf("%+v, want %s", v, want)
	}
	if _, err := keys.Take(v.Address, "SHA256:bogus"); err == nil {
		t.Fatal("trusted a fingerprint that was not shown")
	}
	key, err := keys.Take(v.Address, v.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := TrustHostKey(v.Address, key); err != nil {
		t.Fatal(err)
	}
	if v, err := keys.Inspect(ctx, p); err != nil || v.Status != "known" {
		t.Fatalf("after trust: %+v %v", v, err)
	}

	if err := SetupServer(ctx, p, "wrong", func(int) {}); err == nil || !strings.Contains(err.Error(), "PermitRootLogin") {
		t.Fatalf("wrong password: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := SetupServer(ctx, p, "secret", func(int) {}); err != nil {
			t.Fatalf("setup #%d: %v", i, err)
		}
	}
	ak, err := os.ReadFile(filepath.Join(s.home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(filepath.Join(dir, "id_ed25519.pub"))
	keyBody := strings.Fields(string(pub))[1]
	if strings.Count(string(ak), keyBody) != 1 {
		t.Fatalf("authorized_keys should hold the key once:\n%s", ak)
	}
	if st, _ := os.Stat(filepath.Join(dir, "id_ed25519")); st == nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode: %v", st)
	}
}

func TestSSHSetupKeepsExistingKeys(t *testing.T) {
	useTempConfig(t)
	s := startTestSSHD(t, true)
	os.MkdirAll(filepath.Join(s.home, ".ssh"), 0o700)
	// No final newline: the new key must not glue onto this line.
	os.WriteFile(filepath.Join(s.home, ".ssh", "authorized_keys"), []byte("ssh-ed25519 AAAAexisting user@laptop"), 0o600)
	TrustHostKey(knownhosts.Normalize(s.addr), s.key.PublicKey())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := SetupServer(ctx, s.profile(), "secret", func(int) {}); err != nil {
		t.Fatal(err)
	}
	ak, _ := os.ReadFile(filepath.Join(s.home, ".ssh", "authorized_keys"))
	lines := strings.Split(strings.TrimSpace(string(ak)), "\n")
	if len(lines) != 2 || lines[0] != "ssh-ed25519 AAAAexisting user@laptop" || !strings.HasPrefix(lines[1], "ssh-ed25519 ") {
		t.Fatalf("authorized_keys:\n%s", ak)
	}
}

func TestSSHSetupNoForwarding(t *testing.T) {
	useTempConfig(t)
	s := startTestSSHD(t, false)
	TrustHostKey(knownhosts.Normalize(s.addr), s.key.PublicKey())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := SetupServer(ctx, s.profile(), "secret", func(int) {}); err == nil || !strings.Contains(err.Error(), "AllowTcpForwarding") {
		t.Fatalf("want AllowTcpForwarding hint, got %v", err)
	}
}

func TestSSHSetupChangedHostKey(t *testing.T) {
	useTempConfig(t)
	s := startTestSSHD(t, true)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	TrustHostKey(knownhosts.Normalize(s.addr), otherSigner.PublicKey())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var keys HostKeys
	if v, err := keys.Inspect(ctx, s.profile()); err != nil || v.Status != "changed" {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := keys.Take(knownhosts.Normalize(s.addr), ssh.FingerprintSHA256(s.key.PublicKey())); err == nil {
		t.Fatal("a changed key must not be offered for trust")
	}
	if err := SetupServer(ctx, s.profile(), "secret", func(int) {}); err == nil || !strings.Contains(err.Error(), "изменился") {
		t.Fatalf("want changed-key error, got %v", err)
	}
}

func TestSSHTargetArgs(t *testing.T) {
	dir := useTempConfig(t)
	args := sshTargetArgs(config.Profile{Kind: "ssh", Target: "1.2.3.4", User: "root", Port: 2222, Managed: true})
	got := strings.Join(args, " ")
	for _, want := range []string{
		`GlobalKnownHostsFile="` + filepath.Join(dir, "known_hosts") + `"`,
		"-i " + filepath.Join(dir, "id_ed25519"), "IdentitiesOnly=yes", "-l root", "-p 2222",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q lacks %q", got, want)
		}
	}
	if args[len(args)-1] != "1.2.3.4" {
		t.Fatalf("target must come last: %q", got)
	}
	if strings.Contains(strings.Join(sshTargetArgs(config.Profile{Kind: "ssh", Target: "vd-poland"}), " "), "IdentitiesOnly") {
		t.Fatal("hosts from ~/.ssh/config keep the user's keys")
	}
	if (config.Profile{Name: "x", Kind: "ssh", Target: "h", User: "-oProxyCommand=x"}).Validate() == nil {
		t.Fatal("user must not become an ssh option")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// The default port is where knownhosts.Normalize drops ":22"; the lookup
// must still work there.
func TestHostKeyCheckDefaultPort(t *testing.T) {
	useTempConfig(t)
	newKey := func() ssh.PublicKey {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	d := sshDest{Host: "host.example", Port: 22}
	key := newKey()
	if st, err := hostKeyCheck(d, key); err != nil || st != "unknown" {
		t.Fatalf("before trust: %q, %v", st, err)
	}
	if err := TrustHostKey(d.address(), key); err != nil {
		t.Fatal(err)
	}
	if st, err := hostKeyCheck(d, key); err != nil || st != "known" {
		t.Fatalf("after trust: %q, %v", st, err)
	}
	if st, err := hostKeyCheck(d, newKey()); err != nil || st != "changed" {
		t.Fatalf("other key: %q, %v", st, err)
	}
}

func TestHostKeyAlgosFollowKnownKey(t *testing.T) {
	useTempConfig(t)
	d := sshDest{Host: "host.example", Port: 22}
	if a := hostKeyAlgos(d); len(a) == 0 || a[0] != ssh.KeyAlgoED25519 || a[len(a)-1] != ssh.KeyAlgoRSA {
		t.Fatalf("new host: %v", a)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	if err := TrustHostKey(d.address(), key); err != nil {
		t.Fatal(err)
	}
	if a := hostKeyAlgos(d); len(a) != 1 || a[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("known by ed25519: %v", a)
	}
}

func TestSSHArgs(t *testing.T) {
	args := strings.Join(sshArgs(config.Profile{Kind: "ssh", Target: "vd-poland"}, 41081), " ")
	for _, want := range []string{"-D 127.0.0.1:41081", "BatchMode=yes", "ControlMaster=no", "ControlPath=none"} {
		if !strings.Contains(args, want) {
			t.Fatalf("ssh args lack %q: %s", want, args)
		}
	}
	if !strings.HasSuffix(args, "vd-poland") {
		t.Fatalf("ssh args: %s", args)
	}
}
