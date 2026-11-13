package proxy

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
)

// identityProof is what /claudeguard answers to a nonce. Only the user's own
// claudeguard knows the token, so another program on the port cannot fake it.
func identityProof(token, nonce string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("claudeguard identity " + nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// Listening reports whether anything accepts connections on listen.
func Listening(listen string) bool {
	c, err := net.DialTimeout("tcp", listen, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// ConnectVia asks the local proxy to open a tunnel to target.
func ConnectVia(listen, target string) error {
	c, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		return fmt.Errorf("local proxy not running: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(25 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}

// Owner says who holds the proxy port.
type Owner int

const (
	// Nobody listens on the port.
	Nobody Owner = iota
	// Ours is this user's claudeguard: it proved that it holds the token.
	Ours
	// Stranger is a claudeguard of another user or of an old version.
	Stranger
	// Other is some other program.
	Other
)

// Identity is the answer of Identify.
type Identity struct {
	Owner  Owner
	Banner string // "claudeguard 0.5.0 -> server", for Ours
}

// Running reports whether our own proxy answers on the port. Only then may
// the token be sent there.
func (i Identity) Running() bool { return i.Owner == Ours }

func (i Identity) String() string {
	switch i.Owner {
	case Nobody:
		return "NOT running"
	case Ours:
		return "running (" + i.Banner + ")"
	case Stranger:
		return "a claudeguard of ANOTHER user or an old version is on the port; run install again or pick another --listen"
	}
	return "port is taken by ANOTHER program; pick another --listen"
}

// Identify tells our proxy apart from another program on the same port: the
// listener has to prove that it holds this user's token, which is never
// sent to it.
func Identify(cfg config.Config) Identity {
	if !Listening(cfg.Listen) {
		return Identity{Owner: Nobody}
	}
	var nb [16]byte
	rand.Read(nb[:])
	nonce := hex.EncodeToString(nb[:])
	c := http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Get("http://" + cfg.Listen + "/claudeguard?nonce=" + nonce)
	if err != nil {
		return Identity{Owner: Other}
	}
	defer resp.Body.Close()
	var b [400]byte
	n, _ := io.ReadFull(resp.Body, b[:])
	lines := strings.Split(strings.TrimSpace(string(b[:n])), "\n")
	if !strings.HasPrefix(lines[0], "claudeguard") {
		return Identity{Owner: Other}
	}
	want := "proof " + identityProof(cfg.Token, nonce)
	if cfg.Token != "" && len(lines) > 1 && hmac.Equal([]byte(strings.TrimSpace(lines[1])), []byte(want)) {
		return Identity{Owner: Ours, Banner: lines[0]}
	}
	return Identity{Owner: Stranger}
}
