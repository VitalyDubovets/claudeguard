package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// SetupRequest is the form for a new SSH server.
type SetupRequest struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// Profile is the server the form describes.
func (r SetupRequest) Profile() config.Profile {
	p := config.Profile{Name: strings.TrimSpace(r.Name), Kind: config.KindSSH, Target: strings.TrimSpace(r.Host), User: strings.TrimSpace(r.User), Port: r.Port, Managed: true}
	if p.Port == 22 {
		p.Port = 0
	}
	if p.Name == "" {
		p.Name = p.Target
	}
	return p
}

// SetupServer logs in with the password, installs claudeguard's key and
// checks that the server forwards connections to Anthropic. The host key
// must already be trusted: setup never accepts an unknown key on its own.
// step reports progress: 1 logged in, 2 key installed, 3 forwarding works.
func SetupServer(ctx context.Context, p config.Profile, password string, step func(int)) error {
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
		return fmt.Errorf("нет соединения с %s: %s", addr, sysutil.ShortErr(err))
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
		return fmt.Errorf("сервер не открыл сессию: %s", sysutil.ShortErr(err))
	}
	sess.Stdin = strings.NewReader(appKeyLine(pub))
	stderr := &tailBuffer{} // bounded: the server decides how much it writes
	sess.Stderr = stderr
	err = sess.Run(installKeyScript)
	sess.Close()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = sysutil.ShortErr(err)
		}
		return fmt.Errorf("не удалось записать ключ в ~/.ssh/authorized_keys: %s", msg)
	}

	step(2)

	c, err := client.Dial("tcp", "api.anthropic.com:443")
	if err != nil {
		if strings.Contains(err.Error(), "prohibited") {
			return errors.New("ключ установлен, но сервер запрещает туннели: включите AllowTcpForwarding yes в /etc/ssh/sshd_config")
		}
		return fmt.Errorf("ключ установлен, но сервер не достучался до api.anthropic.com: %s", sysutil.ShortErr(err))
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
	return fmt.Errorf("ssh: %s", sysutil.ShortErr(err))
}
