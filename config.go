package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Profile is one way out: an SSH host (claudeguard keeps `ssh -D` to it
// running) or an existing SOCKS5/HTTP proxy.
type Profile struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`   // ssh | socks5 | http
	Target string `json:"target"` // ssh host alias, or proxy URL
}

func (p Profile) validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("имя сервера пустое")
	}
	switch p.Kind {
	case "ssh":
		// The target becomes an ssh argument: no options, no shell syntax.
		if p.Target == "" || strings.HasPrefix(p.Target, "-") || strings.ContainsAny(p.Target, " \t\r\n'\"`$;&|<>\\") {
			return fmt.Errorf("недопустимый SSH-хост %q", p.Target)
		}
	case "socks5", "http":
		up, err := parseUpstream(p.Target)
		if err != nil {
			return err
		}
		if up.scheme != p.Kind {
			return fmt.Errorf("адрес %q не похож на %s-прокси", p.Target, p.Kind)
		}
	default:
		return fmt.Errorf("неизвестный тип %q", p.Kind)
	}
	return nil
}

// Config is the per-user part: the server list, which one is active, where
// the local proxy listens, and the kill switch options last applied.
type Config struct {
	Profiles     []Profile `json:"profiles"`
	Active       string    `json:"active"`
	Listen       string    `json:"listen"`
	AllowTunnels bool      `json:"allow_tunnels"`
	ExtraBlock   []string  `json:"extra_block,omitempty"`
	Token        string    `json:"ui_token"`

	// Fields from 0.1.0, migrated into Profiles on load.
	Upstream string `json:"upstream,omitempty"`
	SSHHost  string `json:"ssh_host,omitempty"`
}

const defaultListen = "127.0.0.1:41080"

func defaultConfig() Config {
	return Config{Listen: defaultListen}
}

func (c Config) proxyURL() string { return "http://" + c.Listen }

func (c Config) firewall() FirewallOptions {
	return FirewallOptions{AllowTunnels: c.AllowTunnels, Extra: c.ExtraBlock}
}

func (c Config) profile(name string) (Profile, bool) {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// upsert replaces the profile called old (or p.Name) or appends p.
func (c *Config) upsert(old string, p Profile) error {
	if err := p.validate(); err != nil {
		return err
	}
	if old == "" {
		old = p.Name
	}
	if _, taken := c.profile(p.Name); taken && p.Name != old {
		return fmt.Errorf("сервер %q уже есть", p.Name)
	}
	for i, q := range c.Profiles {
		if q.Name == old {
			c.Profiles[i] = p
			if c.Active == old {
				c.Active = p.Name
			}
			return nil
		}
	}
	c.Profiles = append(c.Profiles, p)
	return nil
}

func (c *Config) remove(name string) {
	out := c.Profiles[:0]
	for _, p := range c.Profiles {
		if p.Name != name {
			out = append(out, p)
		}
	}
	c.Profiles = out
	if c.Active == name {
		c.Active = ""
	}
}

// profileFromFlags turns --ssh HOST / --upstream URL into a profile.
func profileFromFlags(sshHost, upstreamURL string) (Profile, bool, error) {
	switch {
	case sshHost != "":
		p := Profile{Name: sshHost, Kind: "ssh", Target: sshHost}
		return p, true, p.validate()
	case upstreamURL != "":
		up, err := parseUpstream(upstreamURL)
		if err != nil {
			return Profile{}, false, err
		}
		u, _ := url.Parse(upstreamURL)
		p := Profile{Name: u.Hostname(), Kind: up.scheme, Target: upstreamURL}
		return p, true, p.validate()
	}
	return Profile{}, false, nil
}

func (c *Config) normalize() {
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if p, ok, err := profileFromFlags(c.SSHHost, c.Upstream); ok && err == nil {
		if _, exists := c.profile(p.Name); !exists {
			c.Profiles = append(c.Profiles, p)
		}
		if c.Active == "" {
			c.Active = p.Name
		}
	}
	c.SSHHost, c.Upstream = "", ""
	if _, ok := c.profile(c.Active); !ok {
		c.Active = ""
	}
	if c.Token == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		c.Token = hex.EncodeToString(b)
	}
}

// upstream is where the bridge sends traffic for p. An SSH profile goes
// through the SOCKS port of its own ssh -D tunnel.
func (p Profile) upstream(sshPort int) (*upstream, error) {
	if p.Kind == "ssh" {
		return &upstream{scheme: "socks5", addr: "127.0.0.1:" + strconv.Itoa(sshPort)}, nil
	}
	return parseUpstream(p.Target)
}

func configPath() (string, error) {
	if p := os.Getenv("CLAUDEGUARD_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "claudeguard", "config.json"), nil
}

func loadConfig() (Config, error) {
	c := defaultConfig()
	p, err := configPath()
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return c, err
	}
	if err == nil {
		if err := json.Unmarshal(data, &c); err != nil {
			return c, fmt.Errorf("%s: %w", p, err)
		}
	}
	hadToken := c.Token != ""
	c.normalize()
	if !hadToken {
		// serve and ui must agree on the token, so persist it right away.
		if err := saveConfig(c); err != nil {
			return c, err
		}
	}
	return c, nil
}

func saveConfig(c Config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	tmp := p + ".new"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
