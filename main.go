// claudeguard routes Claude (desktop app and Claude Code) through a proxy
// and blocks every direct connection to Anthropic at the OS firewall, so
// when the proxy or VPN goes down Claude goes offline instead of leaking.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const version = "0.2.0"

const usageText = `claudeguard %s: proxy + kill switch for Claude

Usage:
  claudeguard install [--ssh HOST | --upstream URL] [--listen ADDR] [--allow-tunnels]
                      [--extra-block CIDRS] [--no-settings] [--no-launcher]
      Set everything up. Asks for the admin password once (firewall rules).
  claudeguard ui                 Open the settings page (servers, kill switch)
  claudeguard uninstall          Remove rules, background proxy, launchers, settings
  claudeguard status             Check that the proxy works and direct access is blocked
  claudeguard launch [--app P]   (Re)start the Claude desktop app through the proxy
  claudeguard serve [--detach]   Run the local proxy and settings page
  claudeguard enable / disable   Turn only the firewall kill switch on or off (admin)

Servers are kept in the config and switched in the settings page. --ssh HOST
adds an SSH server (claudeguard keeps "ssh -N -D" to it running); --upstream
adds socks5://[user:pass@]host:port or http://[user:pass@]host:port.
The local proxy listens on 127.0.0.1:41080 unless --listen says otherwise.
`

func usage() { fmt.Fprintf(os.Stderr, usageText, version) }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "status":
		err = cmdStatus(args)
	case "launch":
		err = cmdLaunch(args)
	case "ui":
		err = cmdUI(args)
	case "serve":
		err = cmdServe(args)
	case "enable":
		err = cmdEnable(args)
	case "disable":
		err = cmdDisable(args)
	case "system-install":
		err = cmdSystemInstall(args)
	case "system-uninstall":
		err = cmdSystemUninstall(args)
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "claudeguard:", err)
		os.Exit(1)
	}
}

func firewallFlags(fs *flag.FlagSet, o *FirewallOptions) *string {
	fs.BoolVar(&o.AllowTunnels, "allow-tunnels", o.AllowTunnels, "also allow Anthropic traffic through VPN tunnel interfaces")
	return fs.String("extra-block", strings.Join(o.Extra, ","), "extra CIDRs to block, comma separated")
}

func parseFirewallArgs(name string, args []string) (FirewallOptions, error) {
	var o FirewallOptions
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	extra := firewallFlags(fs, &o)
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var err error
	o.Extra, err = parseCIDRList(*extra)
	return o, err
}

func cmdInstall(args []string) error {
	if isRoot() {
		return errors.New("run install as your normal user; it asks for admin rights itself")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	upstreamURL := fs.String("upstream", "", "add this SOCKS5/HTTP proxy and make it active")
	sshHost := fs.String("ssh", "", "add this SSH host and make it active")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "local proxy address")
	fw := cfg.firewall()
	extra := firewallFlags(fs, &fw)
	noSettings := fs.Bool("no-settings", false, "do not touch ~/.claude/settings.json")
	noLauncher := fs.Bool("no-launcher", false, "do not create the 'Claude via Proxy' launcher")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fw.Extra, err = parseCIDRList(*extra); err != nil {
		return err
	}
	cfg.AllowTunnels, cfg.ExtraBlock = fw.AllowTunnels, fw.Extra
	p, ok, err := profileFromFlags(*sshHost, *upstreamURL)
	if err != nil {
		return err
	}
	if ok {
		if err := cfg.upsert(p.Name, p); err != nil {
			return err
		}
		cfg.Active = p.Name
	}
	if err := saveConfig(cfg); err != nil {
		return err
	}

	fmt.Println("1/3 Firewall kill switch (needs admin rights)...")
	if err := elevate(append([]string{"system-install"}, fw.args()...)); err != nil {
		return fmt.Errorf("system part failed: %w", err)
	}
	fmt.Println("2/3 Background proxy, launcher...")
	if err := userInstall(cfg, !*noLauncher); err != nil {
		return err
	}
	if !*noSettings {
		fmt.Println("3/3 Claude Code settings (env HTTPS_PROXY/HTTP_PROXY)...")
		if err := configureClaudeCode(cfg.proxyURL(), true); err != nil {
			return fmt.Errorf("~/.claude/settings.json: %w", err)
		}
	}
	fmt.Println("\nDone. Restart Claude with the 'Claude via Proxy' launcher (or `claudeguard launch`).")
	if cfg.Active == "" {
		fmt.Println("No server yet: add one in the settings page.")
	}
	fmt.Println("Settings: the 'Claudeguard' launcher or `claudeguard ui`.")
	return nil
}

func cmdUninstall(args []string) error {
	if isRoot() {
		return errors.New("run uninstall as your normal user")
	}
	cfg, _ := loadConfig()
	var errs []error
	if err := configureClaudeCode(cfg.proxyURL(), false); err != nil {
		errs = append(errs, err)
	}
	if err := userUninstall(); err != nil {
		errs = append(errs, err)
	}
	if err := elevate([]string{"system-uninstall"}); err != nil {
		errs = append(errs, err)
	}
	if p, err := configPath(); err == nil {
		_ = os.Remove(p)
	}
	if len(errs) == 0 {
		fmt.Println("Removed. Restart Claude normally to go direct again.")
	}
	return errors.Join(errs...)
}

func cmdServe(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	saved := cfg.Listen
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "local proxy address (not saved)")
	detach := fs.Bool("detach", false, "start in the background and return")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *detach {
		if proxyListening(cfg.Listen) {
			return nil
		}
		return detachServe([]string{"serve", "--listen", cfg.Listen})
	}
	m := newManager(cfg, func(c Config) error {
		c.Listen = saved
		return saveConfig(c)
	})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		m.stop()
		time.Sleep(200 * time.Millisecond) // let ssh get its signal
		os.Exit(0)
	}()
	return runProxy(cfg.Listen, m)
}

// cmdUI opens the settings page, starting the proxy first if needed. The
// access token rides in the URL fragment, which browsers never send.
func cmdUI(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	id := proxyIdentity(cfg.Listen)
	if strings.HasPrefix(id, "NOT") {
		if err := detachServe([]string{"serve"}); err != nil {
			return err
		}
		for i := 0; i < 50 && !proxyListening(cfg.Listen); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		id = proxyIdentity(cfg.Listen)
	}
	if !strings.HasPrefix(id, "running") {
		return fmt.Errorf("local proxy %s: %s", cfg.Listen, id)
	}
	url := "http://" + cfg.Listen + "/ui#token=" + cfg.Token
	if err := openBrowser(url); err != nil {
		fmt.Println("Open this in a browser:", url)
	}
	return nil
}

func cmdEnable(args []string) error {
	o, err := parseFirewallArgs("enable", args)
	if err != nil {
		return err
	}
	if !isRoot() {
		return elevate(append([]string{"enable"}, args...))
	}
	return enableFirewall(o)
}

func cmdDisable(args []string) error {
	if !isRoot() {
		return elevate([]string{"disable"})
	}
	return disableFirewall()
}

func cmdSystemInstall(args []string) error {
	o, err := parseFirewallArgs("system-install", args)
	if err != nil {
		return err
	}
	if !isRoot() {
		return errors.New("system-install needs admin rights")
	}
	return systemInstall(o)
}

func cmdSystemUninstall(args []string) error {
	if !isRoot() {
		return errors.New("system-uninstall needs admin rights")
	}
	return systemUninstall()
}

func cmdLaunch(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("launch", flag.ContinueOnError)
	app := fs.String("app", "", "path to the Claude desktop app")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !proxyListening(cfg.Listen) {
		fmt.Fprintf(os.Stderr, "warning: local proxy %s is not running; Claude will stay offline until it is\n", cfg.Listen)
	}
	return launchApp(cfg, *app)
}

func proxyListening(listen string) bool {
	c, err := net.DialTimeout("tcp", listen, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// connectVia asks the local proxy to open a tunnel to target.
func connectVia(listen, target string) error {
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

// proxyIdentity tells our proxy apart from another program on the same port.
func proxyIdentity(listen string) string {
	if !proxyListening(listen) {
		return "NOT running"
	}
	c := http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Get("http://" + listen + "/claudeguard")
	if err == nil {
		defer resp.Body.Close()
		var b [200]byte
		n, _ := resp.Body.Read(b[:])
		if s := strings.TrimSpace(string(b[:n])); strings.HasPrefix(s, "claudeguard") {
			return "running (" + s + ")"
		}
	}
	return "port is taken by ANOTHER program; pick another --listen"
}

func directProbe(network, host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip"+strings.TrimPrefix(network, "tcp"), host)
	if err != nil || len(ips) == 0 {
		return "no address (skipped)"
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), "443"))
	if err != nil {
		return "blocked/unreachable (" + shortErr(err) + ")"
	}
	c.Close()
	return "OPEN: direct connection to " + ips[0].String() + " succeeded"
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

func cmdStatus(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	log.SetFlags(0)
	active := cfg.Active
	if p, ok := cfg.profile(active); ok {
		target := p.Target
		if up, err := parseUpstream(target); err == nil {
			target = up.String() // without the password
		}
		active += " (" + p.Kind + " " + target + ")"
	} else {
		active = "none: pick one in `claudeguard ui`"
	}
	fmt.Printf("server:          %s\n", active)
	fmt.Printf("local proxy:     %s %s\n", cfg.proxyURL(), proxyIdentity(cfg.Listen))
	fmt.Printf("firewall rules:  %s\n", firewallStatus())
	if err := connectVia(cfg.Listen, "api.anthropic.com:443"); err != nil {
		fmt.Printf("via proxy:       FAIL (%v)\n", err)
	} else {
		fmt.Println("via proxy:       ok (api.anthropic.com reachable through the proxy)")
	}
	v4 := directProbe("tcp4", "api.anthropic.com")
	v6 := directProbe("tcp6", "api.anthropic.com")
	fmt.Printf("direct IPv4:     %s\n", v4)
	fmt.Printf("direct IPv6:     %s\n", v6)
	if strings.HasPrefix(v4, "OPEN") || strings.HasPrefix(v6, "OPEN") {
		if cfg.AllowTunnels {
			fmt.Println("\nDirect access is open. Fine if a VPN tunnel is up right now (--allow-tunnels).")
		} else {
			fmt.Println("\nKILL SWITCH IS NOT ACTIVE: Claude can bypass the proxy. Run `claudeguard enable`.")
		}
	}
	return nil
}
