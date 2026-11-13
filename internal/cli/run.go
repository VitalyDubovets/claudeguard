package cli

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/panel"
	"github.com/VitalyDubovets/claudeguard/internal/platform"
	"github.com/VitalyDubovets/claudeguard/internal/proxy"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

const probeHost = "api.anthropic.com"

func runServe(args []string) error {
	cfg, err := config.Load()
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
		if proxy.Listening(cfg.Listen) {
			return nil
		}
		return platform.Detach([]string{"serve", "--listen", cfg.Listen})
	}
	m := proxy.NewManager(cfg, func(c config.Config) error {
		c.Listen = saved
		return config.Save(c)
	})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		m.Stop()
		time.Sleep(200 * time.Millisecond) // let ssh get its signal
		os.Exit(0)
	}()
	return proxy.Run(cfg.Listen, m, panel.NewHandler(m, cfg.Listen))
}

// runUI opens the settings window and returns at once: the window lives in
// a process of its own.
func runUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	inBrowser := fs.Bool("browser", false, "open the page in the browser instead of a window")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inBrowser {
		return panel.OpenInBrowser()
	}
	err := platform.OpenPanel()
	if errors.Is(err, sysutil.ErrUnsupported) {
		// No way to start a detached process here: show it from this one.
		return panel.Show()
	}
	return err
}

// runWindow is the process the settings window lives in.
func runWindow([]string) error { return panel.Show() }

func runEnable(args []string) error {
	o, err := parseFirewallArgs("enable", args)
	if err != nil {
		return err
	}
	if !sysutil.IsRoot() {
		return platform.Elevate(append([]string{"enable"}, args...))
	}
	return firewall.Enable(o)
}

func runDisable([]string) error {
	if !sysutil.IsRoot() {
		return platform.Elevate([]string{"disable"})
	}
	return firewall.Disable()
}

func runLaunch(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("launch", flag.ContinueOnError)
	app := fs.String("app", "", "path to the Claude desktop app")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !proxy.Listening(cfg.Listen) {
		fmt.Fprintf(os.Stderr, "warning: local proxy %s is not running; Claude will stay offline until it is\n", cfg.Listen)
	}
	return platform.LaunchClaude(cfg.ProxyURL(), *app)
}

func runStatus([]string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.SetFlags(0)
	fmt.Printf("server:          %s\n", describeActive(cfg))
	fmt.Printf("local proxy:     %s %s\n", cfg.ProxyURL(), proxy.Identify(cfg))
	fmt.Printf("firewall rules:  %s\n", firewall.Status())
	if err := proxy.ConnectVia(cfg.Listen, probeHost+":443"); err != nil {
		fmt.Printf("via proxy:       FAIL (%v)\n", err)
	} else {
		fmt.Printf("via proxy:       ok (%s reachable through the proxy)\n", probeHost)
	}
	v4 := firewall.DirectProbe("tcp4", probeHost)
	v6 := firewall.DirectProbe("tcp6", probeHost)
	fmt.Printf("direct IPv4:     %s\n", v4)
	fmt.Printf("direct IPv6:     %s\n", v6)
	switch {
	case !firewall.IsOpen(v4) && !firewall.IsOpen(v6):
	case cfg.AllowTunnels:
		fmt.Println("\nDirect access is open. Fine if the interface above is a VPN tunnel (--allow-tunnels lets those through).")
	default:
		fmt.Println("\nKILL SWITCH IS NOT ACTIVE: Claude can bypass the proxy. Run `claudeguard enable`.")
	}
	return nil
}

// describeActive names the active server, without the proxy password.
func describeActive(cfg config.Config) string {
	p, ok := cfg.Find(cfg.Active)
	if !ok {
		return "none: pick one in `claudeguard ui`"
	}
	target := p.Target
	if up, err := config.ParseUpstream(target); err == nil {
		target = up.String()
	}
	return cfg.Active + " (" + p.Kind + " " + target + ")"
}
