// Package cli is the command line of claudeguard: it parses the arguments
// and wires the other packages together.
package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/platform"
	"github.com/VitalyDubovets/claudeguard/internal/tray"
	"github.com/VitalyDubovets/claudeguard/internal/version"
)

const usageText = `claudeguard %s: proxy + kill switch for Claude

Usage:
  claudeguard install [--ssh HOST | --upstream URL] [--listen ADDR] [--allow-tunnels]
                      [--extra-block CIDRS] [--no-settings] [--no-launcher] [--no-tray]
      Set everything up. Asks for the admin password once (firewall rules).
  claudeguard app                Install if needed, then open the settings window
                                 (what a double click on the app does)
  claudeguard ui [--browser]     Open the settings window (servers, kill switch)
  claudeguard tray               Menu bar / tray icon: status and server switch
  claudeguard uninstall          Remove everything and put Claude Code settings back
  claudeguard status             Check that the proxy works and direct access is blocked
  claudeguard launch [--app P]   (Re)start the Claude desktop app through the proxy
  claudeguard serve [--detach]   Run the local proxy and settings page
  claudeguard enable / disable   Turn only the firewall kill switch on or off (admin)

Servers are kept in the config and switched in the settings page. --ssh HOST
adds an SSH server (claudeguard keeps "ssh -N -D" to it running); --upstream
adds socks5://[user:pass@]host:port or http://[user:pass@]host:port.
The local proxy listens on 127.0.0.1:41080 unless --listen says otherwise.
`

func usage() { fmt.Fprintf(os.Stderr, usageText, version.Version) }

// commands maps a subcommand to what runs it. "window", "system-install"
// and "system-uninstall" are internal: claudeguard starts them itself, in a
// process of their own or with admin rights.
var commands = map[string]func(args []string) error{
	"install":          runInstall,
	"uninstall":        runUninstall,
	"app":              runApp,
	"status":           runStatus,
	"launch":           runLaunch,
	"ui":               runUI,
	"window":           runWindow,
	"tray":             tray.Run,
	"serve":            runServe,
	"enable":           runEnable,
	"disable":          runDisable,
	"system-install":   runSystemInstall,
	"system-uninstall": runSystemUninstall,
}

// Main runs claudeguard with the given arguments (without the program name)
// and returns the exit code.
func Main(args []string) int {
	if len(args) == 0 {
		// A double click on the app or the installer passes no arguments.
		if !platform.LaunchedFromGUI() {
			usage()
			return 2
		}
		args = []string{"app"}
	}
	switch args[0] {
	case "version", "--version":
		fmt.Println(version.Version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	}
	run, ok := commands[args[0]]
	if !ok {
		usage()
		return 2
	}
	if err := run(args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "claudeguard:", err)
		return 1
	}
	return 0
}

// firewallOptions is the kill switch as the config last saved it.
func firewallOptions(cfg config.Config) firewall.Options {
	return firewall.Options{AllowTunnels: cfg.AllowTunnels, Extra: cfg.ExtraBlock}
}

// firewallFlags adds the kill switch flags to fs, with o as the defaults.
// Call the returned func after fs.Parse to get what the user asked for.
func firewallFlags(fs *flag.FlagSet, o firewall.Options) func() (firewall.Options, error) {
	fs.BoolVar(&o.AllowTunnels, "allow-tunnels", o.AllowTunnels, "also allow Anthropic traffic through VPN tunnel interfaces")
	extra := fs.String("extra-block", strings.Join(o.Extra, ","), "extra CIDRs to block, comma separated")
	return func() (firewall.Options, error) {
		var err error
		o.Extra, err = firewall.ParseCIDRList(*extra)
		return o, err
	}
}

func parseFirewallArgs(name string, args []string) (firewall.Options, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	options := firewallFlags(fs, firewall.Options{})
	if err := fs.Parse(args); err != nil {
		return firewall.Options{}, err
	}
	return options()
}
