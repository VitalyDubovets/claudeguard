package firewall

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// Enable loads the rules that block direct traffic to Anthropic. Needs
// admin rights.
func Enable(o Options) error {
	out, err := sysutil.PowerShell(windowsFirewallScript(o))
	fmt.Print(out)
	if err != nil {
		return err
	}
	fmt.Println("   Windows Firewall rule group", winRuleGroup, "applied (persists across reboots)")
	return nil
}

// Disable removes the rules. Needs admin rights.
func Disable() error {
	_, err := sysutil.PowerShell(windowsRemoveScript())
	return err
}

// Status says in words whether the kill switch is in place.
func Status() string {
	out, err := sysutil.PowerShell(fmt.Sprintf("(Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True' | Measure-Object).Count", PSQuote(winRuleGroup)))
	if err != nil {
		return "unknown"
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(out)); n > 0 {
		return "active"
	}
	return "NOT installed"
}
