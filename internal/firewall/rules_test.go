package firewall

import (
	"strings"
	"testing"
)

func TestRenderPFRules(t *testing.T) {
	got := renderPFRules(Options{Extra: []string{"1.2.3.4"}}.ranges(), []string{"utun4"})
	pass := strings.Index(got, "pass out quick on utun4 to <claudeguard> keep state (if-bound)")
	block := strings.Index(got, "block return out quick to <claudeguard>")
	if pass < 0 || block < 0 || pass > block {
		t.Fatalf("tunnel pass must precede the block rule:\n%s", got)
	}
	for _, r := range append(anthropicRanges, "1.2.3.4") {
		if !strings.Contains(got, r) {
			t.Errorf("missing %s", r)
		}
	}
}

func TestWindowsScript(t *testing.T) {
	s := windowsFirewallScript(Options{})
	if !strings.Contains(s, "-Action Block") || !strings.Contains(s, "'2607:6bc0::/48'") || strings.Contains(s, "InterfaceAlias") {
		t.Fatalf("unexpected script:\n%s", s)
	}
	if s := windowsFirewallScript(Options{AllowTunnels: true}); !strings.Contains(s, "-InterfaceAlias $phys") || !strings.Contains(s, "Get-NetAdapter -Physical") {
		t.Fatalf("tunnel mode must limit the rule to physical adapters:\n%s", s)
	}
}

func TestParseCIDRList(t *testing.T) {
	got, err := ParseCIDRList("1.2.3.0/24, 2001:db8::1")
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseCIDRList("1.2.3.0/24; rm -rf"); err == nil {
		t.Fatal("want error")
	}
}

func TestCIDRListIsNormalized(t *testing.T) {
	got, err := ParseCIDRList("10.1.2.3/8, ::ffff:1.2.3.4, 2001:DB8::/32")
	if err != nil || strings.Join(got, " ") != "10.0.0.0/8 1.2.3.4 2001:db8::/32" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"1.2.3.4/024", "fe80::1%en0", "1.2.3.4;x"} {
		if _, err := ParseCIDRList(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
