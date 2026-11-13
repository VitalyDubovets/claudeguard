package config

import (
	"testing"
)

func TestParseUpstream(t *testing.T) {
	for _, s := range []string{"socks5://127.0.0.1:1081", "socks5h://h:1", "http://user:pw@proxy:3128"} {
		if _, err := ParseUpstream(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"https://proxy:443", "socks5://nohost", "127.0.0.1:1081"} {
		if _, err := ParseUpstream(s); err == nil {
			t.Errorf("%s: want error", s)
		}
	}
}

func TestNormalizeMigratesLegacyConfig(t *testing.T) {
	c := Config{SSHHost: "my-server"}
	c.Normalize()
	if len(c.Profiles) != 1 || c.Active != "my-server" || c.Profiles[0].Kind != "ssh" || c.SSHHost != "" {
		t.Fatalf("%+v", c)
	}
	if c.Listen != defaultListen || len(c.Token) != 32 {
		t.Fatalf("defaults: %+v", c)
	}
	c = Config{Upstream: "socks5://u:p@10.0.0.1:1080"}
	c.Normalize()
	if c.Active != "10.0.0.1" || c.Profiles[0].Kind != "socks5" {
		t.Fatalf("%+v", c)
	}
	c = Config{Active: "gone", Profiles: []Profile{{Name: "a", Kind: "ssh", Target: "a"}}}
	c.Normalize()
	if c.Active != "" {
		t.Fatal("unknown active profile must be cleared")
	}
}

func TestProfileValidate(t *testing.T) {
	good := []Profile{
		{Name: "p", Kind: "ssh", Target: "my-server"},
		{Name: "p", Kind: "ssh", Target: "root@1.2.3.4"},
		{Name: "p", Kind: "socks5", Target: "socks5://127.0.0.1:1080"},
		{Name: "p", Kind: "http", Target: "http://u:p@proxy:3128"},
	}
	for _, p := range good {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []Profile{
		{Name: "", Kind: "ssh", Target: "x"},
		{Name: "p", Kind: "ssh", Target: "-oProxyCommand=evil"},
		{Name: "p", Kind: "ssh", Target: "host; rm -rf ~"},
		{Name: "p", Kind: "socks5", Target: "http://proxy:3128"},
		{Name: "p", Kind: "http", Target: "proxy"},
		{Name: "p", Kind: "ftp", Target: "ftp://x:1"},
	}
	for _, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("%+v: want error", p)
		}
	}
}

func TestUpsertRemove(t *testing.T) {
	var c Config
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Upsert("", Profile{Name: "a", Kind: "ssh", Target: "a"}))
	must(c.Upsert("", Profile{Name: "b", Kind: "ssh", Target: "b"}))
	c.Active = "a"
	if err := c.Upsert("a", Profile{Name: "b", Kind: "ssh", Target: "a"}); err == nil {
		t.Fatal("renaming onto an existing name must fail")
	}
	must(c.Upsert("a", Profile{Name: "a2", Kind: "ssh", Target: "a"}))
	if c.Active != "a2" || len(c.Profiles) != 2 {
		t.Fatalf("rename must follow the active profile: %+v", c)
	}
	c.Remove("a2")
	if c.Active != "" || len(c.Profiles) != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestSSHTargetCharset(t *testing.T) {
	for target, ok := range map[string]bool{
		"my-server": true, "root@1.2.3.4": true, "my_host.example.com": true, "[2001:db8::1]": true,
		"*.example.com": false, "victim.example,x.attacker.net": false, "!host": false, "-oProxyCommand=x": false, "a b": false, "": false,
	} {
		err := Profile{Name: "n", Kind: "ssh", Target: target}.Validate()
		if (err == nil) != ok {
			t.Errorf("%q: %v", target, err)
		}
	}
}
