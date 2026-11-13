package tunnel

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SSHConfigHosts lists concrete Host aliases from ~/.ssh/config (and files
// it includes), for the "add server" suggestions in the UI.
func SSHConfigHosts() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		f, err := os.Open(path)
		if err != nil || depth > 3 {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			switch strings.ToLower(fields[0]) {
			case "host":
				for _, h := range fields[1:] {
					if !strings.ContainsAny(h, "*?!") {
						seen[h] = true
					}
				}
			case "include":
				for _, inc := range fields[1:] {
					if strings.HasPrefix(inc, "~/") {
						inc = filepath.Join(home, inc[2:])
					} else if !filepath.IsAbs(inc) {
						inc = filepath.Join(home, ".ssh", inc)
					}
					matches, _ := filepath.Glob(inc)
					for _, m := range matches {
						walk(m, depth+1)
					}
				}
			}
		}
	}
	walk(filepath.Join(home, ".ssh", "config"), 0)
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
