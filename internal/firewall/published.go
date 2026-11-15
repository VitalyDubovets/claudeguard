package firewall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PublishedURL is the page Anthropic lists its addresses on, as Markdown.
const PublishedURL = "https://platform.claude.com/docs/en/api/ip-addresses.md"

var cidrRe = regexp.MustCompile(`[0-9a-fA-F:.]+/\d{1,3}`)

// ParsePublished picks the networks out of that page. The addresses under
// "Phased out" are no longer Anthropic's and are left out. A network wider
// than /16 (/32 for IPv6) is not believed: the page is somebody else's, and
// a slip there must not suggest blocking half the internet.
func ParsePublished(page string) []netip.Prefix {
	if i := strings.Index(page, "Phased out"); i >= 0 {
		page = page[:i]
	}
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, m := range cidrRe.FindAllString(page, -1) {
		p, err := netip.ParsePrefix(m)
		if err != nil {
			continue
		}
		p = p.Masked()
		narrowest := 16
		if p.Addr().Is6() {
			narrowest = 32
		}
		if p.Bits() < narrowest || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// uncovered lists the published networks that the rules for o leave open.
func uncovered(published []netip.Prefix, o Options) []string {
	var have []netip.Prefix
	for _, r := range o.ranges() {
		if p, err := netip.ParsePrefix(r); err == nil {
			have = append(have, p.Masked())
		} else if a, err := netip.ParseAddr(r); err == nil {
			have = append(have, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	missing := []string{}
	for _, p := range published {
		covered := false
		for _, h := range have {
			if h.Bits() <= p.Bits() && h.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			missing = append(missing, p.String())
		}
	}
	return missing
}

// RangeReport says how the kill switch stands against the published list.
type RangeReport struct {
	// CheckedAt is the last time the page was read; nil if it never was.
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Missing are published networks the rules do not block.
	Missing []string `json:"missing"`
	// Error is why the latest attempt failed, if it did.
	Error string `json:"error,omitempty"`
}

// Published is Anthropic's address list as last read from its page. The
// ranges compiled into the rules are a copy made at release time; this is
// what notices that Anthropic has added to them since.
type Published struct {
	mu   sync.Mutex
	at   time.Time
	nets []netip.Prefix
	err  string
}

// Refresh reads the page through client. A failed read keeps the last good
// list.
func (p *Published) Refresh(ctx context.Context, client *http.Client) error {
	nets, err := fetchPublished(ctx, client)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.err = err.Error()
		return err
	}
	p.nets, p.at, p.err = nets, time.Now(), ""
	return nil
}

func fetchPublished(ctx context.Context, client *http.Client) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, PublishedURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", PublishedURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	nets := ParsePublished(string(body))
	if len(nets) == 0 {
		return nil, errors.New("no addresses found on Anthropic's page: its format may have changed")
	}
	return nets, nil
}

// Report compares the last list read with the rules for o. A nil Published
// reports nothing.
func (p *Published) Report(o Options) RangeReport {
	r := RangeReport{Missing: []string{}}
	if p == nil {
		return r
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r.Error = p.err
	if !p.at.IsZero() {
		at := p.at
		r.CheckedAt = &at
		r.Missing = uncovered(p.nets, o)
	}
	return r
}

// Watch reads the page soon after start and then once a day; a failed read
// is tried again sooner. It never returns.
func (p *Published) Watch(client *http.Client) {
	const daily, retry = 24 * time.Hour, 10 * time.Minute
	wait := 30 * time.Second
	failing := false
	for {
		time.Sleep(wait)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err := p.Refresh(ctx, client)
		cancel()
		if err != nil {
			if !failing {
				log.Printf("address list: could not read Anthropic's page: %v", err)
			}
			failing, wait = true, retry
			continue
		}
		failing, wait = false, daily
		if missing := p.Report(Options{}).Missing; len(missing) > 0 {
			log.Printf("address list: Anthropic publishes networks the built-in list lacks: %s", strings.Join(missing, ", "))
		}
	}
}
