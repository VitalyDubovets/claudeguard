package firewall

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

// The page as Anthropic serves it, cut down to what matters.
const publishedPage = `## Inbound IP addresses
### IPv4
` + "`160.79.104.0/23`" + `

` + "`153.61.224.0/22`" + `
### IPv6
` + "`2607:6bc0::/48`" + `
## Outbound IP addresses
` + "`160.79.104.0/21`" + `

` + "`153.61.208.0/20`" + `
### Phased out IP addresses
34.162.46.92/32
`

func TestBuiltInRangesCoverPublished(t *testing.T) {
	nets := ParsePublished(publishedPage)
	if len(nets) != 5 {
		t.Fatalf("parsed %v", nets)
	}
	if missing := uncovered(nets, Options{}); len(missing) != 0 {
		t.Fatalf("built-in list leaves open: %v", missing)
	}
}

func TestUncovered(t *testing.T) {
	page := publishedPage[:len(publishedPage)-len("### Phased out IP addresses\n34.162.46.92/32\n")] +
		"`198.51.100.0/24`\n`2001:db8:1::/48`\n`0.0.0.0/0`\n`10.0.0.0/8`\n"
	nets := ParsePublished(page)
	got := uncovered(nets, Options{})
	if want := []string{"198.51.100.0/24", "2001:db8:1::/48"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
	// A wider extra network, or the address itself, covers it.
	got = uncovered(nets, Options{Extra: []string{"198.51.0.0/16", "2001:db8:1::/48"}})
	if len(got) != 0 {
		t.Fatalf("still missing with extras: %v", got)
	}
	// A narrower one does not.
	if got = uncovered(nets, Options{Extra: []string{"198.51.100.0/25", "2001:db8:1::/48"}}); len(got) != 1 {
		t.Fatalf("a narrower network counted as cover: %v", got)
	}
}

func TestPublishedRefresh(t *testing.T) {
	page, status := publishedPage+"", http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()
	// Every request lands on the test server, whatever host it names.
	client := srv.Client()
	target, _ := url.Parse(srv.URL)
	client.Transport = rewrite{client.Transport, target.Host}

	var p Published
	if r := p.Report(Options{}); r.CheckedAt != nil || len(r.Missing) != 0 {
		t.Fatalf("report before any read: %+v", r)
	}
	if err := p.Refresh(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if r := p.Report(Options{}); r.CheckedAt == nil || len(r.Missing) != 0 || r.Error != "" {
		t.Fatalf("report after a clean read: %+v", r)
	}

	page = "`203.0.113.0/24`\n"
	if err := p.Refresh(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if r := p.Report(Options{}); !reflect.DeepEqual(r.Missing, []string{"203.0.113.0/24"}) {
		t.Fatalf("new network not reported: %+v", r)
	}

	// A broken page keeps the last good list and says why.
	page = "nothing here"
	if err := p.Refresh(context.Background(), client); err == nil {
		t.Fatal("empty page accepted")
	}
	status = http.StatusBadGateway
	if err := p.Refresh(context.Background(), client); err == nil {
		t.Fatal("502 accepted")
	}
	if r := p.Report(Options{}); r.Error == "" || !reflect.DeepEqual(r.Missing, []string{"203.0.113.0/24"}) {
		t.Fatalf("after a failed read: %+v", r)
	}
	var none *Published
	if r := none.Report(Options{}); r.Missing == nil {
		t.Fatal("nil Published must report an empty list")
	}
}

type rewrite struct {
	next http.RoundTripper
	host string
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = r.host
	return r.next.RoundTrip(req)
}
