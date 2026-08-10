package backend

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/cdp"
	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// browserOrSkip finds one, and says WHY it skipped in a way a reader can act on.
//
// A skipped test and a passing test look identical in a summary line, which is
// the silent-zero fault this estate keeps finding, wearing a `go test` badge.
// SCOPYX_REQUIRE_CHROMIUM turns the skip into a failure, and CI sets it, so "no
// browser on the runner" cannot quietly become "the rendering backend is
// untested".
func browserOrSkip(t *testing.T) string {
	t.Helper()
	exe, ok := cdp.Find()
	if ok {
		return exe
	}
	msg := "no chromium or chrome on this machine, so the rendering backend was NOT exercised. " +
		"Install one, or set SCOPYX_CHROMIUM."
	if os.Getenv("SCOPYX_REQUIRE_CHROMIUM") != "" {
		t.Fatal(msg + " SCOPYX_REQUIRE_CHROMIUM is set, so this is a failure rather than a skip.")
	}
	t.Skip(msg)
	return ""
}

// fixture wires a Chromium backend whose DECISIONS are real and whose sockets
// land on local servers.
//
// Each fixture hostname resolves to its own documentation address, and the dial
// maps that address to the server standing in for it. Everything above the
// socket runs unmodified: the proxy asks the decider, the decider is
// `decide.Subresource` with a real allow-set, and the address it picks is the
// one the resolver produced.
//
// It exists because the fixtures live on loopback, and loopback is an address
// `decide` refuses. The alternative would be weakening the address rules for
// tests, which is the wrong thing to weaken.
type fixture struct {
	addrOf   map[string]string // hostname -> synthetic address
	serverAt map[string]string // synthetic address -> real host:port
}

func newFixture() *fixture {
	return &fixture{addrOf: map[string]string{}, serverAt: map[string]string{}}
}

func (f *fixture) add(host string, srv *httptest.Server, n int) {
	addr := "203.0.113." + string(rune('0'+n))
	f.addrOf[host] = addr
	f.serverAt[addr] = strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://")
}

func (f *fixture) apply(c *Chromium, allowDomains []string) {
	c.Resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		a, ok := f.addrOf[host]
		if !ok {
			return nil, errors.New("no fixture address for " + host)
		}
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	c.Allow = func(_ context.Context, rawURL string, addrs []netip.Addr) decide.Decision {
		return decide.Subresource(rawURL, addrs, allowDomains)
	}
	c.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		real, ok := f.serverAt[host]
		if !ok {
			return nil, errors.New("no fixture server behind " + addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, real)
	}
}

func newChromium(t *testing.T) *Chromium {
	t.Helper()
	c, err := NewChromium(browserOrSkip(t), 1<<20, 40*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The property the backend exists for: a subresource the allow-set refuses is
// not fetched, and the assertion is on the SERVER that would have served it.
//
// An outcome assertion would pass equally well if the request happened and the
// answer were discarded, which is the difference between governing egress and
// filtering a report about it.
func TestASubresourceTheAllowSetRefusesNeverReachesItsServer(t *testing.T) {
	c := newChromium(t)

	var docHits, allowedHits, deniedHits atomic.Int64
	css := func(hits *atomic.Int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte("body{color:#000}"))
		}))
	}
	allowed := css(&allowedHits)
	defer allowed.Close()
	denied := css(&deniedHits)
	defer denied.Close()
	doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		docHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head>` +
			`<link rel="stylesheet" href="http://allowed.example/a.css">` +
			`<link rel="stylesheet" href="http://tracker.example/t.css">` +
			`</head><body><h1>the document itself</h1></body></html>`))
	}))
	defer doc.Close()

	f := newFixture()
	f.add("doc.example", doc, 1)
	f.add("allowed.example", allowed, 2)
	f.add("tracker.example", denied, 3)
	f.apply(c, []string{"doc.example", "allowed.example"})

	res, err := c.Fetch(context.Background(), Request{URL: "http://doc.example/page"})
	if err != nil {
		t.Fatalf("the allowed page must render: %v", err)
	}

	if docHits.Load() == 0 {
		t.Error("the document itself was never fetched")
	}
	if allowedHits.Load() == 0 {
		t.Error("an allowed subresource must be fetched")
	}
	if n := deniedHits.Load(); n != 0 {
		t.Errorf("the refused subresource's server was reached %d times", n)
	}
	if !strings.Contains(string(res.Body), "the document itself") {
		t.Errorf("the rendered body is missing the document: %.200q", res.Body)
	}

	if res.Subresources == nil {
		t.Fatal("this backend can report subresources, so the list must never be nil")
	}
	var blocked int
	for _, s := range res.Subresources {
		if s.Blocked {
			blocked++
		}
	}
	if blocked == 0 {
		t.Errorf("a refused subresource must be COUNTED and not merely prevented: %+v", res.Subresources)
	}
}

// The reason this backend exists at all: it runs the page's own JavaScript, so
// a document assembled in the browser arrives assembled rather than as the
// shell that assembles it.
func TestItRendersRatherThanReturningTheShell(t *testing.T) {
	c := newChromium(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><div id="x"></div>` +
			`<script>document.getElementById("x").textContent="assembled in the browser"</script>` +
			`</body></html>`))
	}))
	defer srv.Close()

	f := newFixture()
	f.add("app.example", srv, 1)
	f.apply(c, nil)

	res, err := c.Fetch(context.Background(), Request{URL: "http://app.example/"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Body), "assembled in the browser") {
		t.Errorf("the page's own script did not run: %.300q", res.Body)
	}
	if c.Enforcement() != decide.EnforcementPerRequest {
		t.Errorf("enforcement = %q, want per_request", c.Enforcement())
	}
}

// A redirect on the navigation is reported UP rather than followed. Chrome
// would follow it happily, which is the oldest allowlist bypass there is, and
// the hop belongs to internal/fetch where it is resolved and decided again.
func TestANavigationRedirectIsReportedAndNotFollowed(t *testing.T) {
	c := newChromium(t)

	var elsewhere atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		_, _ = w.Write([]byte("<html><body>the second destination</body></html>"))
	}))
	defer target.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://second.example/collect", http.StatusFound)
	}))
	defer first.Close()

	f := newFixture()
	f.add("first.example", first, 1)
	f.add("second.example", target, 2)
	f.apply(c, nil)

	res, err := c.Fetch(context.Background(), Request{URL: "http://first.example/notice"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.RedirectTo, "second.example") {
		t.Errorf("RedirectTo = %q, want the hop reported for re-decision", res.RedirectTo)
	}
	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the redirect target was reached %d times by the browser", n)
	}
}

// A missing browser is refused at construction, with a message about the
// browser. A backend that started happily and failed every fetch would report a
// network problem to somebody whose problem is that they never installed one.
func TestAMissingBrowserIsRefusedAtConstructionAndSaysSo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("SCOPYX_CHROMIUM", "")
	if _, ok := cdp.Find(); ok {
		t.Skip("a browser was found through a path this test cannot clear")
	}
	_, err := NewChromium("", 1<<20, time.Second)
	if err == nil {
		t.Fatal("a missing browser must be refused")
	}
	if !errors.Is(err, ErrNoBrowser) {
		t.Errorf("the error must be typed as a missing browser, got %v", err)
	}
	if !strings.Contains(err.Error(), "SCOPYX_BACKEND=passthrough") {
		t.Errorf("the message must name the way out, got %q", err)
	}
}

// It will not fetch without the decision function handed in. A backend that
// decided for itself is invariant 1 broken from the inside, and the failure
// must be loud rather than a page fetched under nobody's policy.
func TestItRefusesToFetchWithoutADeciderRatherThanDecidingForItself(t *testing.T) {
	c := &Chromium{Exe: "/nonexistent", MaxBodyBytes: 1 << 20, Timeout: time.Second}
	_, err := c.Fetch(context.Background(), Request{URL: "http://example.com/"})
	if err == nil {
		t.Fatal("a backend with no decider must not fetch")
	}
	if !strings.Contains(err.Error(), "deciding for itself") {
		t.Errorf("the refusal must say why, got %q", err)
	}
}

// A debugging PORT is an unauthenticated remote control channel for the browser
// this plane fetches with. The pipe is the whole reason internal/cdp exists.
func TestTheLaunchRefusesADebuggingPort(t *testing.T) {
	_, err := cdp.Launch(context.Background(), "/nonexistent", "--remote-debugging-port=9222")
	if err == nil {
		t.Fatal("a debugging port must be refused")
	}
	if !strings.Contains(err.Error(), "unauthenticated remote control") {
		t.Errorf("the refusal must say why a port differs from a pipe, got %q", err)
	}
}

// Chrome bypasses a configured proxy for loopback by default, which on a
// developer's machine is every other service they run. The launch closes it,
// and this reads the flags rather than trusting the comment beside them.
func TestTheLaunchClosesChromesOwnProxyBypass(t *testing.T) {
	joined := strings.Join(chromeArgs("/tmp/profile", "127.0.0.1:1234"), " ")
	for _, want := range []string{
		"--proxy-server=http://127.0.0.1:1234",
		"--proxy-bypass-list=<-loopback>",
		"--user-data-dir=/tmp/profile",
		"--headless=new",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the launch is missing %s", want)
		}
	}
}

// Invariant 4, and here it is not theoretical: a warm browser is the obvious
// optimisation, it would pass every other test, and it would join two tenants'
// pages in one storage partition.
func TestTheProfileIsFreshPerFetchAndRemovedAfter(t *testing.T) {
	c := newChromium(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()
	f := newFixture()
	f.add("x.example", srv, 1)
	f.apply(c, nil)

	before := profileDirs(t)
	if _, err := c.Fetch(context.Background(), Request{URL: "http://x.example/"}); err != nil {
		t.Fatal(err)
	}
	if after := profileDirs(t); after > before {
		t.Errorf("a profile directory outlived the fetch: %d before, %d after", before, after)
	}
}

func profileDirs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "scopyx-profile-") {
			n++
		}
	}
	return n
}
