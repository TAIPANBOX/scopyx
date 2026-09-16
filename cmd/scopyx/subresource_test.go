package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/cdp"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/mcp"
	"github.com/TAIPANBOX/scopyx/internal/policy"
	"github.com/TAIPANBOX/scopyx/internal/record"
)

// A page is a document plus forty requests the caller never named, and the
// chromium backend is the one backend that decides each of them. Until
// 2026-09-16 it decided them against the address rules and an allow-set the
// policy plane never sends, so a subresource on an approved page reached any
// public host at all while the record said per_request. These tests hold the
// other half: every subresource host is a question to the policy plane, asked
// through the fetch's own memo, and a question that cannot be asked is a
// refusal.

// hostPDP is a policy plane that answers per host and remembers what it was
// asked, because the assertion that matters is not only the verdict but that
// the question reached the plane at all.
type hostPDP struct {
	srv  *httptest.Server
	deny map[string]bool

	mu    sync.Mutex
	asked []string
}

func newHostPDP(t *testing.T, deny ...string) *hostPDP {
	t.Helper()
	p := &hostPDP{deny: map[string]bool{}}
	for _, d := range deny {
		p.deny[d] = true
	}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Domains []string `json:"domains"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		host := ""
		if len(req.Domains) > 0 {
			host = req.Domains[0]
		}
		p.mu.Lock()
		p.asked = append(p.asked, host)
		p.mu.Unlock()
		decision := "allow"
		if p.deny[host] {
			decision = "deny"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision": decision, "policy_version": "v1", "reason": "fixture policy on " + host,
		})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *hostPDP) client() *policy.Client { return policy.New(p.srv.URL, "k", time.Second) }

func (p *hostPDP) questions() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.asked...)
}

// fixedResolver answers with a synthetic public address per host, so a name
// that exists only in the test still goes through every address rule.
type fixedResolver map[string]string

func (r fixedResolver) Resolve(_ context.Context, host string) ([]netip.Addr, error) {
	a, ok := r[host]
	if !ok {
		return nil, errors.New("no such host in this fixture: " + host)
	}
	return []netip.Addr{netip.MustParseAddr(a)}, nil
}

var subresourceHosts = fixedResolver{
	"doc.example":     "203.0.113.1",
	"cdn.example":     "203.0.113.2",
	"tracker.example": "203.0.113.3",
}

// governedContext is what internal/fetch puts on the context before the
// backend is called: the memo for one fetch by one caller.
func governedContext(pdp *policy.Client) context.Context {
	memo := policy.NewMemo(pdp, "agent://acme.example/support-bot", "run-sub", "browse")
	return policy.WithMemo(context.Background(), memo)
}

func TestASubresourceHostThePolicyPlaneRefusesIsDenied(t *testing.T) {
	pdp := newHostPDP(t, "tracker.example")
	decideSub := subresourceDecider(subresourceHosts)

	_, d := decideSub(governedContext(pdp.client()), "https://tracker.example/t.css")
	if d.Verdict != decide.DenyPolicy {
		t.Fatalf("a subresource host the policy plane refuses was %s (%q), want deny_policy",
			d.Verdict, d.Reason)
	}
	if q := pdp.questions(); len(q) != 1 || q[0] != "tracker.example" {
		t.Fatalf("the policy plane was asked %v, want exactly [tracker.example]: a subresource "+
			"is a destination the caller never named, and it is decided by asking, not by assuming", q)
	}
}

func TestASubresourceThePolicyPlaneAllowsIsAllowedWithItsCheckedAddresses(t *testing.T) {
	pdp := newHostPDP(t)
	decideSub := subresourceDecider(subresourceHosts)

	addrs, d := decideSub(governedContext(pdp.client()), "https://cdn.example/app.js")
	if d.Verdict != decide.Allow {
		t.Fatalf("an allowed subresource was %s (%q)", d.Verdict, d.Reason)
	}
	if len(addrs) != 1 || addrs[0].String() != "203.0.113.2" {
		t.Fatalf("the decider must hand back the addresses it decided about, so the proxy dials "+
			"what was checked and never resolves the name again: got %v", addrs)
	}
}

func TestASubresourceIsDecidedOncePerHostNotOncePerRequest(t *testing.T) {
	pdp := newHostPDP(t)
	decideSub := subresourceDecider(subresourceHosts)
	ctx := governedContext(pdp.client())

	for _, u := range []string{
		"https://cdn.example/a.js", "https://cdn.example/b.css", "https://cdn.example/c.png",
	} {
		if _, d := decideSub(ctx, u); d.Verdict != decide.Allow {
			t.Fatalf("%s was %s (%q)", u, d.Verdict, d.Reason)
		}
	}
	if q := pdp.questions(); len(q) != 1 {
		t.Fatalf("three requests on one host asked the policy plane %d times (%v); the memo "+
			"exists so a forty-subresource page is not forty-one round trips", len(q), q)
	}
}

func TestAnUnreachablePolicyPlaneRefusesASubresourceAndSaysWhichRefusalItWas(t *testing.T) {
	pdp := newHostPDP(t)
	client := pdp.client()
	pdp.srv.Close() // the plane goes away before the page loads
	decideSub := subresourceDecider(subresourceHosts)

	_, d := decideSub(governedContext(client), "https://cdn.example/app.js")
	if d.Verdict != decide.DenyPolicyUnreachable {
		t.Fatalf("with the policy plane gone a subresource was %s (%q); this plane fails "+
			"closed and says it could not ask, never that a policy refused", d.Verdict, d.Reason)
	}
}

func TestASubresourceAskedOutsideAGovernedFetchIsRefused(t *testing.T) {
	decideSub := subresourceDecider(subresourceHosts)

	_, d := decideSub(context.Background(), "https://cdn.example/app.js")
	if d.Verdict != decide.DenyPolicyUnreachable {
		t.Fatalf("a subresource decided on a context no fetch prepared was %s (%q); with no "+
			"memo there is nobody to ask, and nobody to ask is a refusal", d.Verdict, d.Reason)
	}
	if !strings.Contains(d.Reason, "memo") {
		t.Fatalf("the reason should name what was missing: %q", d.Reason)
	}
}

// The whole path, with a real browser: the MCP surface's fetcher, the fetch
// ordering, the chromium backend's proxy and interception, and the decider
// main.go wires in. The assertion is on the server that would have served the
// refused subresource, because an outcome assertion passes equally well when
// the request happened and the answer was thrown away.
func TestASubresourceThePolicyPlaneRefusesNeverReachesItsServer(t *testing.T) {
	exe, ok := cdp.Find()
	if !ok {
		if os.Getenv("SCOPYX_REQUIRE_CHROMIUM") != "" {
			t.Fatal("no browser found and SCOPYX_REQUIRE_CHROMIUM is set")
		}
		t.Skip("no chromium or chrome on this machine; set SCOPYX_CHROMIUM to point at one")
	}

	var allowedHits, deniedHits atomic.Int64
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
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head>` +
			`<link rel="stylesheet" href="http://cdn.example/a.css">` +
			`<link rel="stylesheet" href="http://tracker.example/t.css">` +
			`</head><body><h1>the document itself</h1></body></html>`))
	}))
	defer doc.Close()
	behind := map[string]string{
		"203.0.113.1": strings.TrimPrefix(doc.URL, "http://"),
		"203.0.113.2": strings.TrimPrefix(allowed.URL, "http://"),
		"203.0.113.3": strings.TrimPrefix(denied.URL, "http://"),
	}

	ch, err := backend.NewChromium(exe, 1<<20, 40*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ch.NoSandbox = os.Getenv("SCOPYX_CHROMIUM_NO_SANDBOX") != ""
	// The decider main.go wires, with the fixture's resolver in place of the
	// system one; the dial sends each checked synthetic address to its fixture.
	ch.Decide = subresourceDecider(subresourceHosts)
	ch.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		real, ok := behind[host]
		if !ok {
			return nil, errors.New("no fixture server behind " + addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, real)
	}

	pdp := newHostPDP(t, "tracker.example")
	journalPath := filepath.Join(t.TempDir(), "events.ndjson")
	j, err := record.Open(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()

	g := &governed{
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		backend:  ch,
		pdp:      pdp.client(),
		journal:  j,
		limits:   decide.Limits{MaxRedirects: 5, MaxBodyBytes: 1 << 20},
		cap:      newHourlyCap(100),
		resolver: subresourceHosts,
	}
	ans, err := g.Fetch(context.Background(), mcp.Call{
		Tool: "browse", URL: "http://doc.example/page", Extract: "html",
		AgentID: "agent://acme.example/support-bot", RunID: "run-e2e",
	})
	if err != nil {
		t.Fatalf("the approved page must render: %v", err)
	}
	if allowedHits.Load() == 0 {
		t.Error("the subresource the policy plane allows was never fetched")
	}
	if n := deniedHits.Load(); n != 0 {
		t.Errorf("the subresource the policy plane refuses reached its server %d time(s)", n)
	}
	// At least one, not exactly one: the browser's own background traffic also
	// reaches the floor, is refused there (no fixture address, and no policy
	// answer for a host the page never named), and is rightly counted too.
	if b := ans.Fidelity.SubresourcesBlockedByPolicy; b == nil || *b < 1 {
		t.Errorf("the record must count the refused subresource, got blocked=%v", b)
	}
	if !strings.Contains(string(ans.Body), "the document itself") {
		t.Errorf("the rendered body is missing the document: %.200q", ans.Body)
	}
	var sawTracker bool
	for _, q := range pdp.questions() {
		if q == "tracker.example" {
			sawTracker = true
		}
	}
	if !sawTracker {
		t.Errorf("the policy plane was never asked about tracker.example; it was asked %v", pdp.questions())
	}
}
