package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/cdp"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/mcp"
	"github.com/TAIPANBOX/scopyx/internal/record"
)

// Finding 3 (Fable, 2026-09-16). An over-bound screenshot is refused AFTER
// the page and every allowed subresource already left through the proxy, and
// the refusal came back as a plain error, not a *fetch.Refusal: governed.Fetch
// in main.go journalled Blocked only for a *fetch.Refusal and Fetch only on
// success, so the egress that had already happened left no trail at all. This
// test holds the fix through governed.Fetch with a real journal and a real
// browser, run red first against the unfixed code.
func TestARefusedScreenshotStillJournalsTheEgressThatHappened(t *testing.T) {
	exe, ok := cdp.Find()
	if !ok {
		if os.Getenv("SCOPYX_REQUIRE_CHROMIUM") != "" {
			t.Fatal("no browser found and SCOPYX_REQUIRE_CHROMIUM is set")
		}
		t.Skip("no chromium or chrome on this machine; set SCOPYX_CHROMIUM to point at one")
	}

	// Its own TMPDIR: cmd/scopyx's other browser test (subresource_test.go)
	// documents go test ./... running packages in parallel, and two browser
	// tests sharing one temp dir have collided on CI over the profile-dir
	// count before. This test does not count profile directories, but it
	// gets a TMPDIR of its own on the same principle rather than trusting
	// that omission is safe.
	t.Setenv("TMPDIR", t.TempDir())

	doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><h1>plenty to render</h1></body></html>`))
	}))
	defer doc.Close()

	ch, err := backend.NewChromium(exe, 1<<20, 40*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ch.NoSandbox = os.Getenv("SCOPYX_CHROMIUM_NO_SANDBOX") != ""
	// Small enough that no real screenshot's base64 fits. The capture itself
	// still happens and the page and its subresources still went out; the
	// refusal is on the SIZE of what came back, exactly the case finding 3
	// is about.
	ch.MaxBodyBytes = 16
	ch.Decide = func(_ context.Context, rawURL string) ([]netip.Addr, decide.Decision) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, decide.Decision{Verdict: decide.Allow}
	}
	ch.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(doc.URL, "http://"))
	}

	pdp := newHostPDP(t) // allows every host it is asked about
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
		resolver: fixedResolver{"shot.example": "203.0.113.9"},
	}

	_, err = g.Fetch(context.Background(), mcp.Call{
		Tool: "browse", URL: "http://shot.example/", Extract: "screenshot",
		AgentID: "agent://acme.example/support-bot", RunID: "run-e2e",
	})
	if err == nil {
		t.Fatal("a screenshot over the byte bound must still be refused")
	}

	evs, rerr := event.ReadFile(journalPath)
	if rerr != nil {
		t.Fatalf("reading the journal: %v", rerr)
	}
	if len(evs) == 0 {
		t.Fatal("the page was rendered and refused only for its size, but the journal holds nothing: " +
			"the egress that already happened left no trail")
	}
	if evs[0].Type != record.TypeFetch {
		t.Errorf("type = %q, want %q: this is egress that happened, not a request that was prevented",
			evs[0].Type, record.TypeFetch)
	}
	if evs[0].AgentID != "agent://acme.example/support-bot" {
		t.Errorf("agent_id = %q, want the identity the credential carries", evs[0].AgentID)
	}
}
