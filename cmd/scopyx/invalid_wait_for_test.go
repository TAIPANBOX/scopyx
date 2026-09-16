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
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/cdp"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/mcp"
	"github.com/TAIPANBOX/scopyx/internal/record"
)

// Round 2 of the Fable review, 2026-09-16, found a hole the fix for finding 1
// opened: the invalid selector was validated AFTER Page.navigate, so a typo
// in wait_for still made the page and every allowed subresource leave through
// the proxy before the error came back, as a plain error rather than a
// *fetch.Refusal. governed.Fetch's "the backend fetched nothing" branch
// (main.go, added for finding 3's screenshot case) read that Result{} as
// exactly that, nothing fetched, when the document had in fact been fetched:
// finding 3's hole, reopened on the path finding 1 created.
//
// This test holds the fix through governed.Fetch with a real browser and a
// real journal: an invalid wait_for selector is now caught on about:blank,
// before Page.navigate ever runs, so the document server is never reached and
// the journal staying empty is honest, not a gap. Run red first against the
// round-1 code (commit f1801fc, selector checked inside waitFor after
// navigation): the document server was hit once.
func TestAnInvalidWaitForSelectorFetchesNothingAndJournalsNothing(t *testing.T) {
	exe, ok := cdp.Find()
	if !ok {
		if os.Getenv("SCOPYX_REQUIRE_CHROMIUM") != "" {
			t.Fatal("no browser found and SCOPYX_REQUIRE_CHROMIUM is set")
		}
		t.Skip("no chromium or chrome on this machine; set SCOPYX_CHROMIUM to point at one")
	}

	// Its own TMPDIR, same reasoning as TestARefusedScreenshotStillJournalsTheEgressThatHappened:
	// go test ./... runs packages in parallel and two browser tests sharing
	// one temp dir have collided on CI before (subresource_test.go).
	t.Setenv("TMPDIR", t.TempDir())

	var hits atomic.Int64
	doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><h1>never fetched</h1></body></html>`))
	}))
	defer doc.Close()

	ch, err := backend.NewChromium(exe, 1<<20, 6*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ch.NoSandbox = os.Getenv("SCOPYX_CHROMIUM_NO_SANDBOX") != ""
	// Only the fixture host is allowed, everything else (Chrome's own
	// background traffic, update.googleapis.com and the like, see CLAUDE.md
	// "Chrome's own background traffic reaches the floor") is refused. This
	// matters here specifically: Dial below routes every allowed destination
	// to doc.URL regardless of which host it was for, so an always-allow
	// Decide would let stray background traffic inflate the hit count this
	// test asserts on and hide the very egress this test exists to catch.
	ch.Decide = func(_ context.Context, rawURL string) ([]netip.Addr, decide.Decision) {
		if !strings.Contains(rawURL, "neverfetched.example") {
			return nil, decide.Decision{Verdict: decide.DenyAddress, Reason: "not the fixture host"}
		}
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
		resolver: fixedResolver{"neverfetched.example": "203.0.113.9"},
	}

	_, err = g.Fetch(context.Background(), mcp.Call{
		Tool: "browse", URL: "http://neverfetched.example/", WaitFor: "##not-a-selector",
		AgentID: "agent://acme.example/support-bot", RunID: "run-e2e",
	})
	if err == nil {
		t.Fatal("an invalid wait_for selector must be refused")
	}
	if !strings.Contains(err.Error(), "##not-a-selector") {
		t.Errorf("the error must name the invalid selector, got %q", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("document server hits = %d, want 0: an invalid selector must be caught before "+
			"Page.navigate ever runs, not after the document already left through the proxy", hits.Load())
	}

	evs, rerr := event.ReadFile(journalPath)
	if rerr != nil {
		t.Fatalf("reading the journal: %v", rerr)
	}
	if len(evs) != 0 {
		t.Errorf("journal holds %d events, want 0: nothing was fetched, so nothing should be "+
			"journalled; a non-empty journal here means the selector was checked after egress "+
			"happened, not before it", len(evs))
	}
}
