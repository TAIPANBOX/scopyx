package backend

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// Until 2026-09-16, extract=screenshot and wait_for were frozen names the
// `browse` tool accepted and the chromium backend implemented neither: a
// screenshot request came back as the page's outerHTML with nothing in the
// fidelity block saying so, and wait_for was plumbed into backend.Request and
// never read. Invariant 5 says a result never claims more than happened, and
// a caller who asked for a screenshot and got HTML is exactly that. These
// tests hold the fix, run red first against the unfixed backend.

// pngMagic is the eight bytes every PNG starts with, RFC-defined.
var pngMagic = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

// A screenshot request returns a base64 PNG body of the page as rendered, not
// its HTML. The page carries one solid-coloured block so a reader could tell
// the screenshot is of something, though this test only checks the format:
// pixel content is not asserted, because a headless renderer's exact bytes are
// not a contract this backend can promise.
func TestScreenshotReturnsAPNGBody(t *testing.T) {
	c := newChromium(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body style="margin:0">` +
			`<div style="width:120px;height:120px;background:#ff00ff"></div>` +
			`</body></html>`))
	}))
	defer srv.Close()
	f := newFixture()
	f.add("shot.example", srv, 1)
	f.apply(c)

	res, err := c.Fetch(context.Background(), Request{URL: "http://shot.example/", Extract: "screenshot"})
	if err != nil {
		t.Fatalf("a screenshot of a page every decision allows must not error: %v", err)
	}
	if len(res.Body) == 0 {
		t.Fatal("the screenshot body is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(res.Body))
	if err != nil {
		t.Fatalf("the body is not valid base64, so it cannot be the PNG the caller asked for: %v", err)
	}
	if len(decoded) < len(pngMagic) || string(decoded[:len(pngMagic)]) != string(pngMagic) {
		shown := decoded
		if len(shown) > 16 {
			shown = shown[:16]
		}
		t.Errorf("the decoded body does not start with the PNG magic bytes, got %x", shown)
	}
}

// A screenshot over the byte bound is refused rather than handed back cut.
// The reason is in the type itself: a truncated PNG cannot be decoded, so a
// truncation flag would be a lie dressed as an apology. Refusing loudly is the
// honest alternative CLAUDE.md invariant 5 asks for.
func TestScreenshotOverTheByteBoundIsRefusedRatherThanTruncated(t *testing.T) {
	c := newChromium(t)
	c.MaxBodyBytes = 16 // no real screenshot's base64 fits in 16 bytes

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body>anything</body></html>`))
	}))
	defer srv.Close()
	f := newFixture()
	f.add("toobig.example", srv, 1)
	f.apply(c)

	_, err := c.Fetch(context.Background(), Request{URL: "http://toobig.example/", Extract: "screenshot"})
	if err == nil {
		t.Fatal("a screenshot over the byte bound must be refused, not truncated")
	}
	if !strings.Contains(err.Error(), "screenshot") {
		t.Errorf("the refusal must name what was refused, got %q", err)
	}
}

// wait_for on a selector a page's own script inserts after load: the
// extraction happens after the element exists, not at whatever the document
// looked like when the load event fired.
func TestWaitForReturnsTheElementInsertedAfterLoad(t *testing.T) {
	c := newChromium(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 2 seconds, deliberately longer than the browser launch, CDP handshake
		// and load-event round trips take on their own: a version of this test
		// that used a small delay (300ms) passed against the UNFIXED backend,
		// because those round trips alone eat more than 300ms wall clock and the
		// element was already there by the time extraction ran regardless of
		// whether wait_for was honoured. This delay is long enough that the
		// element is provably absent at the load event and present only because
		// something waited for it.
		_, _ = w.Write([]byte(`<!doctype html><html><body><div id="early">loaded</div><script>` +
			`setTimeout(function(){var d=document.createElement("div");d.id="late";` +
			`d.textContent="late-arrived";document.body.appendChild(d);}, 2000);` +
			`</script></body></html>`))
	}))
	defer srv.Close()
	f := newFixture()
	f.add("late.example", srv, 1)
	f.apply(c)

	// extract=text, not html: outerHTML includes the <script> tag's own source,
	// which literally contains the string "late-arrived" as a JS string
	// literal, so an html-extract assertion on that substring would pass
	// whether or not the element was ever actually inserted. innerText only
	// reflects rendered, visible content, which the JS literal is not.
	start := time.Now()
	res, err := c.Fetch(context.Background(), Request{URL: "http://late.example/", Extract: "text", WaitFor: "#late"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Body), "late-arrived") {
		t.Errorf("the element the page inserts after load is missing: %.400q", res.Body)
	}
	if res.TruncatedBy != decide.TruncatedNone {
		t.Errorf("TruncatedBy = %q, want none: the selector appeared well inside the bound", res.TruncatedBy)
	}
	if elapsed > 10*time.Second {
		t.Errorf("took %s to see an element inserted after 300ms; wait_for is not polling", elapsed)
	}
}

// wait_for on a selector that never appears must not hang and must not error:
// it returns within the bound, with the document present and the time
// truncation named, because the caller asked to wait and the wait did not
// find what it was waiting for.
func TestWaitForOnASelectorThatNeverAppearsReturnsWithinTheBoundWithTimeTruncation(t *testing.T) {
	c := newChromium(t)
	c.Timeout = 6 * time.Second // short, so this test does not itself hang for the default 40s

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><h1>never grows a #never</h1></body></html>`))
	}))
	defer srv.Close()
	f := newFixture()
	f.add("stall.example", srv, 1)
	f.apply(c)

	start := time.Now()
	res, err := c.Fetch(context.Background(), Request{URL: "http://stall.example/", Extract: "html", WaitFor: "#never"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("a selector that never appears must not turn into an error: %v", err)
	}
	if elapsed >= c.Timeout {
		t.Errorf("took %s, the whole fetch timeout: wait_for hung rather than returning within its own bound", elapsed)
	}
	if res.TruncatedBy != decide.TruncatedByTime {
		t.Errorf("TruncatedBy = %q, want %q", res.TruncatedBy, decide.TruncatedByTime)
	}
	if !strings.Contains(string(res.Body), "never grows") {
		t.Errorf("the document must still come back: %.200q", res.Body)
	}
}

// The selector is caller input. It must reach the evaluated expression as a
// JSON string literal, never by concatenation, so a selector holding a quote
// and a closing paren cannot break out of the querySelector(...) call it is
// placed inside. The assertion is on a canary the injection would reach if it
// ran, exactly the same shape as the subresource tests: an outcome check would
// pass equally well if the injected code ran and merely returned something
// harmless-looking.
func TestWaitForSelectorWithAQuoteAndParenIsNotAnInjection(t *testing.T) {
	c := newChromium(t)
	c.Timeout = 6 * time.Second

	var canaryHits atomic.Int64
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		canaryHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer canary.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><h1>ordinary page</h1></body></html>`))
	}))
	defer srv.Close()

	f := newFixture()
	f.add("inject.example", srv, 1)
	f.add("canary.example", canary, 2)
	f.apply(c)

	payload := `nope") ; fetch('http://canary.example/hit') ; //`
	res, err := c.Fetch(context.Background(),
		Request{URL: "http://inject.example/", Extract: "html", WaitFor: payload})
	if err != nil {
		t.Fatalf("an injection attempt in wait_for must not error the fetch: %v", err)
	}
	if canaryHits.Load() != 0 {
		t.Fatal("the canary was reached: the wait_for selector broke out of its string and ran as script")
	}
	if res.TruncatedBy != decide.TruncatedByTime {
		t.Errorf("TruncatedBy = %q, want %q: the literal selector never matches anything", res.TruncatedBy, decide.TruncatedByTime)
	}
	if !strings.Contains(string(res.Body), "ordinary page") {
		t.Errorf("the document must still come back untouched: %.200q", res.Body)
	}
}
