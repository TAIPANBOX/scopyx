package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// The property this backend exists to have, and the one an HTTP client gives
// away by default in every language.
//
// A followed redirect is a second request that no policy decision preceded. The
// assertion is a COUNT rather than an outcome: a backend that followed the hop
// and returned the final page would satisfy any test that only looked at what
// came back.
func TestARedirectIsReportedAndNeverFollowed(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/landed", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("the page nobody was allowed to reach yet"))
	}))
	defer srv.Close()

	p := NewPassthrough(1<<20, 2*time.Second)
	res, err := p.Fetch(context.Background(), Request{URL: srv.URL + "/start"})
	if err != nil {
		t.Fatal(err)
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("the server was asked %d times, want 1: the hop was followed without a decision", got)
	}
	if res.HTTPStatus != http.StatusFound {
		t.Errorf("status = %d, want 302", res.HTTPStatus)
	}
	if !strings.HasSuffix(res.RedirectTo, "/landed") {
		t.Errorf("RedirectTo = %q, want the target reported so the caller can decide it", res.RedirectTo)
	}
	if strings.Contains(string(res.Body), "nobody was allowed") {
		t.Error("the body of the redirect TARGET came back, so it was fetched")
	}
}

// Invariant 5. A bound that truncates without saying so hands an agent half a
// page it will report on confidently.
func TestABodyPastTheCapIsTruncatedAndSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer srv.Close()

	p := NewPassthrough(1000, 2*time.Second)
	res, err := p.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Body) != 1000 {
		t.Errorf("body is %d bytes, want the cap of 1000", len(res.Body))
	}
	if res.TruncatedBy != decide.TruncatedByBytes {
		t.Errorf("TruncatedBy = %q, want %q: a silent truncation is the failure",
			res.TruncatedBy, decide.TruncatedByBytes)
	}
}

// A body exactly at the cap is complete, not truncated. This is why the reader
// takes one byte more than the bound: reading exactly the bound cannot tell the
// two apart and would report every full-size page as cut short.
func TestABodyExactlyAtTheCapIsNotCalledTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
	}))
	defer srv.Close()

	res, err := NewPassthrough(1000, 2*time.Second).Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.TruncatedBy != decide.TruncatedNone {
		t.Errorf("TruncatedBy = %q, want none: the page ended exactly at the bound", res.TruncatedBy)
	}
}

// Empty, not nil, and the difference is what the fidelity block reports.
//
// Nil means "this backend cannot say what the page asked for", which for a
// fetch that parses no HTML would be false: it knows perfectly well that it
// requested nothing.
func TestItReportsAskingForNothingRatherThanNotKnowing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<img src=/a.png><script src=/b.js>"))
	}))
	defer srv.Close()

	res, err := NewPassthrough(1<<20, 2*time.Second).Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.Subresources == nil {
		t.Fatal("nil says nobody knows; this backend knows it asked for nothing")
	}
	if len(res.Subresources) != 0 {
		t.Errorf("got %d subresources, want 0", len(res.Subresources))
	}
}

// 304 is an answer about a cache and 300 has no single target. Treating either
// as a hop would send the layer above looking for a destination that is not
// there.
func TestAStatusThatIsNotAHopIsNotReportedAsOne(t *testing.T) {
	for _, status := range []int{http.StatusMultipleChoices, http.StatusNotModified, http.StatusOK} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/somewhere")
			w.WriteHeader(status)
		}))
		res, err := NewPassthrough(1<<20, 2*time.Second).Fetch(context.Background(), Request{URL: srv.URL})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.RedirectTo != "" {
			t.Errorf("status %d reported RedirectTo=%q, and it is not a hop", status, res.RedirectTo)
		}
	}
}

// Invariant 9. This plane governs evasion and never supplies it, and a matched
// browser user-agent is evasion with a polite name.
func TestItNamesItselfRatherThanImpersonatingABrowser(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	if _, err := NewPassthrough(1<<20, 2*time.Second).Fetch(
		context.Background(), Request{URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	ua := <-got
	if !strings.HasPrefix(ua, "scopyx/") {
		t.Errorf("User-Agent = %q, want this component named", ua)
	}
	for _, tell := range []string{"Mozilla", "Chrome", "Safari", "WebKit"} {
		if strings.Contains(ua, tell) {
			t.Errorf("User-Agent %q carries %q, which is impersonating a browser", ua, tell)
		}
	}
}

// Both bounds are finite whatever the caller passes. A zero timeout is a fetch
// that hangs rather than one that is refused.
func TestTheBoundsAreFiniteEvenWhenTheCallerPassesZero(t *testing.T) {
	p := NewPassthrough(0, 0)
	if p.MaxBodyBytes <= 0 {
		t.Errorf("MaxBodyBytes = %d, want a finite default", p.MaxBodyBytes)
	}
	if p.HTTP.Timeout <= 0 {
		t.Error("an unbounded timeout is a hang, which is a bound that never arrives")
	}
}
