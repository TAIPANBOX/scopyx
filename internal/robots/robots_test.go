package robots

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// serve stands up an origin that answers /robots.txt with body and status, and
// counts how many times it was asked.
func serve(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/robots.txt" {
			w.WriteHeader(http.StatusOK)
			return
		}
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func check(t *testing.T, c *Cache, srv *httptest.Server, path string) Result {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	return c.Check(context.Background(), "http", host, path)
}

// The property the whole package exists for.
func TestADisallowedPathIsRefusedAndTheRuleIsNamed(t *testing.T) {
	srv, _ := serve(t, 200, "User-agent: *\nDisallow: /private/\n")
	c := New(ModeReport, 0, nil)

	if got := check(t, c, srv, "/private/report"); got.Allowed {
		t.Error("a disallowed path must be refused")
	} else {
		if !got.Read {
			t.Error("robots was read; Read must say so")
		}
		if !strings.Contains(got.Rule, "/private/") {
			t.Errorf("the refusal must name the rule, got %q", got.Rule)
		}
	}
	if got := check(t, c, srv, "/public/report"); !got.Allowed {
		t.Errorf("a path outside the rule must be allowed: %s", got.Reason)
	}
}

// A group naming us wins outright, and applying another agent's rules to
// ourselves is the wrong direction of wrong: it refuses fetches nobody asked to
// have refused.
func TestOurOwnGroupWinsAndAnotherAgentsRulesAreNotOurs(t *testing.T) {
	body := "User-agent: SomeoneElse\nDisallow: /\n\nUser-agent: scopyx\nDisallow: /admin/\n"
	srv, _ := serve(t, 200, body)
	c := New(ModeReport, 0, nil)

	if got := check(t, c, srv, "/anything"); !got.Allowed {
		t.Errorf("another agent's Disallow: / must not apply to us: %s", got.Reason)
	}
	if got := check(t, c, srv, "/admin/x"); got.Allowed {
		t.Error("our own group's rule must apply")
	}
}

// A `User-agent` line after a rule line starts a NEW group. Treating the file
// as a flat list merges everybody's rules into one.
func TestARuleLineEndsTheGroupSoTheNextAgentStartsAFreshOne(t *testing.T) {
	body := "User-agent: *\nDisallow: /a/\nUser-agent: SomeoneElse\nDisallow: /b/\n"
	srv, _ := serve(t, 200, body)
	c := New(ModeReport, 0, nil)

	if got := check(t, c, srv, "/a/x"); got.Allowed {
		t.Error("the star group's own rule must apply")
	}
	if got := check(t, c, srv, "/b/x"); !got.Allowed {
		t.Errorf("/b/ belongs to another agent's group: %s", got.Reason)
	}
}

// RFC 9309 2.2.2: the longest matching pattern wins and Allow beats Disallow at
// equal length. Without it a single `Disallow: /` beats every Allow under it,
// which is the shape most real files use.
func TestTheMostSpecificRuleWinsAndAllowBeatsDisallowAtEqualLength(t *testing.T) {
	body := "User-agent: *\nDisallow: /\nAllow: /public/\n"
	srv, _ := serve(t, 200, body)
	c := New(ModeReport, 0, nil)

	if got := check(t, c, srv, "/public/page"); !got.Allowed {
		t.Errorf("a longer Allow must beat a shorter Disallow: %s", got.Reason)
	}
	if got := check(t, c, srv, "/private/page"); got.Allowed {
		t.Error("Disallow: / must still cover everything else")
	}
}

// An empty Disallow means "nothing is disallowed", not "everything matches".
// This is the line hand-rolled parsers get backwards.
func TestAnEmptyDisallowAllowsEverything(t *testing.T) {
	srv, _ := serve(t, 200, "User-agent: *\nDisallow:\n")
	c := New(ModeReport, 0, nil)
	if got := check(t, c, srv, "/anything/at/all"); !got.Allowed {
		t.Errorf("an empty Disallow forbids nothing: %s", got.Reason)
	}
}

func TestTheTwoWildcardsWork(t *testing.T) {
	body := "User-agent: *\nDisallow: /*.pdf$\nDisallow: /a/*/secret\n"
	srv, _ := serve(t, 200, body)
	c := New(ModeReport, 0, nil)

	for _, tc := range []struct {
		path string
		want bool // allowed
	}{
		{"/reports/q3.pdf", false},
		{"/reports/q3.pdf.html", true}, // $ anchors the end
		{"/a/one/secret", false},
		{"/a/one/two/secret", false},
		{"/b/one/secret", true},
	} {
		if got := check(t, c, srv, tc.path); got.Allowed != tc.want {
			t.Errorf("%s: allowed = %v, want %v (%s)", tc.path, got.Allowed, tc.want, got.Reason)
		}
	}
}

// A 404 IS a reading: the site was asked and has nothing to say. RFC 9309
// 2.3.1.3, and by far the common case.
func TestAFourOhFourIsAReadingRatherThanAFailure(t *testing.T) {
	srv, _ := serve(t, 404, "")
	c := New(ModeReport, 0, nil)
	got := check(t, c, srv, "/anything")
	if !got.Allowed {
		t.Error("404 means no rules")
	}
	if !got.Read {
		t.Error("404 is a reading: the site answered")
	}
}

// The decision this package makes differently from crawler guidance, and the
// reason is that we are not a crawler. An unreadable robots.txt must not let a
// site's outage stop an operator's own governed work.
func TestAnUnreadableRobotsAllowsAndSaysItCouldNotLook(t *testing.T) {
	srv, _ := serve(t, 500, "")
	c := New(ModeReport, 0, nil)
	got := check(t, c, srv, "/anything")

	if !got.Allowed {
		t.Error("the default must not let a 5xx deny an operator's own fetch")
	}
	if got.Read {
		t.Fatal("Read must be false: nothing was read")
	}
	if !strings.Contains(got.Reason, "not a statement that the site allows it") {
		t.Errorf("the reason must refuse the wrong reading, got %q", got.Reason)
	}
}

// And the operator who wants the crawler posture gets it.
func TestStrictModeRefusesWhatItCouldNotRead(t *testing.T) {
	srv, _ := serve(t, 500, "")
	c := New(ModeStrict, 0, nil)
	got := check(t, c, srv, "/anything")
	if got.Allowed {
		t.Error("strict mode must refuse rather than assume permission")
	}
	if got.Read {
		t.Error("Read is still false: strict changes the verdict, not the fact")
	}
}

func TestOffDoesNotAskAtAll(t *testing.T) {
	srv, hits := serve(t, 200, "User-agent: *\nDisallow: /\n")
	c := New(ModeOff, 0, nil)
	if got := check(t, c, srv, "/anything"); !got.Allowed {
		t.Error("with robots off nothing is refused by it")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("robots.txt was fetched %d times with the feature off", n)
	}
}

// One reading per origin per window, so a page of forty subresources does not
// become forty robots.txt fetches.
func TestOneReadingIsReusedInsideTheWindow(t *testing.T) {
	srv, hits := serve(t, 200, "User-agent: *\nDisallow: /private/\n")
	c := New(ModeReport, time.Hour, nil)
	for i := 0; i < 5; i++ {
		check(t, c, srv, "/page")
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("robots.txt was fetched %d times, want 1", n)
	}
}

// And it expires, because a rule somebody changed to stop us is a rule we would
// otherwise ignore for as long as the cache lives.
func TestAReadingExpires(t *testing.T) {
	srv, hits := serve(t, 200, "User-agent: *\nDisallow: /private/\n")
	c := New(ModeReport, time.Nanosecond, nil)
	check(t, c, srv, "/page")
	time.Sleep(2 * time.Millisecond)
	check(t, c, srv, "/page")
	if n := hits.Load(); n < 2 {
		t.Errorf("robots.txt was fetched %d times, want it re-read after the window", n)
	}
}

// A robots.txt that redirects off its origin is not that origin's robots.txt,
// and following it would be a request to a destination nobody decided.
func TestARedirectingRobotsIsNotFollowed(t *testing.T) {
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	}))
	defer other.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/robots.txt", http.StatusFound)
	}))
	defer srv.Close()

	c := New(ModeReport, 0, nil)
	got := c.Check(context.Background(), "http", strings.TrimPrefix(srv.URL, "http://"), "/x")
	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the redirect was followed %d times", n)
	}
	if got.Read {
		t.Error("a 302 is not a reading")
	}
}

// A group naming us with no rules is a site saying we may fetch everything, and
// falling back to `*` would ignore what it said.
func TestAnEmptyGroupForUsBeatsTheStarGroup(t *testing.T) {
	srv, _ := serve(t, 200, "User-agent: *\nDisallow: /\n\nUser-agent: scopyx\n")
	c := New(ModeReport, 0, nil)
	if got := check(t, c, srv, "/anything"); !got.Allowed {
		t.Errorf("our own empty group must win over the star group: %s", got.Reason)
	}
}
