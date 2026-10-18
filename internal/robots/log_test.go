package robots

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// capture returns a logger that writes text lines into buf at Info, so every
// level the package uses is kept.
func capture(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// In the default posture an unreadable robots.txt allows the fetch. The Result
// carries Read false, but the fetch does not hand that to the caller, so the
// log is where the allow is written down, once per destination.
func TestAnUnreadableRobotsIsLoggedForEachDestinationWhenAllowed(t *testing.T) {
	first, _ := serve(t, 500, "")
	second, _ := serve(t, 503, "")
	var buf bytes.Buffer
	c := New(ModeReport, 0, nil)
	c.Log = capture(&buf)

	for _, srv := range []*httptest.Server{first, second} {
		// A path with words in it, so a log that carried the path would show it.
		if got := check(t, c, srv, "/secret/report?email=someone"); !got.Allowed {
			t.Fatalf("report mode must allow when robots.txt cannot be read: %s", got.Reason)
		}
	}
	out := buf.String()
	for _, srv := range []*httptest.Server{first, second} {
		if !strings.Contains(out, "origin="+srv.URL) {
			t.Errorf("no decision line for %s in:\n%s", srv.URL, out)
		}
	}
	if strings.Count(out, "decision=allowed") != 2 {
		t.Errorf("want one allowed decision per destination, got:\n%s", out)
	}
	if strings.Contains(out, "secret") || strings.Contains(out, "email") {
		t.Errorf("the log carries part of the URL, which invariant 10 forbids:\n%s", out)
	}
}

// The decision is made again on every fetch, and the reading is reused only for
// the rules. A second fetch to the same site is a second decision, so it is a
// second line.
func TestEachFetchToAnUnreadableSiteIsLoggedNotOnlyTheFirst(t *testing.T) {
	srv, _ := serve(t, 500, "")
	var buf bytes.Buffer
	c := New(ModeReport, time.Hour, nil)
	c.Log = capture(&buf)

	check(t, c, srv, "/one")
	check(t, c, srv, "/two")
	if n := strings.Count(buf.String(), "origin="+srv.URL); n != 2 {
		t.Errorf("two fetches made two decisions, want two lines, got %d:\n%s", n, buf.String())
	}
}

// The strict posture refuses, and the refusal is written down the same way.
func TestAnUnreadableRobotsIsLoggedWhenStrictRefuses(t *testing.T) {
	srv, _ := serve(t, 500, "")
	var buf bytes.Buffer
	c := New(ModeStrict, 0, nil)
	c.Log = capture(&buf)

	if got := check(t, c, srv, "/anything"); got.Allowed {
		t.Fatal("strict mode must refuse when robots.txt cannot be read")
	}
	out := buf.String()
	if !strings.Contains(out, "origin="+srv.URL) || !strings.Contains(out, "decision=refused") {
		t.Errorf("want a refused decision line for %s, got:\n%s", srv.URL, out)
	}
}

// A readable robots.txt is the normal case. The rule decides, and nothing about
// the reading is written down: the log holds only decisions made without rules.
func TestAReadableRobotsWritesNoDecisionLine(t *testing.T) {
	srv, _ := serve(t, 200, "User-agent: *\nDisallow: /private/\n")
	var buf bytes.Buffer
	c := New(ModeReport, 0, nil)
	c.Log = capture(&buf)

	if got := check(t, c, srv, "/private/report"); got.Allowed {
		t.Fatal("the rule must still refuse a disallowed path")
	}
	check(t, c, srv, "/public/report")
	if buf.Len() != 0 {
		t.Errorf("a readable robots.txt wrote a decision line:\n%s", buf.String())
	}
}

// With the feature off nothing is asked, so there is no decision to write down.
func TestOffWritesNoDecisionLine(t *testing.T) {
	srv, _ := serve(t, 500, "")
	var buf bytes.Buffer
	c := New(ModeOff, 0, nil)
	c.Log = capture(&buf)

	check(t, c, srv, "/anything")
	if buf.Len() != 0 {
		t.Errorf("robots off wrote a decision line:\n%s", buf.String())
	}
}
