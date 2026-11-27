package main

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/mcp"
	"github.com/TAIPANBOX/scopyx/internal/record"
)

// Invariant 8, the window: a spent cap reopens when its hour is over and not a
// minute before. A window that never reopened would stop a deployment for good
// after its first busy hour; one that reopened early is no ceiling.
func TestTheHourlyWindowReopensAfterAnHourAndNotBefore(t *testing.T) {
	c := newHourlyCap(1)
	if !c.take() {
		t.Fatal("the first fetch of the hour must be allowed")
	}
	if c.take() {
		t.Fatal("the cap is one, the second must be refused")
	}

	c.windowAt = time.Now().Add(-59 * time.Minute)
	if c.take() {
		t.Error("the window reopened before its hour was over")
	}

	c.windowAt = time.Now().Add(-time.Hour - time.Second)
	if !c.take() {
		t.Error("the window did not reopen after its hour")
	}
	if c.take() {
		t.Error("a reopened window must count from zero up to the same cap, not lift it")
	}
}

// A spent cap is a refusal the agent is told about and the trail records: a
// throttled hour must not look like a quiet one. And nothing leaves.
func TestASpentCapRefusesTheFetchRecordsItAndNeverReachesTheTarget(t *testing.T) {
	h := newHarness(t, "allow", publicResolver{})
	g := h.mcpSrv.Config.Handler.(*mcp.Server).Fetcher.(*governed)
	g.cap = &hourlyCap{limit: 1, used: 1, windowAt: time.Now()}

	out := h.call(t, "k1", "http://example.com/page")
	res, _ := out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("a spent cap must refuse, got %v", out)
	}
	if txt := firstText(t, res); !strings.Contains(txt, "deny_rate") {
		t.Errorf("the agent must be told it was the cap, got %q", txt)
	}
	if got := h.paths(t, 300*time.Millisecond); len(got) != 0 {
		t.Fatalf("the target was reached with the cap spent: %v", got)
	}
	evs := h.events(t)
	if len(evs) != 1 || evs[0].Type != record.TypeBlocked {
		t.Fatalf("want one web_blocked event, got %+v", evs)
	}
	if v, _ := evs[0].Data["verdict"].(string); v != "deny_rate" {
		t.Errorf("verdict = %q, want deny_rate", v)
	}
}

// A bound an operator set is the bound used.
func TestAWellFormedBoundIsTheOneUsed(t *testing.T) {
	t.Setenv("SCOPYX_MAX_BYTES", "1234")
	if got := envInt("SCOPYX_MAX_BYTES", defaultMaxBodyBytes); got != 1234 {
		t.Errorf("SCOPYX_MAX_BYTES=1234 gave %d", got)
	}
	t.Setenv("SCOPYX_MAX_BYTES", "")
	if got := envInt("SCOPYX_MAX_BYTES", defaultMaxBodyBytes); got != defaultMaxBodyBytes {
		t.Errorf("unset gave %d, want the default %d", got, defaultMaxBodyBytes)
	}
}

// countingResolver records whether it was asked at all.
type countingResolver struct{ asked int }

func (r *countingResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	r.asked++
	return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
}

// A subresource URL that does not parse is refused before anything is looked
// up for it: there is no host to decide about, and guessing one is how a
// decision ends up about a different destination than the request.
func TestASubresourceURLThatDoesNotParseIsRefusedAndNeverResolved(t *testing.T) {
	res := &countingResolver{}
	decideSub := subresourceDecider(res)

	addrs, d := decideSub(context.Background(), "http://[::1")
	if d.Verdict != decide.DenyScheme {
		t.Fatalf("an unparsable subresource URL was %s (%q), want deny_scheme", d.Verdict, d.Reason)
	}
	if addrs != nil || res.asked != 0 {
		t.Errorf("an unparsable URL was resolved anyway (asked %d, addrs %v)", res.asked, addrs)
	}
}

// The real resolver: an answer for a name that has one, an error and no
// addresses for a name that cannot exist (RFC 6761 reserves .invalid).
func TestTheSystemResolverAnswersForANameAndRefusesOneThatCannotExist(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := systemResolver{}.Resolve(ctx, "localhost")
	if err != nil || len(addrs) == 0 {
		t.Fatalf("localhost must resolve, got %v, %v", addrs, err)
	}
	for _, a := range addrs {
		if !a.IsLoopback() {
			t.Errorf("localhost resolved to %s, which is not loopback", a)
		}
	}

	addrs, err = systemResolver{}.Resolve(ctx, "no-such-host.invalid")
	if err == nil {
		t.Fatalf("a .invalid name must not resolve, got %v", addrs)
	}
	if addrs != nil {
		t.Errorf("a failed lookup must return no addresses, got %v", addrs)
	}
}

// SCOPYX_BACKEND=chromium with a SCOPYX_CHROMIUM that names nothing refuses to
// start, and the error names the path, instead of starting and failing on the
// first fetch.
func TestTheChromiumBackendRefusesToStartWithAMissingBrowserPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-chrome")
	t.Setenv("SCOPYX_BACKEND", "chromium")
	t.Setenv("SCOPYX_CHROMIUM", missing)

	b, err := chooseBackend(&http.Client{})
	if err == nil {
		t.Fatalf("a missing browser path must refuse startup, built %T", b)
	}
	if !errors.Is(err, backend.ErrNoBrowser) {
		t.Errorf("want backend.ErrNoBrowser, got %v", err)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("the startup error must name %q, got %q", missing, err)
	}
}

// SCOPYX_BACKEND=chromium builds the browser backend on the path the operator
// named, and carries their sandbox choice.
func TestTheChromiumBackendUsesTheConfiguredBrowserAndSandboxChoice(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "chrome")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCOPYX_BACKEND", "chromium")
	t.Setenv("SCOPYX_CHROMIUM", exe)

	for _, tc := range []struct {
		env  string
		want bool
	}{{"1", true}, {"0", false}, {"", false}} {
		t.Setenv("SCOPYX_CHROMIUM_NO_SANDBOX", tc.env)
		b, err := chooseBackend(&http.Client{})
		if err != nil {
			t.Fatalf("chromium with a browser on disk must build: %v", err)
		}
		ch, ok := b.(*backend.Chromium)
		if !ok {
			t.Fatalf("SCOPYX_BACKEND=chromium built %T", b)
		}
		if ch.Exe != exe {
			t.Errorf("the backend drives %q, want the configured %q", ch.Exe, exe)
		}
		if ch.NoSandbox != tc.want {
			t.Errorf("SCOPYX_CHROMIUM_NO_SANDBOX=%q gave NoSandbox=%v", tc.env, ch.NoSandbox)
		}
	}
}
