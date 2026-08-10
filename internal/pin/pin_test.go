package pin

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func addrsOf(t *testing.T, s ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(s))
	for _, one := range s {
		a, err := netip.ParseAddr(one)
		if err != nil {
			t.Fatalf("bad fixture address %q: %v", one, err)
		}
		out = append(out, a)
	}
	return out
}

// hostPort splits an httptest URL into the pieces a pin needs.
func hostPort(t *testing.T, srv *httptest.Server) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("bad server URL %q: %v", srv.URL, err)
	}
	return host, port
}

// The property the package exists for. A host nobody checked is not dialled,
// and the refusal says so rather than looking like a network failure.
func TestAHostNoDecisionCoveredIsNotDialled(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	c := Client(3 * time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	_, err := c.Do(req)

	if err == nil {
		t.Fatal("a fetch with no pin must not succeed")
	}
	if !errors.Is(err, ErrUnchecked) {
		t.Errorf("the refusal must be typed as unchecked, got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the server was reached %d times by a fetch nothing checked", n)
	}
}

// And a pinned one goes through, so the refusal above is the pin working
// rather than the transport being broken.
func TestAPinnedHostIsReached(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host, _ := hostPort(t, srv)
	ctx := With(context.Background(), host, addrsOf(t, host))

	c := Client(3 * time.Second)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("a pinned host must be reachable: %v", err)
	}
	defer resp.Body.Close()
	if n := hits.Load(); n != 1 {
		t.Errorf("the server was reached %d times, want 1", n)
	}
}

// The rebinding case, which is the whole reason for the package: the socket
// goes where the PIN says, not where the name says now.
//
// The request names `localhost`, which really does resolve to the fixture
// server. The pin carries an address that does not. An unpinned dialer looks
// the name up and reaches the server; a pinned one dials what was checked and
// reaches nothing. So the fixture server being UNTOUCHED is the whole assertion,
// and it is the same shape as a name that answered publicly for the decision
// and privately a microsecond later.
func TestTheSocketGoesWhereThePinSaysAndNotWhereTheNameSaysNow(t *testing.T) {
	var reached atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Add(1)
	}))
	defer srv.Close()
	_, port := hostPort(t, srv)

	// TEST-NET-3, reserved by RFC 5737 for documentation and routed nowhere.
	ctx := With(context.Background(), "localhost", addrsOf(t, "203.0.113.10"))

	c := Client(300 * time.Millisecond)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:"+port+"/", nil)
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("the fetch reached something: the dialer used the name rather than the pin")
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("the fixture server was reached %d times, so the name won over the checked address", n)
	}
}

// A pin is per host, and one host's pin is not another's permission. This is
// the mistake a map with a single "current" entry would make.
func TestOneHostsPinIsNotAnothersPermission(t *testing.T) {
	ctx := With(context.Background(), "allowed.example", addrsOf(t, "203.0.113.10"))
	if _, ok := Checked(ctx, "allowed.example"); !ok {
		t.Error("the pinned host must be checked")
	}
	if _, ok := Checked(ctx, "other.example"); ok {
		t.Error("an unpinned host must not inherit another host's pin")
	}
}

// Hops accumulate rather than replace: a redirect pins its own host and the
// first one stays, because a connection to it may still be in flight.
func TestASecondHopAddsAPinWithoutRemovingTheFirst(t *testing.T) {
	ctx := With(context.Background(), "first.example", addrsOf(t, "203.0.113.10"))
	ctx = With(ctx, "second.example", addrsOf(t, "203.0.113.11"))
	for _, h := range []string{"first.example", "second.example"} {
		if _, ok := Checked(ctx, h); !ok {
			t.Errorf("%s must still be pinned", h)
		}
	}
}

// Copied rather than mutated, so a context passed to two goroutines cannot
// grow under either of them. Without the copy, `With` on a derived context
// would write into the parent's map and pin a host for code that never asked.
func TestAPinDoesNotLeakBackIntoTheParentContext(t *testing.T) {
	parent := With(context.Background(), "first.example", addrsOf(t, "203.0.113.10"))
	_ = With(parent, "second.example", addrsOf(t, "203.0.113.11"))
	if _, ok := Checked(parent, "second.example"); ok {
		t.Error("a child's pin must not appear in the parent")
	}
}

// `example.com.` and `Example.com` name the same host. Absent means REFUSED
// here, so a case-sensitive map would refuse a fetch the plane allowed, which
// is a silent breakage rather than a security hole and is worse to debug.
func TestATrailingDotAndAnUppercaseNameAreTheSameHost(t *testing.T) {
	ctx := With(context.Background(), "Example.com.", addrsOf(t, "203.0.113.10"))
	for _, h := range []string{"example.com", "EXAMPLE.COM", "example.com."} {
		if _, ok := Checked(ctx, h); !ok {
			t.Errorf("%q must match the pin", h)
		}
	}
}

// A pin with no addresses is not a pin. Storing an empty slice would make
// `Checked` report true and the dial loop try nothing, which reads as "checked
// and unreachable" instead of "never checked".
func TestAnEmptyPinIsNotStored(t *testing.T) {
	ctx := With(context.Background(), "example.com", nil)
	if _, ok := Checked(ctx, "example.com"); ok {
		t.Error("an empty address list must not register as a pin")
	}
}

// Keep-alives off, checked here because it is a security property wearing the
// clothes of a performance setting, and somebody will switch it on for speed.
// A pooled connection is keyed on scheme, host and port, which is exactly what
// a rebinding attack holds constant, so a reused socket consults the pin once
// and then never again.
func TestKeepAlivesAreOffSoASocketCannotOutliveTheDecisionThatOpenedIt(t *testing.T) {
	if !Transport(time.Second).DisableKeepAlives {
		t.Error("keep-alives must be off: a pooled connection outlives the check that opened it")
	}
}

// It never follows a redirect. The hop belongs to internal/fetch, which
// re-resolves and re-decides it; a client that followed here would make a
// request no decision preceded.
func TestTheClientDoesNotFollowRedirects(t *testing.T) {
	var second atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		second.Add(1)
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/next", http.StatusFound)
	}))
	defer srv.Close()

	srvHost, _ := hostPort(t, srv)
	targetHost, _ := hostPort(t, target)
	ctx := With(context.Background(), srvHost, addrsOf(t, srvHost))
	ctx = With(ctx, targetHost, addrsOf(t, targetHost))

	c := Client(3 * time.Second)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("the first hop must succeed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the 302 returned rather than followed", resp.StatusCode)
	}
	if n := second.Load(); n != 0 {
		// Both hosts are pinned here on purpose: if the pin were the only
		// thing stopping the follow, this case would pass for the wrong reason
		// and the CheckRedirect could be deleted without a test noticing.
		t.Errorf("the redirect target was reached %d times", n)
	}
}
