package fetch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/pin"
	"github.com/TAIPANBOX/scopyx/internal/policy"
	"github.com/TAIPANBOX/scopyx/internal/robots"
)

// The refusals that happen before a destination is even decided, and the
// answers a backend can give that are not a plain page. Each refusal is
// asserted against what the backend was asked, because "refused" is equally
// true of a fetch that went out and was discarded.

// countingResolver counts lookups and can fail them.
type countingResolver struct {
	asked int
	err   error
}

func (r *countingResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	r.asked++
	if r.err != nil {
		return nil, r.err
	}
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

func hostDeps(t *testing.T, b backend.Backend, res Resolver) Deps {
	t.Helper()
	return Deps{
		Backend:  b,
		Resolver: res,
		Memo:     policy.NewMemo(newHostPDP(t), "agent://acme.example/a", "run-1", "browse"),
		Limits:   decide.Limits{MaxRedirects: 5},
	}
}

// A URL that does not parse has no host to decide about. It is refused as a
// scheme refusal, nothing is looked up, and the backend is never asked.
func TestAURLThatDoesNotParseIsRefusedBeforeAnythingIsResolved(t *testing.T) {
	b := &redirectingBackend{}
	res := &countingResolver{}

	_, err := Do(context.Background(), hostDeps(t, b, res), backend.Request{URL: "https://[::1"})
	r, ok := AsRefusal(err)
	if !ok || r.Verdict() != decide.DenyScheme {
		t.Fatalf("got %v, want a deny_scheme refusal", err)
	}
	if !strings.HasPrefix(err.Error(), "deny_scheme: the URL could not be parsed") {
		t.Errorf("the refusal must read as its verdict then its reason, got %q", err)
	}
	if res.asked != 0 || len(b.seen()) != 0 {
		t.Errorf("an unparsable URL was resolved %d time(s) and fetched %v", res.asked, b.seen())
	}
}

// A name that does not resolve is refused on the address rules, and the
// backend never gets the chance to resolve it some other way.
func TestAHostThatCannotBeResolvedIsRefusedAndNeverFetched(t *testing.T) {
	b := &redirectingBackend{}
	res := &countingResolver{err: errors.New("no such host")}

	_, err := Do(context.Background(), hostDeps(t, b, res), backend.Request{URL: "https://gone.example/x"})
	r, ok := AsRefusal(err)
	if !ok || r.Verdict() != decide.DenyAddress {
		t.Fatalf("got %v, want a deny_address refusal", err)
	}
	if !strings.Contains(r.Decision.Reason, "no such host") {
		t.Errorf("the reason must carry the lookup failure, got %q", r.Decision.Reason)
	}
	if len(b.seen()) != 0 {
		t.Errorf("an unresolvable host was fetched: %v", b.seen())
	}
}

// Invariant 9 in this package: a path the site's robots.txt disallows is
// refused after the policy allowed it and before the backend is asked. The
// robots.txt itself travels over the pinned client, as in main.go.
func TestAPathRobotsDisallowsIsRefusedBeforeTheBackend(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = io.WriteString(w, "User-agent: *\nDisallow: /private\n")
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(site.Close)
	addr := strings.TrimPrefix(site.URL, "http://")
	pinned := pin.ClientWith(2*time.Second, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	})

	b := &redirectingBackend{}
	d := hostDeps(t, b, &countingResolver{})
	d.Robots = robots.New(robots.ModeReport, time.Minute, pinned)

	_, err := Do(context.Background(), d, backend.Request{URL: "http://site.example/private/report"})
	r, ok := AsRefusal(err)
	if !ok || r.Verdict() != decide.DenyRobots {
		t.Fatalf("got %v, want a deny_robots refusal", err)
	}
	if len(b.seen()) != 0 {
		t.Errorf("a disallowed path reached the backend: %v", b.seen())
	}

	res, err := Do(context.Background(), d, backend.Request{URL: "http://site.example/public"})
	if err != nil {
		t.Fatalf("a path robots.txt allows must be fetched: %v", err)
	}
	if res.FinalURL != "http://site.example/public" {
		t.Errorf("FinalURL = %q", res.FinalURL)
	}
}

// A redirect whose target does not parse is refused at the hop, and nothing
// is fetched past the page that sent it.
func TestARedirectTargetThatDoesNotParseIsRefusedAtTheHop(t *testing.T) {
	b := &redirectingBackend{route: map[string]string{
		"https://a.example/x": "https://[::1",
	}}
	_, err := Do(context.Background(), hostDeps(t, b, hostResolver{}), backend.Request{URL: "https://a.example/x"})
	r, ok := AsRefusal(err)
	if !ok || r.Verdict() != decide.DenyScheme || !strings.Contains(r.Decision.Reason, "redirect target") {
		t.Fatalf("got %v, want a deny_scheme refusal naming the redirect target", err)
	}
	if got := b.seen(); len(got) != 1 {
		t.Errorf("backend saw %v, want only the page that redirected", got)
	}
}

// scriptedBackend answers one fixed result and error.
type scriptedBackend struct {
	res backend.Result
	err error
}

func (scriptedBackend) Name() string                    { return "scripted" }
func (scriptedBackend) Enforcement() decide.Enforcement { return decide.EnforcementPerRequest }
func (s scriptedBackend) Fetch(context.Context, backend.Request) (backend.Result, error) {
	return s.res, s.err
}

// A backend that refuses AFTER it fetched (the over-bound screenshot) hands
// back what left and how much it captured, beside its own error, so the
// caller can journal egress that happened. One that fetched nothing hands back
// no URL, so the caller journals nothing.
func TestABackendErrorCarriesWhatAlreadyLeftAndNothingWhenNothingDid(t *testing.T) {
	tooBig := errors.New("the screenshot is over the byte bound")
	b := scriptedBackend{
		res: backend.Result{FinalURL: "https://a.example/landed", ContentBytes: 5000, Subresources: []backend.Subresource{}},
		err: tooBig,
	}
	res, err := Do(context.Background(), hostDeps(t, b, hostResolver{}),
		backend.Request{URL: "https://a.example/x", Extract: "screenshot"})
	if !errors.Is(err, tooBig) {
		t.Fatalf("the backend's own error must come back, got %v", err)
	}
	if _, isRefusal := AsRefusal(err); isRefusal {
		t.Error("a backend error is not a policy refusal and must not read as one")
	}
	if res.FinalURL != "https://a.example/landed" {
		t.Errorf("FinalURL = %q, want where the backend actually landed", res.FinalURL)
	}
	if res.Fidelity.ContentBytes != 5000 {
		t.Errorf("ContentBytes = %d, want the 5000 captured and withheld, not len(Body)", res.Fidelity.ContentBytes)
	}
	if res.Fidelity.Extract != "screenshot" {
		t.Errorf("Extract = %q", res.Fidelity.Extract)
	}

	res, err = Do(context.Background(), hostDeps(t, scriptedBackend{err: errors.New("connection refused")}, hostResolver{}),
		backend.Request{URL: "https://a.example/x"})
	if err == nil || res.FinalURL != "" {
		t.Errorf("a backend that fetched nothing must report no URL, got %q (%v)", res.FinalURL, err)
	}
}

// A backend that reports no final URL fetched the one it was asked for, and
// the answer says so rather than carrying an empty address.
func TestAnAnswerWithNoFinalURLIsTheOneAskedFor(t *testing.T) {
	b := scriptedBackend{res: backend.Result{Body: []byte("page"), HTTPStatus: 200, Subresources: []backend.Subresource{}}}
	res, err := Do(context.Background(), hostDeps(t, b, hostResolver{}), backend.Request{URL: "https://a.example/asked"})
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalURL != "https://a.example/asked" {
		t.Errorf("FinalURL = %q, want the URL that was fetched", res.FinalURL)
	}
}
