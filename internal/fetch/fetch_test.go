package fetch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/policy"
)

type fixedResolver []string

func (f fixedResolver) Resolve(_ context.Context, _ string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(f))
	for _, s := range f {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

// externalFixture stands in for the operator's own fetching service, and
// COUNTS what it was asked.
//
// The count is the assertion. An outcome test ("the fetch was refused") passes
// just as well when the refusal happens after the remote call, which is the
// exact regression this package exists to prevent, so these tests assert a
// number instead.
type externalFixture struct {
	calls atomic.Int64
	srv   *httptest.Server
}

func newExternalFixture(t *testing.T) *externalFixture {
	t.Helper()
	f := &externalFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"final_url": "https://example.com/x",
			"content":   "hello",
			"status":    200,
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *externalFixture) backend() backend.Backend {
	return backend.NewExternal("fixture", f.srv.URL, "operator-key", time.Second)
}

// newPDP stands up a policy plane that answers a fixed verdict.
func newPDP(t *testing.T, decision string) *policy.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision":       decision,
			"policy_version": "v1",
			"reason":         "fixture",
		})
	}))
	t.Cleanup(srv.Close)
	return policy.New(srv.URL, "k", time.Second)
}

func deps(t *testing.T, b backend.Backend, decision string, addrs ...string) Deps {
	t.Helper()
	if len(addrs) == 0 {
		addrs = []string{"93.184.216.34"}
	}
	return Deps{
		Backend:  b,
		Resolver: fixedResolver(addrs),
		Memo:     policy.NewMemo(newPDP(t, decision), "agent://acme.example/a", "run-1", "browse"),
		Limits:   decide.Limits{MaxRedirects: 5},
	}
}

// WP5's acceptance, and the reason this package exists.
//
// A destination the policy refuses never reaches the operator's own service,
// so it never appears in their bill for it either. Asserted against the
// fixture's call count, not against the outcome.
func TestAPolicyRefusalNeverReachesTheOperatorsOwnService(t *testing.T) {
	ext := newExternalFixture(t)
	d := deps(t, ext.backend(), "deny")

	_, err := Do(context.Background(), d, backend.Request{URL: "https://forbidden.example/x"})
	if err == nil {
		t.Fatal("a denied destination must not fetch")
	}
	r, ok := AsRefusal(err)
	if !ok || r.Verdict() != decide.DenyPolicy {
		t.Fatalf("got %v, want a DenyPolicy refusal", err)
	}
	if n := ext.calls.Load(); n != 0 {
		t.Fatalf("the external service was called %d time(s); a refused fetch must never reach it", n)
	}
}

// The same, for the address rules: they run before the backend too, and they
// run even when the policy plane said yes.
func TestALocalAddressNeverReachesTheOperatorsOwnServiceEither(t *testing.T) {
	ext := newExternalFixture(t)
	d := deps(t, ext.backend(), "allow", "169.254.169.254")

	_, err := Do(context.Background(), d, backend.Request{URL: "https://friendly.example/x"})
	r, ok := AsRefusal(err)
	if !ok || r.Verdict() != decide.DenyAddress {
		t.Fatalf("got %v, want a DenyAddress refusal", err)
	}
	if n := ext.calls.Load(); n != 0 {
		t.Fatalf("the external service was called %d time(s)", n)
	}
}

// CLAUDE.md invariant 7, end to end: an unreachable policy plane refuses, and
// the operator's service is not called on the way past.
func TestAnUnreachablePolicyPlaneStopsTheFetchBeforeTheBackend(t *testing.T) {
	ext := newExternalFixture(t)
	d := Deps{
		Backend:  ext.backend(),
		Resolver: fixedResolver{"93.184.216.34"},
		Memo:     policy.NewMemo(policy.New("http://127.0.0.1:1", "k", 200*time.Millisecond), "agent://acme.example/a", "run-1", "browse"),
	}
	_, err := Do(context.Background(), d, backend.Request{URL: "https://example.com/x"})
	r, ok := AsRefusal(err)
	if !ok || r.Verdict() != decide.DenyPolicyUnreachable {
		t.Fatalf("got %v, want DenyPolicyUnreachable", err)
	}
	if n := ext.calls.Load(); n != 0 {
		t.Fatalf("the external service was called %d time(s) while policy could not be asked", n)
	}
}

func TestAnAllowedFetchReachesTheServiceAndComesBack(t *testing.T) {
	ext := newExternalFixture(t)
	d := deps(t, ext.backend(), "allow")

	res, err := Do(context.Background(), d, backend.Request{URL: "https://example.com/x"})
	if err != nil {
		t.Fatalf("an allowed fetch must succeed: %v", err)
	}
	if string(res.Body) != "hello" {
		t.Errorf("body = %q", res.Body)
	}
	if ext.calls.Load() != 1 {
		t.Errorf("called %d times, want 1", ext.calls.Load())
	}
	if res.Fidelity.Backend != "external:fixture" {
		t.Errorf("the record must name WHICH of the operator's tools fetched it, got %q", res.Fidelity.Backend)
	}
}

// The external backend cannot enforce per subresource, and the result says so
// rather than claiming a control that no code performs.
func TestAnExternalFetchReportsNavigationOnlyEnforcementAndUnknownCounts(t *testing.T) {
	ext := newExternalFixture(t)
	d := deps(t, ext.backend(), "allow")

	res, err := Do(context.Background(), d, backend.Request{URL: "https://example.com/x"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fidelity.Enforcement != decide.EnforcementNavigationOnly {
		t.Errorf("enforcement = %q, want navigation_only: this backend cannot refuse a subresource",
			res.Fidelity.Enforcement)
	}
	for name, got := range map[string]*int{
		"requested": res.Fidelity.SubresourcesRequested,
		"ok":        res.Fidelity.SubresourcesOK,
		"blocked":   res.Fidelity.SubresourcesBlockedByPolicy,
		"failed":    res.Fidelity.SubresourcesFailed,
	} {
		if got != nil {
			t.Errorf("subresources %s = %d, want nil: this backend reports none, which is not the "+
				"same as reporting zero", name, *got)
		}
	}
}

// A backend that DOES report subresources gets real counts, so the nil case
// above is a property of that backend rather than of this package.
type countingBackend struct{ subs []backend.Subresource }

func (countingBackend) Name() string                    { return "counting" }
func (countingBackend) Enforcement() decide.Enforcement { return decide.EnforcementPerRequest }
func (c countingBackend) Fetch(context.Context, backend.Request) (backend.Result, error) {
	return backend.Result{FinalURL: "https://example.com/x", Body: []byte("hi"), HTTPStatus: 200, Subresources: c.subs}, nil
}

func TestABackendThatReportsSubresourcesGetsRealCounts(t *testing.T) {
	b := countingBackend{subs: []backend.Subresource{
		{URL: "a", Status: 200},
		{URL: "b", Blocked: true},
		{URL: "c", Failed: true},
		{URL: "d", Status: 200},
	}}
	d := deps(t, b, "allow")
	res, err := Do(context.Background(), d, backend.Request{URL: "https://example.com/x"})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Fidelity
	if f.SubresourcesRequested == nil || *f.SubresourcesRequested != 4 {
		t.Errorf("requested = %v, want 4", f.SubresourcesRequested)
	}
	if f.SubresourcesOK == nil || *f.SubresourcesOK != 2 {
		t.Errorf("ok = %v, want 2", f.SubresourcesOK)
	}
	if f.SubresourcesBlockedByPolicy == nil || *f.SubresourcesBlockedByPolicy != 1 {
		t.Errorf("blocked = %v, want 1", f.SubresourcesBlockedByPolicy)
	}
	if f.SubresourcesFailed == nil || *f.SubresourcesFailed != 1 {
		t.Errorf("failed = %v, want 1", f.SubresourcesFailed)
	}
	if f.Enforcement != decide.EnforcementPerRequest {
		t.Errorf("enforcement = %q", f.Enforcement)
	}
}

// A page that yielded nothing while something failed is not an answer.
type emptyFailingBackend struct{}

func (emptyFailingBackend) Name() string                    { return "empty" }
func (emptyFailingBackend) Enforcement() decide.Enforcement { return decide.EnforcementPerRequest }
func (emptyFailingBackend) Fetch(context.Context, backend.Request) (backend.Result, error) {
	return backend.Result{
		FinalURL:     "https://example.com/x",
		Body:         nil,
		HTTPStatus:   200,
		Subresources: []backend.Subresource{{URL: "a", Failed: true}},
	}, nil
}

func TestNothingExtractedWithAFailureIsNotHandedBackAsAnAnswer(t *testing.T) {
	d := deps(t, emptyFailingBackend{}, "allow")
	_, err := Do(context.Background(), d, backend.Request{URL: "https://example.com/x"})
	if err == nil {
		t.Fatal("a page that could not be read must not come back as an empty page")
	}
}

// -- the redirect loop ------------------------------------------------------

// hostResolver answers per host, so "the target resolves somewhere else" is a
// case this package can have. With one resolver for every name it cannot.
type hostResolver map[string][]string

func (h hostResolver) Resolve(_ context.Context, host string) ([]netip.Addr, error) {
	out := []netip.Addr{}
	for _, s := range h[host] {
		out = append(out, netip.MustParseAddr(s))
	}
	if len(out) == 0 {
		out = append(out, netip.MustParseAddr("93.184.216.34"))
	}
	return out, nil
}

// redirectingBackend reports hops instead of following them, and RECORDS every
// URL it was asked for.
//
// The record is the assertion throughout this section. "The fetch was refused"
// is equally true when the refusal happened after the request went out, which
// is the regression that matters.
type redirectingBackend struct {
	mu    sync.Mutex
	asked []string
	route map[string]string
}

func (*redirectingBackend) Name() string                    { return "redirecting" }
func (*redirectingBackend) Enforcement() decide.Enforcement { return decide.EnforcementPerRequest }

func (b *redirectingBackend) Fetch(_ context.Context, req backend.Request) (backend.Result, error) {
	b.mu.Lock()
	b.asked = append(b.asked, req.URL)
	b.mu.Unlock()
	res := backend.Result{
		FinalURL:     req.URL,
		Body:         []byte("page"),
		HTTPStatus:   200,
		Subresources: []backend.Subresource{},
	}
	if to, ok := b.route[req.URL]; ok {
		res.RedirectTo = to
		res.HTTPStatus = 302
	}
	return res, nil
}

func (b *redirectingBackend) seen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.asked...)
}

// newHostPDP denies the named hosts and allows everything else.
func newHostPDP(t *testing.T, denied ...string) *policy.Client {
	t.Helper()
	bad := map[string]bool{}
	for _, d := range denied {
		bad[d] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Domains []string `json:"domains"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		decision := "allow"
		for _, d := range in.Domains {
			if bad[d] {
				decision = "deny"
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision": decision, "policy_version": "v1", "reason": "fixture",
		})
	}))
	t.Cleanup(srv.Close)
	return policy.New(srv.URL, "k", time.Second)
}

// The classic allowlist bypass: an allowed host answers 302 to a denied one.
//
// Invisible to any check that evaluates only the URL the caller passed, which
// is why the hop is decided rather than followed.
func TestARedirectToADeniedHostIsRefusedAtTheHopAndNeverRequested(t *testing.T) {
	b := &redirectingBackend{route: map[string]string{
		"https://good.example/a": "https://evil.example/b",
	}}
	d := Deps{
		Backend:  b,
		Resolver: hostResolver{},
		Memo:     policy.NewMemo(newHostPDP(t, "evil.example"), "agent://acme.example/a", "run-1", "browse"),
		Limits:   decide.Limits{MaxRedirects: 5},
	}

	_, err := Do(context.Background(), d, backend.Request{URL: "https://good.example/a"})
	r, ok := AsRefusal(err)
	if !ok {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if r.Verdict() != decide.DenyPolicy {
		t.Errorf("verdict = %v, want DenyPolicy", r.Verdict())
	}
	for _, u := range b.seen() {
		if strings.Contains(u, "evil.example") {
			t.Fatalf("the denied host was requested anyway: %v", b.seen())
		}
	}
}

// A hop whose TARGET resolves inside the deployment. The first host is public
// and perfectly allowed; the answer it gives points at the metadata endpoint.
//
// This is why every hop is re-resolved rather than decided on the first
// lookup's answer.
func TestARedirectTargetIsResolvedAgainAndRefusedOnItsOwnAddress(t *testing.T) {
	b := &redirectingBackend{route: map[string]string{
		"https://good.example/a": "https://sneaky.example/b",
	}}
	d := Deps{
		Backend: b,
		Resolver: hostResolver{
			"good.example":   {"93.184.216.34"},
			"sneaky.example": {"169.254.169.254"},
		},
		Memo:   policy.NewMemo(newHostPDP(t), "agent://acme.example/a", "run-1", "browse"),
		Limits: decide.Limits{MaxRedirects: 5},
	}

	_, err := Do(context.Background(), d, backend.Request{URL: "https://good.example/a"})
	r, ok := AsRefusal(err)
	if !ok {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if r.Verdict() != decide.DenyAddress {
		t.Errorf("verdict = %v, want DenyAddress", r.Verdict())
	}
	if len(b.seen()) != 1 {
		t.Errorf("the backend was asked %v, want only the first hop", b.seen())
	}
}

// An ordinary chain, which is most of the web: http to https, a trailing
// slash, a country redirect. Each hop decided, then followed.
func TestAnAllowedChainIsFollowedAndTheFinalUrlIsTheLastOne(t *testing.T) {
	b := &redirectingBackend{route: map[string]string{
		"https://a.example/1": "https://a.example/2",
		"https://a.example/2": "https://b.example/3",
	}}
	d := Deps{
		Backend:  b,
		Resolver: hostResolver{},
		Memo:     policy.NewMemo(newHostPDP(t), "agent://acme.example/a", "run-1", "browse"),
		Limits:   decide.Limits{MaxRedirects: 5},
	}

	res, err := Do(context.Background(), d, backend.Request{URL: "https://a.example/1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalURL != "https://b.example/3" {
		t.Errorf("FinalURL = %q, want the last hop", res.FinalURL)
	}
	if res.Fidelity.RedirectHops != 2 {
		t.Errorf("RedirectHops = %d, want 2: a reader must see the fetch moved",
			res.Fidelity.RedirectHops)
	}
	if len(b.seen()) != 3 {
		t.Errorf("backend saw %v, want three requests", b.seen())
	}
}

// The configured bound refuses before the plane's own ceiling does.
func TestTheConfiguredRedirectBoundRefusesTheChain(t *testing.T) {
	b := &redirectingBackend{route: map[string]string{
		"https://a.example/1": "https://a.example/2",
		"https://a.example/2": "https://a.example/3",
		"https://a.example/3": "https://a.example/4",
	}}
	d := Deps{
		Backend:  b,
		Resolver: hostResolver{},
		Memo:     policy.NewMemo(newHostPDP(t), "agent://acme.example/a", "run-1", "browse"),
		Limits:   decide.Limits{MaxRedirects: 2},
	}

	_, err := Do(context.Background(), d, backend.Request{URL: "https://a.example/1"})
	r, ok := AsRefusal(err)
	if !ok {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if r.Verdict() != decide.DenyRedirectDepth {
		t.Errorf("verdict = %v, want DenyRedirectDepth", r.Verdict())
	}
}

// A zero MaxRedirects legally means "no policy bound". In a pure function that
// is fine; in a loop it is two servers pointing at each other forever, and a
// fetch that never returns is worse than one that is refused because nothing
// reports it.
func TestAnUnboundedConfigStillCannotSpinForever(t *testing.T) {
	b := &redirectingBackend{route: map[string]string{
		"https://loop.example/x": "https://loop.example/x",
	}}
	d := Deps{
		Backend:  b,
		Resolver: hostResolver{},
		Memo:     policy.NewMemo(newHostPDP(t), "agent://acme.example/a", "run-1", "browse"),
		Limits:   decide.Limits{MaxRedirects: 0},
	}

	done := make(chan error, 1)
	go func() {
		_, err := Do(context.Background(), d, backend.Request{URL: "https://loop.example/x"})
		done <- err
	}()

	select {
	case err := <-done:
		r, ok := AsRefusal(err)
		if !ok {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if r.Verdict() != decide.DenyRedirectDepth {
			t.Errorf("verdict = %v, want DenyRedirectDepth", r.Verdict())
		}
		if !strings.Contains(r.Decision.Reason, "regardless of configured limits") {
			t.Errorf("the reason must say which bound stopped it, got %q", r.Decision.Reason)
		}
		if n := len(b.seen()); n > absoluteMaxRedirects+1 {
			t.Errorf("the backend was asked %d times, past the ceiling of %d",
				n, absoluteMaxRedirects)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Do never returned: an unbounded config is a hang")
	}
}

// A relative Location goes to the host that sent it, not to a bare path that
// would be refused as a scheme.
func TestARelativeRedirectResolvesAgainstTheHostThatSentIt(t *testing.T) {
	b := &redirectingBackend{route: map[string]string{
		"https://a.example/one/two": "../three",
	}}
	d := Deps{
		Backend:  b,
		Resolver: hostResolver{},
		Memo:     policy.NewMemo(newHostPDP(t), "agent://acme.example/a", "run-1", "browse"),
		Limits:   decide.Limits{MaxRedirects: 5},
	}

	res, err := Do(context.Background(), d, backend.Request{URL: "https://a.example/one/two"})
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalURL != "https://a.example/three" {
		t.Errorf("FinalURL = %q, want the relative target resolved against its sender", res.FinalURL)
	}
}
