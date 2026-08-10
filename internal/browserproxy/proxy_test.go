package browserproxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// allowAll decides yes and hands back one address, which the fixture dialer
// then ignores. The decision is real; only the socket is redirected.
func allowAll(addr string) *Proxy {
	return &Proxy{
		Decide: DeciderFunc(func(context.Context, string, string) ([]netip.Addr, decide.Decision) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, decide.Decision{}
		}),
		Dial: fixtureDial(addr),
	}
}

func denyAll() *Proxy {
	return &Proxy{
		Decide: DeciderFunc(func(context.Context, string, string) ([]netip.Addr, decide.Decision) {
			return nil, decide.Decision{Verdict: decide.DenyPolicy, Reason: "the fixture policy said no"}
		}),
	}
}

// fixtureDial sends every checked address at one real listener, so a test can
// count what actually left while the decision above it runs for real.
func fixtureDial(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}

func start(t *testing.T, p *Proxy) *http.Client {
	t.Helper()
	addr, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	pu, _ := url.Parse("http://" + addr)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(pu),
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // fixture cert
		},
	}
}

// The property the package exists for, on the plaintext path: a destination
// the plane refused is not reached, and the browser is told why rather than
// being handed a dead socket.
func TestARefusedDestinationIsNeverReachedOverPlainHTTP(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	p := denyAll()
	p.Dial = fixtureDial(strings.TrimPrefix(srv.URL, "http://"))
	c := start(t, p)

	resp, err := c.Get("http://tracker.example/pixel.gif")
	if err != nil {
		t.Fatalf("the refusal must be an answer, not a broken connection: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get("X-Scopyx-Refused") == "" {
		t.Error("the refusal must be distinguishable from the site's own 403")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the destination was reached %d times despite the refusal", n)
	}
}

// And the same on the tunnelled path, which is the one that matters more: for
// https the proxy sees a CONNECT and nothing else, and it must still refuse
// before a byte of TLS is exchanged.
func TestARefusedDestinationIsNeverReachedOverCONNECT(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	p := denyAll()
	p.Dial = fixtureDial(strings.TrimPrefix(srv.URL, "https://"))
	c := start(t, p)

	_, err := c.Get("https://tracker.example/pixel.gif")
	if err == nil {
		t.Fatal("a refused CONNECT must not become a working tunnel")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the destination was reached %d times despite the refusal", n)
	}
}

// An allowed one goes through, so the two refusals above are the decider
// working rather than the proxy being broken.
func TestAnAllowedDestinationIsReachedAndTheAnswerComesBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/page" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		_, _ = io.WriteString(w, "the page itself")
	}))
	defer srv.Close()

	c := start(t, allowAll(strings.TrimPrefix(srv.URL, "http://")))
	resp, err := c.Get("http://allowed.example/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "the page itself" {
		t.Errorf("body = %q", body)
	}
}

// The same over TLS, end to end, which also proves the tunnel does not lose
// bytes the client pipelined behind the CONNECT.
func TestAnAllowedTunnelCarriesTLSEndToEnd(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "through the tunnel")
	}))
	defer srv.Close()

	c := start(t, allowAll(strings.TrimPrefix(srv.URL, "https://")))
	resp, err := c.Get("https://allowed.example/page")
	if err != nil {
		t.Fatalf("an allowed CONNECT must carry TLS: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "through the tunnel" {
		t.Errorf("body = %q", body)
	}
}

// The proxy dials the address it was GIVEN, never the name it was handed. A
// browser resolves for itself and a proxy resolving again would put the second
// lookup straight back in, which is the hole internal/pin exists to close.
func TestItDialsTheCheckedAddressAndNeverResolvesTheNameItself(t *testing.T) {
	var reached atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Add(1)
	}))
	defer srv.Close()

	var asked []netip.Addr
	p := &Proxy{
		Decide: DeciderFunc(func(context.Context, string, string) ([]netip.Addr, decide.Decision) {
			return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, decide.Decision{}
		}),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			if a, err := netip.ParseAddr(host); err == nil {
				asked = append(asked, a)
			}
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(srv.URL, "http://"))
		},
	}
	c := start(t, p)
	resp, err := c.Get("http://localhost/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if len(asked) != 1 || asked[0].String() != "198.51.100.7" {
		t.Errorf("the dial went to %v, want the address the decider returned", asked)
	}
	if reached.Load() != 1 {
		t.Errorf("the fixture saw %d requests, want 1", reached.Load())
	}
}

// Every attempt is counted, including the refused ones. A count of only what
// succeeded would make a heavily blocked page look like a quiet one, which is
// the same silent-zero fault the fidelity block exists to prevent.
func TestRefusedRequestsAreCountedAndNotSilentlyDropped(t *testing.T) {
	p := denyAll()
	c := start(t, p)

	for _, u := range []string{"http://a.example/one", "http://b.example/two"} {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	got := p.Requests()
	if len(got) != 2 {
		t.Fatalf("recorded %d requests, want 2: %+v", len(got), got)
	}
	for _, s := range got {
		if !s.Blocked {
			t.Errorf("%s was refused and must be recorded as blocked", s.URL)
		}
	}
}

// Empty is not nil. One layer up, nil means "this backend cannot report
// subresources" and empty means "the page asked for nothing", and a proxy that
// returned nil for a quiet page would claim the weaker guarantee.
func TestAQuietPageReportsAnEmptyListRatherThanNil(t *testing.T) {
	p := allowAll("127.0.0.1:1")
	if _, err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if got := p.Requests(); got == nil {
		t.Error("Requests must be empty rather than nil: nil means nobody knows")
	}
}

// A proxy with no decider refuses. A nil decider is a misconfiguration, and
// this plane fails closed, so the one thing it must not do is pass everything.
func TestANilDeciderRefusesRatherThanAllows(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	p := &Proxy{Dial: fixtureDial(strings.TrimPrefix(srv.URL, "http://"))}
	c := start(t, p)
	resp, err := c.Get("http://anything.example/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 from a proxy with no decider", resp.StatusCode)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("a proxy with no decider reached the destination %d times", n)
	}
}

// Allowed with nothing to dial is a decider bug, and the tempting repair is to
// resolve the name here. That would put the second lookup back and undo the
// point of the arrangement, so it refuses instead.
func TestAllowedWithNoAddressIsRefusedRatherThanResolvedHere(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	p := &Proxy{
		Decide: DeciderFunc(func(context.Context, string, string) ([]netip.Addr, decide.Decision) {
			return nil, decide.Decision{} // allowed, and nothing to dial
		}),
		Dial: fixtureDial(strings.TrimPrefix(srv.URL, "http://")),
	}
	c := start(t, p)
	resp, err := c.Get("http://allowed.example/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the destination was reached %d times with no checked address", n)
	}
}

// Proxy-Authorization must not travel upstream. A proxy that forwarded it
// would hand the site the arrangement between the browser and this plane.
func TestHopByHopHeadersDoNotReachTheSite(t *testing.T) {
	seen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := start(t, allowAll(strings.TrimPrefix(srv.URL, "http://")))
	req, _ := http.NewRequest(http.MethodGet, "http://allowed.example/", nil)
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	req.Header.Set("X-Kept", "yes")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	h := <-seen
	if h.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization reached the site")
	}
	if h.Get("X-Kept") != "yes" {
		t.Error("an ordinary header must pass through unchanged")
	}
}

// The scheme the decider is asked about is the one the request actually uses.
// A CONNECT decided as http would be checked against the wrong scheme rule.
func TestTheDeciderIsToldTheRealScheme(t *testing.T) {
	got := make(chan string, 2)
	p := &Proxy{
		Decide: DeciderFunc(func(_ context.Context, scheme, _ string) ([]netip.Addr, decide.Decision) {
			got <- scheme
			return nil, decide.Decision{Verdict: decide.DenyPolicy, Reason: "counted, not allowed"}
		}),
	}
	c := start(t, p)

	resp, _ := c.Get("http://a.example/")
	if resp != nil {
		resp.Body.Close()
	}
	if s := <-got; s != "http" {
		t.Errorf("plain request decided as %q", s)
	}

	_, _ = c.Get("https://b.example/")
	if s := <-got; s != "https" {
		t.Errorf("CONNECT decided as %q", s)
	}
}
