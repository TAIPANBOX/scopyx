package main

import (
	"context"
	"encoding/json"
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
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/mcp"
	"github.com/TAIPANBOX/scopyx/internal/policy"
	"github.com/TAIPANBOX/scopyx/internal/record"
	"github.com/TAIPANBOX/scopyx/internal/robots"
)

// # WHY THIS TEST NEEDS A DIALER OF ITS OWN
//
// Every httptest server is on loopback, and `decide` refuses loopback, which is
// correct and is one of the controls this component exists for. So an end-to-end
// test either removes the address check, which would be testing the pipeline
// with its most important refusal taken out, or it keeps the check and arranges
// for the connection to arrive somewhere a test can observe.
//
// This does the second. The resolver answers with a public address, so `decide`
// sees exactly what it would see in production and either allows or refuses on
// the real rules. The transport then dials the fixture regardless of address,
// so the bytes go somewhere a test can assert about. The decision is real; only
// the socket is redirected.
//
// The fixtures are plain HTTP for the same reason: `decide` treats http and
// https identically, so a TLS handshake against a test server would add a
// certificate to arrange and would test nothing this file is about.
type publicResolver struct{}

func (publicResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

// metadataResolver answers with the cloud metadata endpoint, which no policy
// may permit.
type metadataResolver struct{}

func (metadataResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
}

type harness struct {
	mcpSrv     *httptest.Server
	target     *httptest.Server
	hits       chan string
	journal    string
	robotsBody atomic.Value
}

// robots sets what the fixture serves at /robots.txt. Unset is a 404, which is
// a reading rather than a failure.
func (h *harness) robots(body string) { h.robotsBody.Store(body) }

// paths drains what the target was asked for within d.
func (h *harness) paths(t *testing.T, d time.Duration) []string {
	t.Helper()
	var out []string
	deadline := time.After(d)
	for {
		select {
		case p := <-h.hits:
			out = append(out, p)
		case <-deadline:
			return out
		}
	}
}

// newHarness stands up the whole plane: a policy plane, a target web server,
// the real passthrough backend, the real journal and the real MCP surface.
func newHarness(t *testing.T, decision string, res interface {
	Resolve(context.Context, string) ([]netip.Addr, error)
}) *harness {
	t.Helper()

	h := &harness{hits: make(chan string, 16)}

	h.target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case h.hits <- r.URL.Path:
		default:
		}
		if r.URL.Path == "/robots.txt" {
			body := h.robotsBody.Load()
			if body == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = io.WriteString(w, body.(string))
			return
		}
		_, _ = io.WriteString(w, "the page the agent asked for")
	}))
	t.Cleanup(h.target.Close)

	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision": decision, "policy_version": "v1", "reason": "fixture policy",
		})
	}))
	t.Cleanup(pdp.Close)

	pass := backend.NewPassthrough(1<<20, 3*time.Second)
	// The decision above ran on the resolver's answer; this only moves the
	// socket, so the fixture can see what actually left.
	targetAddr := strings.TrimPrefix(h.target.URL, "http://")
	pass.HTTP.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, targetAddr)
		},
	}

	h.journal = filepath.Join(t.TempDir(), "events.ndjson")
	j, err := record.Open(h.journal, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })

	// The robots client shares the backend's transport, which is the same
	// arrangement main.go makes: robots.txt is fetched from the origin that
	// was just decided, over the same route the fetch itself will take.
	g := &governed{
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		robots:   robots.New(robots.ModeReport, 0, &http.Client{Timeout: 3 * time.Second, Transport: pass.HTTP.Transport}),
		backend:  pass,
		pdp:      policy.New(pdp.URL, "k", time.Second),
		journal:  j,
		limits:   decide.Limits{MaxRedirects: 5, MaxBodyBytes: 1 << 20},
		cap:      newHourlyCap(100),
		resolver: res,
	}

	h.mcpSrv = httptest.NewServer(&mcp.Server{
		Keys:    mcp.ParseKeys("k1=agent://acme.example/support-bot"),
		Fetcher: g,
		RunID:   "run-e2e",
	})
	t.Cleanup(h.mcpSrv.Close)
	return h
}

func (h *harness) call(t *testing.T, key, url string) map[string]any {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url",
		"arguments":{"url":"` + url + `"}}}`
	req, _ := http.NewRequest(http.MethodPost, h.mcpSrv.URL, strings.NewReader(body))
	if key != "" {
		req.Header.Set(mcp.ClientKeyHeader, key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (h *harness) events(t *testing.T) []event.Event {
	t.Helper()
	evs, err := event.ReadFile(h.journal)
	if err != nil {
		t.Fatalf("reading the journal: %v", err)
	}
	return evs
}

// WP6's acceptance: the standalone path is a TESTED path rather than a README
// claim. No broker, this plane's own door, its own Wardryx call, its own
// record.
func TestAnAllowedFetchGoesEndToEndAndIsRecorded(t *testing.T) {
	h := newHarness(t, "allow", publicResolver{})

	out := h.call(t, "k1", "http://example.com/report")

	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", out)
	}
	if res["isError"] == true {
		t.Fatalf("the fetch was refused: %v", res["content"])
	}
	if !strings.Contains(firstText(t, res), "the page the agent asked for") {
		t.Errorf("the body did not come back: %v", res["content"])
	}

	// The target sees TWO requests now: its own robots.txt, then the page.
	// Asserted as a set rather than in order, because the order is this
	// plane's business and the test should not pin it.
	seen := h.paths(t, 2*time.Second)
	var gotPage bool
	for _, p := range seen {
		if p == "/report" {
			gotPage = true
		}
	}
	if !gotPage {
		t.Fatalf("the target was never asked for the page, saw %v", seen)
	}

	evs := h.events(t)
	if len(evs) != 1 {
		t.Fatalf("want one event, got %d", len(evs))
	}
	if evs[0].Type != record.TypeFetch {
		t.Errorf("type = %q", evs[0].Type)
	}
	if evs[0].AgentID != "agent://acme.example/support-bot" {
		t.Errorf("agent_id = %q, want the identity the credential carries", evs[0].AgentID)
	}
	// Invariant 10, end to end rather than only in the unit test.
	if raw, _ := os.ReadFile(h.journal); strings.Contains(string(raw), "/report") {
		t.Error("the full URL reached the record")
	}
}

// The refusal path, end to end, asserted against what the TARGET saw. An
// outcome assertion would pass equally well if the fetch happened and the
// answer were discarded.
func TestAPolicyRefusalNeverReachesTheTargetAndIsRecorded(t *testing.T) {
	h := newHarness(t, "deny", publicResolver{})

	out := h.call(t, "k1", "http://example.com/secret")

	res, _ := out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("want a refusal, got %v", out)
	}
	if txt := firstText(t, res); !strings.Contains(txt, "deny_policy") {
		t.Errorf("the agent must be told which refusal it was, got %q", txt)
	}

	select {
	case path := <-h.hits:
		t.Fatalf("the target was reached anyway, at %q", path)
	case <-time.After(300 * time.Millisecond):
	}

	evs := h.events(t)
	if len(evs) != 1 || evs[0].Type != record.TypeBlocked {
		t.Fatalf("want one web_blocked event, got %+v", evs)
	}
	if evs[0].Severity != "high" {
		t.Errorf("severity = %q, want high", evs[0].Severity)
	}
}

// Invariant 7. An unreachable policy plane is a DIFFERENT refusal from a policy
// that said no, and collapsing them sends somebody to repair a machine that is
// fine.
func TestAnUnreachablePolicyPlaneFailsClosedAndSaysWhichRefusalItWas(t *testing.T) {
	h := newHarness(t, "allow", publicResolver{})
	// Point the plane at nothing.
	h.mcpSrv.Config.Handler.(*mcp.Server).Fetcher.(*governed).pdp =
		policy.New("http://127.0.0.1:1", "k", 200*time.Millisecond)

	out := h.call(t, "k1", "http://example.com/x")
	res, _ := out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("an unreachable policy plane must refuse, got %v", out)
	}
	txt := firstText(t, res)
	if !strings.Contains(txt, "deny_policy_unreachable") {
		t.Errorf("the two refusals must be distinguishable, got %q", txt)
	}

	select {
	case path := <-h.hits:
		t.Fatalf("the target was reached with no decision, at %q", path)
	case <-time.After(300 * time.Millisecond):
	}
}

// A name that answers with the cloud metadata endpoint. The policy says allow;
// it is refused anyway, because the policy language talks about domains an
// agent may reach and was never written to contemplate 169.254.169.254.
func TestAnAllowedDomainResolvingToTheMetadataEndpointIsStillRefused(t *testing.T) {
	h := newHarness(t, "allow", metadataResolver{})

	out := h.call(t, "k1", "http://harmless-looking.example/x")
	res, _ := out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("want a refusal, got %v", out)
	}
	if txt := firstText(t, res); !strings.Contains(txt, "deny_address") {
		t.Errorf("got %q, want an address refusal", txt)
	}

	select {
	case path := <-h.hits:
		t.Fatalf("the target was reached anyway, at %q", path)
	case <-time.After(300 * time.Millisecond):
	}
}

// Invariant 8. The cap is finite by default and an uncapped deployment needs a
// deliberate variable.
func TestTheHourlyCapIsFiniteByDefaultAndRefusesWhenSpent(t *testing.T) {
	c := newHourlyCap(2)
	// Bound to names rather than written as `!c.take() || !c.take()`. That form
	// short-circuits, so a first call returning false would skip the second and
	// the assertion below would then be testing the SECOND take rather than the
	// third, passing while the cap was off by one. staticcheck flagged it, and
	// it was right for a better reason than the one it gives.
	first, second := c.take(), c.take()
	if !first || !second {
		t.Fatal("the first two must be allowed")
	}
	if c.take() {
		t.Error("the third must be refused: the cap is spent")
	}

	if !newHourlyCap(0).take() {
		t.Error("zero means uncapped, which startup warns about")
	}
	if defaultFetchesPerHour <= 0 {
		t.Error("the default must be finite, or a backend that becomes metered starts spending")
	}
}

// A malformed bound is refused rather than replaced by the default, which would
// be a bound the operator believes they set.
func TestAMalformedBoundIsRefusedRatherThanSilentlyDefaulted(t *testing.T) {
	t.Setenv("SCOPYX_MAX_BYTES", "32MB")
	defer func() {
		if recover() == nil {
			t.Error("a malformed bound must not become the default silently")
		}
	}()
	_ = envInt("SCOPYX_MAX_BYTES", defaultMaxBodyBytes)
}

func firstText(t *testing.T, res map[string]any) string {
	t.Helper()
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("no content in %v", res)
	}
	first, _ := content[0].(map[string]any)
	s, _ := first["text"].(string)
	return s
}

// ---------------------------------------------------------------------------
// robots.txt, end to end
// ---------------------------------------------------------------------------

// The claim invariant 9 made and nothing held until 2026-08-10. Asserted
// against what the TARGET saw, because "the fetch was refused" is equally true
// when the fetch happened and the answer was discarded.
func TestADisallowedPathIsRefusedAndTheTargetNeverSeesIt(t *testing.T) {
	h := newHarness(t, "allow", publicResolver{})
	h.robots("User-agent: *\nDisallow: /private/\n")

	out := h.call(t, "k1", "http://example.com/private/report")
	res, _ := out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("a disallowed path must be refused, got %v", out)
	}
	if txt := firstText(t, res); !strings.Contains(txt, "deny_robots") {
		t.Errorf("the agent must be told which refusal it was, got %q", txt)
	}

	// The target saw the robots.txt request and nothing else.
	seen := h.paths(t, 400*time.Millisecond)
	for _, p := range seen {
		if p != "/robots.txt" {
			t.Errorf("the target was asked for %q despite its own robots.txt", p)
		}
	}
}

// A site's preference is asked AFTER the operator's policy, so a destination
// the operator forbids never learns it was asked about.
func TestADomainThePolicyRefusesIsNotEvenAskedForItsRobots(t *testing.T) {
	h := newHarness(t, "deny", publicResolver{})
	h.robots("User-agent: *\nDisallow: /private/\n")

	h.call(t, "k1", "http://example.com/anything")
	if seen := h.paths(t, 400*time.Millisecond); len(seen) != 0 {
		t.Errorf("a policy-refused domain was contacted anyway, at %v", seen)
	}
}

// An allowed path still goes through.
func TestAPathRobotsAllowsIsFetched(t *testing.T) {
	h := newHarness(t, "allow", publicResolver{})
	h.robots("User-agent: *\nDisallow: /private/\n")

	out := h.call(t, "k1", "http://example.com/public/report")
	res, _ := out["result"].(map[string]any)
	if res["isError"] == true {
		t.Fatalf("an allowed path must be fetched: %v", res["content"])
	}
}
