package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// pdp is a stand-in for Wardryx that answers exactly what a test tells it to,
// and records what it was asked.
//
// A fake rather than a mock of our own client: the thing worth testing is what
// this package does with a real HTTP answer, and a fake that agrees with our
// own reading of the contract would agree with our mistakes too.
type pdp struct {
	decision string
	version  string
	reason   string
	status   int
	body     string
	calls    atomic.Int64
	lastReq  atomic.Value // decideRequestDTO
}

func (p *pdp) start(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		var dto decideRequestDTO
		_ = json.NewDecoder(r.Body).Decode(&dto)
		p.lastReq.Store(dto)
		if p.status != 0 && p.status != http.StatusOK {
			w.WriteHeader(p.status)
			_, _ = w.Write([]byte(p.body))
			return
		}
		_ = json.NewEncoder(w).Encode(decideResponseDTO{
			Decision:      p.decision,
			PolicyVersion: p.version,
			Reason:        p.reason,
		})
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "test-key", time.Second)
}

func TestAnAllowIsAnAllowAndADenyIsADeny(t *testing.T) {
	allow := (&pdp{decision: "allow", version: "v1"}).start(t)
	if a := allow.Decide(context.Background(), Request{AgentID: "agent://a.example/b", RunID: "r", Host: "example.com"}); !a.Allowed || a.Unreachable {
		t.Fatalf("got %+v, want allowed", a.PolicyAnswer)
	}
	deny := (&pdp{decision: "deny", version: "v1", reason: "not in allow_domains"}).start(t)
	a := deny.Decide(context.Background(), Request{AgentID: "agent://a.example/b", RunID: "r", Host: "evil.example"})
	if a.Allowed || a.Unreachable {
		t.Fatalf("got %+v, want a plain deny", a.PolicyAnswer)
	}
	if !strings.Contains(a.Reason, "allow_domains") {
		t.Errorf("the PDP's own reason must survive: %q", a.Reason)
	}
}

// CLAUDE.md invariant 7. Every way of not getting an answer is a refusal, and
// it is Unreachable rather than a deny, because those are different facts.
func TestEveryWayOfNotGettingAnAnswerIsUnreachableAndNeverADeny(t *testing.T) {
	cases := []struct {
		name string
		c    func(t *testing.T) *Client
		want string
	}{
		{"the plane is down", func(t *testing.T) *Client {
			return New("http://127.0.0.1:1", "k", 200*time.Millisecond)
		}, "could not be reached"},
		{"our credential is wrong", func(t *testing.T) *Client {
			return (&pdp{status: http.StatusUnauthorized, body: "unauthorized"}).start(t)
		}, "HTTP 401"},
		{"the plane is unwell", func(t *testing.T) *Client {
			return (&pdp{status: http.StatusInternalServerError, body: "boom"}).start(t)
		}, "HTTP 500"},
		{"a verdict this build does not know", func(t *testing.T) *Client {
			return (&pdp{decision: "maybe", version: "v1"}).start(t)
		}, "does not know"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := c.c(t).Decide(context.Background(), Request{AgentID: "agent://a.example/b", RunID: "r", Host: "example.com"})
			if !a.Unreachable {
				t.Fatalf("got %+v, want Unreachable", a.PolicyAnswer)
			}
			if a.Allowed {
				t.Fatal("an answer nobody gave must never read as an allow")
			}
			if !strings.Contains(a.Reason, c.want) {
				t.Errorf("the reason must say what happened, got %q", a.Reason)
			}
		})
	}
}

// A hold means a human decides, and nobody is going to for a subresource on a
// page an agent is reading right now. Refused, and named as a hold so the
// reason does not read as a policy that forbids the destination.
func TestAHoldIsRefusedAndSaysItWasAHold(t *testing.T) {
	c := (&pdp{decision: "hold", version: "v1", reason: "over require_human_above_usd"}).start(t)
	a := c.Decide(context.Background(), Request{AgentID: "agent://a.example/b", RunID: "r", Host: "example.com"})
	if a.Allowed {
		t.Fatal("a hold must not fetch")
	}
	if a.Unreachable {
		t.Fatal("a hold is a decision somebody made; it is not an unreachable plane")
	}
	if !strings.Contains(a.Reason, "held") {
		t.Errorf("the reason must say it was held rather than forbidden: %q", a.Reason)
	}
}

// CLAUDE.md invariant 6. This plane does not present a claimed identity, so
// having none is a refusal here rather than a request with a guess in it.
func TestWithNoAuthenticatedIdentityNothingIsEvenAsked(t *testing.T) {
	p := &pdp{decision: "allow", version: "v1"}
	c := p.start(t)
	a := c.Decide(context.Background(), Request{AgentID: "", RunID: "r", Host: "example.com"})
	if !a.Unreachable || a.Allowed {
		t.Fatalf("got %+v, want a refusal", a.PolicyAnswer)
	}
	if p.calls.Load() != 0 {
		t.Errorf("the policy plane must not be asked at all, it was asked %d times", p.calls.Load())
	}
}

func TestTheHostIsDeclaredAsTheDomainTheActionWouldReach(t *testing.T) {
	p := &pdp{decision: "allow", version: "v1"}
	c := p.start(t)
	c.Decide(context.Background(), Request{AgentID: "agent://a.example/b", RunID: "r", Host: "img.example.com", Tool: "browse"})
	got := p.lastReq.Load().(decideRequestDTO)
	if len(got.Domains) != 1 || got.Domains[0] != "img.example.com" {
		t.Errorf("domains = %v, want the one host being asked about", got.Domains)
	}
	if len(got.ToolNames) != 1 || got.ToolNames[0] != "browse" {
		t.Errorf("tool_names = %v", got.ToolNames)
	}
}

// ------------------------------------------------------------------- the memo

func TestOneHostIsAskedAboutOnce(t *testing.T) {
	p := &pdp{decision: "allow", version: "v1"}
	m := NewMemo(p.start(t), "agent://a.example/b", "r", "browse")
	for i := 0; i < 5; i++ {
		if a := m.Host(context.Background(), "cdn.example.com"); !a.Allowed {
			t.Fatalf("iteration %d: %+v", i, a.PolicyAnswer)
		}
	}
	if p.calls.Load() != 1 {
		t.Errorf("the plane was asked %d times about one host, want 1", p.calls.Load())
	}
	asked, reused := m.Counts()
	if asked != 1 || reused != 4 {
		t.Errorf("asked=%d reused=%d, want 1 and 4", asked, reused)
	}
}

// A policy set that changes mid-page must not leave half the page decided
// under the old rules, which is the outcome nobody could explain afterwards.
func TestAPolicySetThatMovesMidFetchDiscardsWhatWasRemembered(t *testing.T) {
	p := &pdp{decision: "allow", version: "v1"}
	m := NewMemo(p.start(t), "agent://a.example/b", "r", "browse")

	m.Host(context.Background(), "a.example.com")
	m.Host(context.Background(), "a.example.com") // remembered
	if p.calls.Load() != 1 {
		t.Fatalf("setup: asked %d times", p.calls.Load())
	}

	p.version = "v2" // the rules move
	m.Host(context.Background(), "b.example.com")

	// a.example.com was decided under v1 and must be asked again.
	m.Host(context.Background(), "a.example.com")
	if p.calls.Load() != 3 {
		t.Errorf("asked %d times, want 3: the version moved, so v1's answers are gone", p.calls.Load())
	}
}

// A blip must not become a whole page of refusals with no way to tell them
// apart afterwards.
func TestAnUnreachablePlaneIsNeverRemembered(t *testing.T) {
	p := &pdp{status: http.StatusInternalServerError, body: "boom"}
	c := p.start(t)
	m := NewMemo(c, "agent://a.example/b", "r", "browse")

	for i := 0; i < 3; i++ {
		if a := m.Host(context.Background(), "example.com"); !a.Unreachable {
			t.Fatalf("iteration %d: want unreachable, got %+v", i, a.PolicyAnswer)
		}
	}
	if p.calls.Load() != 3 {
		t.Errorf("asked %d times, want 3: an outage is retried, not cached", p.calls.Load())
	}
	if _, reused := m.Counts(); reused != 0 {
		t.Errorf("reused=%d, want 0", reused)
	}
}

func TestADenyIsRememberedJustAsAnAllowIs(t *testing.T) {
	p := &pdp{decision: "deny", version: "v1", reason: "no"}
	m := NewMemo(p.start(t), "agent://a.example/b", "r", "browse")
	for i := 0; i < 3; i++ {
		if a := m.Host(context.Background(), "tracker.example"); a.Allowed {
			t.Fatal("a remembered deny must stay a deny")
		}
	}
	if p.calls.Load() != 1 {
		t.Errorf("asked %d times, want 1", p.calls.Load())
	}
}
