// Package policy asks Wardryx whether one destination may be reached, and
// turns the answer into something `internal/decide` can use.
//
// The I/O lives here and the decision does not. `internal/decide` is a pure
// function of its arguments, and this package is the edge that feeds it, which
// is what makes every refusal in the pipeline testable without a live policy
// plane.
//
// # WHAT THE CONTRACT ACTUALLY IS, WHICH IS NOT WHAT THE PLAN ASSUMED
//
// `browse-plane-plan.md` says to "hold the allow-set the policy plane returned
// for the navigation". Wardryx returns no such list. Its `DecideResponse`
// carries a decision, a policy version and a reason, and its `allow_domains`
// rule works the other way round: the CALLER declares the destinations an
// action would reach, and the PDP refuses if any of them is outside the
// policy's set.
//
// So there is no set to hold, and a subresource is a destination the caller did
// not know about when it asked about the navigation. Each one is therefore its
// own question. See Memo for why that is not one HTTP call per image.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// Request is one destination, asked about.
//
// AgentID is required by the PDP and must come from an authenticated caller.
// CLAUDE.md invariant 6: `AGENT_PASSPORT_ID` may fill a log line or an event's
// subject, and may never be what is presented here, because a policy carrying
// `deny_if_unattested` would then be satisfied by a string the caller wrote
// for itself. This package cannot check that, and says so rather than implying
// it does: the caller is responsible for where AgentID came from, and the
// server refuses when it has none.
type Request struct {
	AgentID string
	RunID   string
	Host    string
	Tool    string
}

// Client talks to one Wardryx.
type Client struct {
	BaseURL string
	Key     string
	HTTP    *http.Client
}

// New builds a client with a bounded timeout.
//
// Bounded rather than left to the caller because an unbounded wait here is a
// fetch that hangs rather than a fetch that is refused, and this plane's whole
// posture is that a decision it cannot get is a refusal. A hang is a
// fail-closed that never arrives.
func New(baseURL, key string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Client{
		BaseURL: baseURL,
		Key:     key,
		HTTP:    &http.Client{Timeout: timeout},
	}
}

type decideRequestDTO struct {
	AgentID   string   `json:"agent_id"`
	RunID     string   `json:"run_id"`
	ToolNames []string `json:"tool_names,omitempty"`
	Domains   []string `json:"domains,omitempty"`
}

type decideResponseDTO struct {
	Decision      string `json:"decision"`
	PolicyVersion string `json:"policy_version"`
	Reason        string `json:"reason"`
}

// Answer is a PolicyAnswer plus the policy version it was decided under.
//
// The version travels because Memo keys on it: a policy set that changes
// mid-fetch must not have its old verdicts reused for the rest of the page.
type Answer struct {
	decide.PolicyAnswer
	PolicyVersion string
}

// Decide asks about one destination.
//
// It never returns an error. Every failure to get an answer becomes
// `Unreachable`, which `decide.Destination` turns into a refusal, because an
// error return invites a caller to log it and carry on and that is the
// fail-open this plane exists to refuse. The reason carries what went wrong so
// an operator is not left guessing which of the two refusals they are looking
// at.
func (c *Client) Decide(ctx context.Context, req Request) Answer {
	if req.AgentID == "" {
		return unreachable("no authenticated agent identity was available, and this plane " +
			"does not present a claimed one to the policy plane")
	}
	body, err := json.Marshal(decideRequestDTO{
		AgentID:   req.AgentID,
		RunID:     req.RunID,
		ToolNames: []string{req.Tool},
		Domains:   []string{req.Host},
	})
	if err != nil {
		return unreachable(fmt.Sprintf("the decision request could not be encoded: %v", err))
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return unreachable(fmt.Sprintf("the decision request could not be built: %v", err))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.Key)

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return unreachable(fmt.Sprintf("the policy plane could not be reached: %v", err))
	}
	defer resp.Body.Close()

	// Every status that is not 200 is unreachable rather than denied, and the
	// distinction is the point. A 401 means this plane's own credential is
	// wrong, a 500 means the PDP is unwell: neither is a decision anybody
	// made about this fetch, and reporting them as a policy deny would send an
	// operator to read a policy that never ran.
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return unreachable(fmt.Sprintf("the policy plane answered HTTP %d: %s",
			resp.StatusCode, bytes.TrimSpace(snippet)))
	}

	var dto decideResponseDTO
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dto); err != nil {
		return unreachable(fmt.Sprintf("the policy plane's answer could not be read: %v", err))
	}

	switch dto.Decision {
	case "allow":
		return Answer{
			PolicyAnswer:  decide.PolicyAnswer{Allowed: true, Reason: dto.Reason},
			PolicyVersion: dto.PolicyVersion,
		}
	case "deny":
		return Answer{
			PolicyAnswer:  decide.PolicyAnswer{Allowed: false, Reason: dto.Reason},
			PolicyVersion: dto.PolicyVersion,
		}
	case "hold":
		// A hold means a human has to decide, and nobody is going to for a
		// subresource on a page an agent is reading right now. Refused, and
		// named as a hold so the reason does not read as a policy that
		// forbids the destination.
		return Answer{
			PolicyAnswer: decide.PolicyAnswer{
				Allowed: false,
				Reason:  "the policy plane held this for human approval, which a fetch cannot wait for: " + dto.Reason,
			},
			PolicyVersion: dto.PolicyVersion,
		}
	default:
		// A verdict this build does not know is refused rather than read as
		// one it does. The alternative to refusing a decision you have never
		// heard of is treating it as one you have.
		return unreachable(fmt.Sprintf("the policy plane returned a decision this build does not know: %q", dto.Decision))
	}
}

func unreachable(reason string) Answer {
	return Answer{PolicyAnswer: decide.PolicyAnswer{Unreachable: true, Reason: reason}}
}
