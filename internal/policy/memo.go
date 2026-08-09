package policy

import (
	"context"
	"sync"
)

// Memo remembers verdicts for the life of ONE fetch.
//
// # WHY THIS IS NOT A CACHE, AND WHY THAT DISTINCTION IS LOAD-BEARING
//
// A page is a navigation plus forty subresources, each a destination the caller
// did not know about when it asked about the page. Wardryx answers one
// destination at a time, so the honest implementation is one decision per
// destination, and the naive one is forty-one HTTP calls for one page.
//
// This asks once per HOST instead, and it is allowed to because Wardryx says
// so about itself: its decision path is deterministic, imports no clock, no
// randomness, no network and no database in its own code, and its first
// invariant is that the same request against the same policy set yields the
// same decision. Reusing an answer inside one fetch is therefore not a
// weakening of the check. It is using a property the other repository gates.
//
// The dependency is real and is written down rather than assumed: if Wardryx
// ever became nondeterministic per call, this would silently start reusing an
// answer that was never going to repeat. That is why the key carries the
// policy version.
//
// # WHAT THE POLICY VERSION IS FOR
//
// A policy set can change while a page is loading. Every answer carries the
// version it was decided under, and a version that moves discards everything
// remembered so far rather than letting a page finish half under the old rules
// and half under the new. Half a page under each is the outcome nobody could
// explain afterwards.
//
// It deliberately does NOT remember refusals across fetches, or across agents.
// A Memo belongs to one fetch by one caller and is thrown away with it.
type Memo struct {
	client *Client
	agent  string
	run    string
	tool   string

	mu      sync.Mutex
	version string
	seen    map[string]Answer
	asked   int
	reused  int
}

// NewMemo starts remembering for one fetch.
func NewMemo(c *Client, agentID, runID, tool string) *Memo {
	return &Memo{
		client: c,
		agent:  agentID,
		run:    runID,
		tool:   tool,
		seen:   map[string]Answer{},
	}
}

// Host asks about one host, or answers from what this fetch already learned.
func (m *Memo) Host(ctx context.Context, host string) Answer {
	m.mu.Lock()
	if a, ok := m.seen[host]; ok {
		m.reused++
		m.mu.Unlock()
		return a
	}
	m.mu.Unlock()

	a := m.client.Decide(ctx, Request{
		AgentID: m.agent,
		RunID:   m.run,
		Host:    host,
		Tool:    m.tool,
	})

	m.mu.Lock()
	defer m.mu.Unlock()
	m.asked++

	// An unreachable answer is never remembered. The plane may come back
	// during this same page, and caching a refusal that was really an outage
	// would turn one blip into a whole page of refusals with no way to tell
	// them apart afterwards.
	if a.Unreachable {
		return a
	}

	if m.version == "" {
		m.version = a.PolicyVersion
	} else if a.PolicyVersion != m.version {
		// The rules moved mid-page. Everything remembered was decided under a
		// set that is no longer in force, so it goes.
		m.seen = map[string]Answer{}
		m.version = a.PolicyVersion
	}
	m.seen[host] = a
	return a
}

// Counts reports how many decisions were asked for and how many were answered
// from what this fetch already knew.
//
// Reported rather than kept private because it is the number that says whether
// the memo is doing anything, and a reader who cannot see it has to take this
// file's word for the argument above.
func (m *Memo) Counts() (asked, reused int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.asked, m.reused
}
