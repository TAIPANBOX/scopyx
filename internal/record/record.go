// Package record writes what this plane did into the estate's shared event
// envelope.
//
// # ITS OWN JOURNAL, ONE WRITER
//
// This writes its own file on its own volume and never into the planes' log,
// which is heraldyx's pattern and heraldyx's reason: a component that mounts
// the shared log writable is a component that, once compromised, can corrupt
// the trail it was supposed to be adding to. This plane reaches the internet
// on purpose, which makes it the last one in the estate that should be able to
// rewrite anybody else's record.
//
// # A URL IS PERSONAL DATA, WHICH IS THE RULE THIS FILE IS BUILT AROUND
//
// `https://crm.example/customers/12345?email=jane@example.com` is an address
// and also a name, an identifier and a contact detail. Putting it in the event
// would put personal data somewhere erasure cannot reach, and the event is the
// part designed to be kept.
//
// So the envelope carries the ORIGIN and a hash. The full URL is payload, and
// payload is written only when an operator has asked for it and only behind a
// subject key. Nothing here writes a page body, ever.
package record

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

// Schema and source, per agent-passport SPEC 6.
const (
	Schema = "taipanbox.dev/agent-event/v0.2"
	Source = "scopyx"
)

// Event types, and their fixed severities.
//
// Two, not one per outcome, and named `web_*` rather than `browse_*` because
// this plane governs web egress rather than browsing: the passthrough path
// renders nothing and is still the same fact.
//
// The severities are fixed in code rather than chosen per call. A severity an
// emission site can pick is a severity that drifts between sites, and every
// downstream count of "how many high events" then measures who wrote the call
// rather than what happened.
const (
	TypeFetch   = "web_fetch"
	TypeBlocked = "web_blocked"

	severityFetch   = "low"
	severityBlocked = "high"
)

// Outcome is what happened to one emit, reported back to the caller.
//
// Returned rather than logged inside, because the caller has the logger and
// because a skip that is only ever logged is a skip nobody counts.
type Outcome int

const (
	// Written: one line reached the journal.
	Written Outcome = iota
	// Disabled: no journal is configured. The common case, and free.
	Disabled
	// SkippedNoAgentID: no agent identity, so nothing was written.
	//
	// SPEC 6.1 forbids a fabricated `agent_id`, and the reason is not
	// pedantry: a fallback subject, a "various" agent or the org's own id in
	// that field makes every downstream count wrong and puts a name on an
	// alert that did not do the thing. Skipped and counted is the honest
	// answer, and the count is what stops it being silent.
	SkippedNoAgentID
	// WriteFailed: the journal could not be appended to. Fail-open: a fetch
	// is not refused because its record could not be written, and the caller
	// is told so it can be said out loud.
	WriteFailed
)

// Journal is this plane's own append-only event log.
//
// The zero value is a disabled journal, which is the default and costs one
// branch per emit. An operator who wants records sets a path.
type Journal struct {
	mu      sync.Mutex
	w       *event.ChainedWriter
	skipped int
	failed  int

	// retainURL is P2 in CLAUDE.md's terms: off by default. When off, the
	// full URL never reaches disk at all, only its origin and its hash. The
	// cheapest control over personal data is the one where the data never
	// lands.
	retainURL bool
}

// Open starts a journal at path. An empty path returns a disabled journal
// rather than an error: not wanting records is a configuration, not a fault.
func Open(path string, retainURL bool) (*Journal, error) {
	if strings.TrimSpace(path) == "" {
		return &Journal{}, nil
	}
	w, err := event.NewChainedWriter(path)
	if err != nil {
		return nil, fmt.Errorf("opening the scopyx journal at %s: %w", path, err)
	}
	return &Journal{w: w, retainURL: retainURL}, nil
}

// Close flushes and closes.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.w == nil {
		return nil
	}
	return j.w.Close()
}

// Fetch records one fetch that happened.
func (j *Journal) Fetch(agentID, runID, rawURL, backend, enforcement string, contentBytes int64) Outcome {
	data := j.destination(rawURL)
	data["backend"] = backend
	data["enforcement"] = enforcement
	data["content_bytes"] = contentBytes
	return j.emit(TypeFetch, severityFetch, agentID, runID, data)
}

// Blocked records one fetch that did not happen, and why.
func (j *Journal) Blocked(agentID, runID, rawURL, verdict, reason string) Outcome {
	data := j.destination(rawURL)
	data["verdict"] = verdict
	data["reason"] = reason
	return j.emit(TypeBlocked, severityBlocked, agentID, runID, data)
}

// destination turns a URL into the fields that may be kept.
//
// This is the whole of P1. The origin is a typed, bounded value an auditor can
// group by; the hash lets two records be compared without either holding the
// address. The path and the query string, which is where an identifier or a
// session token actually lives, are simply never assembled into the event.
func (j *Journal) destination(rawURL string) map[string]any {
	data := map[string]any{
		"origin":     origin(rawURL),
		"url_sha384": hashURL(rawURL),
	}
	if j.retainURL {
		// Only when an operator asked. Even then this belongs behind a
		// subject key in the payload plane, and until scopyx has one, saying
		// so in the field name is better than pretending the plane exists.
		data["url_unprotected"] = rawURL
	}
	return data
}

// origin is scheme://host, and nothing else.
func origin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		// An unparseable URL still gets a record, because the fact that
		// something asked for it is the interesting part. It gets no origin
		// rather than a guessed one.
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func hashURL(rawURL string) string {
	sum := sha512.Sum384([]byte(rawURL))
	return "sha384:" + hex.EncodeToString(sum[:])
}

func (j *Journal) emit(kind, severity, agentID, runID string, data map[string]any) Outcome {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.w == nil {
		return Disabled
	}
	if strings.TrimSpace(agentID) == "" {
		j.skipped++
		return SkippedNoAgentID
	}
	e := event.Event{
		Schema:   Schema,
		TS:       time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Source:   Source,
		Type:     kind,
		AgentID:  agentID,
		Severity: severity,
		RunID:    runID,
		Data:     data,
	}
	if err := j.w.Write(e); err != nil {
		j.failed++
		return WriteFailed
	}
	return Written
}

// Counts reports how many events were skipped for want of an identity and how
// many failed to write.
//
// Both are reported rather than kept private, because each is a number that
// means "this journal is not the whole story" and a reader who cannot see it
// has no way to know.
func (j *Journal) Counts() (skipped, failed int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.skipped, j.failed
}
