package record

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

const (
	testAgent = "agent://acme.example/support/tier1-bot"
	// The URL this package exists to keep out of the record: a path holding
	// an identifier and a query string holding a contact detail. Both are
	// personal data and both are somewhere erasure cannot reach once written.
	sensitive = "https://crm.example/customers/12345?email=jane@example.com&session=abc123"
)

func openJournal(t *testing.T, retainURL bool) (*Journal, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.ndjson")
	j, err := Open(path, retainURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path
}

func readEvents(t *testing.T, path string) []event.Event {
	t.Helper()
	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return evs
}

// P1, and the reason this package is shaped the way it is. The path and the
// query string are where an identifier or a session token actually lives, and
// they are never assembled into the event at all.
func TestTheFullUrlNeverReachesTheRecord(t *testing.T) {
	j, path := openJournal(t, false)
	if got := j.Fetch(testAgent, "run-1", sensitive, "external:x", "navigation_only", 42); got != Written {
		t.Fatalf("outcome = %v, want Written", got)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(raw)
	for _, secret := range []string{"12345", "jane@example.com", "abc123", "/customers/"} {
		if strings.Contains(line, secret) {
			t.Errorf("the record carries %q, which is personal data somewhere erasure cannot reach:\n%s",
				secret, line)
		}
	}
	if !strings.Contains(line, "https://crm.example") {
		t.Error("the origin must be there: it is what an auditor groups by")
	}
	if !strings.Contains(line, "sha384:") {
		t.Error("the hash must be there: it is what lets two records be compared without either holding the address")
	}
}

// The same hash for the same URL, a different one for a different URL. Without
// this the field is decoration.
func TestTheHashDistinguishesUrlsAndRepeatsForOne(t *testing.T) {
	a := hashURL(sensitive)
	if a != hashURL(sensitive) {
		t.Error("the same URL must hash the same, or two records of one fetch cannot be matched")
	}
	if a == hashURL(sensitive+"x") {
		t.Error("two URLs must not share a hash")
	}
	if !strings.HasPrefix(a, "sha384:") {
		t.Errorf("the algorithm must be named in the value, got %q", a)
	}
}

// P2. Retention is opt-in, and when an operator opts in the field says out
// loud that it is unprotected, because this plane has no subject-key payload
// plane yet and pretending otherwise would be the worse lie.
func TestTheUrlIsRetainedOnlyWhenAskedForAndSaysSo(t *testing.T) {
	j, path := openJournal(t, true)
	j.Fetch(testAgent, "run-1", sensitive, "external:x", "navigation_only", 1)

	evs := readEvents(t, path)
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	got, ok := evs[0].Data["url_unprotected"]
	if !ok {
		t.Fatal("with retention on, the URL must be there")
	}
	if got != sensitive {
		t.Errorf("url_unprotected = %v", got)
	}
}

// SPEC 6.1 forbids a fabricated agent_id. A fallback subject, a "various"
// agent or an org id in that field makes every downstream count wrong and puts
// a name on an alert that did not do the thing.
func TestWithNoIdentityNothingIsWrittenAndTheSkipIsCounted(t *testing.T) {
	j, path := openJournal(t, false)

	for _, id := range []string{"", "   "} {
		if got := j.Fetch(id, "run-1", sensitive, "external:x", "navigation_only", 1); got != SkippedNoAgentID {
			t.Errorf("agent %q: outcome = %v, want SkippedNoAgentID", id, got)
		}
	}
	if skipped, _ := j.Counts(); skipped != 2 {
		t.Errorf("skipped = %d, want 2: a skip nobody counts is a skip nobody knows about", skipped)
	}

	if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
		t.Errorf("nothing may be written without an identity, got:\n%s", raw)
	}
}

func TestABlockedFetchIsRecordedWithItsVerdictAndReason(t *testing.T) {
	j, path := openJournal(t, false)
	if got := j.Blocked(testAgent, "run-1", "https://tracker.example/pixel.gif",
		"deny_policy", "not in allow_domains"); got != Written {
		t.Fatalf("outcome = %v", got)
	}
	evs := readEvents(t, path)
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	e := evs[0]
	if e.Type != TypeBlocked {
		t.Errorf("type = %q, want %q", e.Type, TypeBlocked)
	}
	if e.Severity != severityBlocked {
		t.Errorf("severity = %q, want %q", e.Severity, severityBlocked)
	}
	if e.Data["verdict"] != "deny_policy" {
		t.Errorf("verdict = %v", e.Data["verdict"])
	}
}

// Severity is fixed per type in code. A severity an emission site can pick is
// one that drifts between sites, and every downstream count of "how many high
// events" then measures who wrote the call rather than what happened.
func TestSeverityIsFixedPerTypeAndTheTwoDiffer(t *testing.T) {
	j, path := openJournal(t, false)
	j.Fetch(testAgent, "r", "https://a.example/x", "b", "per_request", 1)
	j.Blocked(testAgent, "r", "https://b.example/x", "deny_policy", "no")

	evs := readEvents(t, path)
	if len(evs) != 2 {
		t.Fatalf("got %d events", len(evs))
	}
	if evs[0].Severity != "low" || evs[1].Severity != "high" {
		t.Errorf("severities = %q, %q; want low then high", evs[0].Severity, evs[1].Severity)
	}
	if evs[0].Severity == evs[1].Severity {
		t.Error("a fetch and a refusal must not carry the same severity")
	}
}

// SPEC 6.5. The chain is what makes a dropped or edited line detectable, and a
// journal that did not chain would look identical until somebody tried to
// verify it.
func TestTheJournalIsChainedAndVerifies(t *testing.T) {
	j, path := openJournal(t, false)
	for i := 0; i < 4; i++ {
		j.Fetch(testAgent, "run-1", "https://a.example/x", "b", "per_request", int64(i))
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	report, err := event.VerifyChain(f)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ok() {
		t.Fatalf("the journal must verify: %+v", report)
	}

	evs := readEvents(t, path)
	if evs[0].PrevHash != "" {
		t.Error("the first line is a chain head and carries no prev_hash")
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].PrevHash == "" {
			t.Errorf("line %d carries no prev_hash, so a deletion before it would be invisible", i+1)
		}
	}
}

// A tampered line must be detectable, or the chain is decoration. This is the
// property the whole envelope exists for, asserted rather than assumed.
func TestATamperedLineIsDetected(t *testing.T) {
	j, path := openJournal(t, false)
	for i := 0; i < 3; i++ {
		j.Fetch(testAgent, "run-1", "https://a.example/x", "b", "per_request", int64(i))
	}
	_ = j.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"content_bytes":1`, `"content_bytes":9999`, 1)
	if tampered == string(raw) {
		t.Fatal("the test could not alter the file, so it proves nothing")
	}

	report, err := event.VerifyChain(strings.NewReader(tampered))
	if err != nil {
		t.Fatal(err)
	}
	if report.Ok() {
		t.Fatal("an altered line must break the chain, or the record is not evidence of anything")
	}
}

// Not wanting records is a configuration, not a fault, and a disabled journal
// costs one branch.
func TestADisabledJournalWritesNothingAndIsNotAnError(t *testing.T) {
	j, err := Open("", false)
	if err != nil {
		t.Fatalf("an empty path is a disabled journal, not an error: %v", err)
	}
	if got := j.Fetch(testAgent, "r", "https://a.example/x", "b", "per_request", 1); got != Disabled {
		t.Errorf("outcome = %v, want Disabled", got)
	}
	if skipped, failed := j.Counts(); skipped != 0 || failed != 0 {
		t.Errorf("a disabled journal counts nothing, got skipped=%d failed=%d", skipped, failed)
	}
}
