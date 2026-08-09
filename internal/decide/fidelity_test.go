package decide

import (
	"encoding/json"
	"errors"
	"testing"
)

// The single most important refusal in the package. An empty page and a page
// that could not be read are indistinguishable to a model, and the second one
// silently becomes "the agent looked and there was nothing there".
func TestNothingExtractedWithAFailureIsAnErrorNotAnEmptyPage(t *testing.T) {
	f := Fidelity{
		Backend:            "stub",
		Enforcement:        EnforcementPerRequest,
		ContentBytes:       0,
		SubresourcesFailed: Count(3),
	}
	if err := f.Check(); !errors.Is(err, ErrEmptyWithFailures) {
		t.Fatalf("got %v, want ErrEmptyWithFailures", err)
	}
}

// The overeager guard, and it earns its place: a check that refused a
// genuinely empty page would be deleted by whoever hit it first.
func TestAGenuinelyEmptyPageFetchedCleanlyIsAnAnswer(t *testing.T) {
	f := Fidelity{
		Backend:            "stub",
		Enforcement:        EnforcementPerRequest,
		ContentBytes:       0,
		SubresourcesFailed: Count(0),
	}
	if err := f.Check(); err != nil {
		t.Fatalf("an empty page with nothing failed is a legitimate answer, got %v", err)
	}
}

// A backend that cannot count its subresources must not be reported as one
// that counted zero. Filling an unknown with zero reports perfect fidelity for
// exactly the backend that can see the least.
func TestAnUnknownCountIsNullAndNeverZero(t *testing.T) {
	f := Fidelity{
		Backend:            "external:firecrawl",
		Enforcement:        EnforcementNavigationOnly,
		ContentBytes:       1024,
		SubresourcesFailed: nil,
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"subresources_requested", "subresources_ok",
		"subresources_blocked_by_policy", "subresources_failed",
	} {
		v, present := back[k]
		if !present {
			t.Errorf("%s must be present and null, not omitted: a missing key reads as a field that does not exist", k)
			continue
		}
		if v != nil {
			t.Errorf("%s must be null when the backend cannot count, got %v", k, v)
		}
	}
}

// An unknown count must not turn a real answer into an error either: the
// backend saw nothing about subresources, which is not the same as seeing a
// failure.
func TestAnUnknownFailureCountDoesNotRefuseAnEmptyResult(t *testing.T) {
	f := Fidelity{Backend: "external:firecrawl", Enforcement: EnforcementNavigationOnly, ContentBytes: 0}
	if err := f.Check(); err != nil {
		t.Fatalf("nothing is known about failures here, so nothing may be concluded: %v", err)
	}
}

// The result says which guarantee was in force. Reporting both backends the
// same way would claim in the second a guarantee that was only true in the
// first.
func TestTheResultSaysWhetherSubresourcesWereEnforcedOrMerelyObserved(t *testing.T) {
	driven := Fidelity{Backend: "kitesurf", Enforcement: EnforcementPerRequest, ContentBytes: 1}
	external := Fidelity{Backend: "external:firecrawl", Enforcement: EnforcementNavigationOnly, ContentBytes: 1}
	if driven.Enforcement == external.Enforcement {
		t.Fatal("a driven backend and one somebody else runs must not report the same enforcement")
	}
	raw, _ := json.Marshal(external)
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	if back["enforcement"] != string(EnforcementNavigationOnly) {
		t.Errorf("enforcement must travel in the result, got %v", back["enforcement"])
	}
}

func TestTruncationNamesWhichBoundCutIt(t *testing.T) {
	f := Fidelity{Backend: "stub", ContentBytes: 1 << 20, TruncatedBy: TruncatedByBytes}
	if err := f.Check(); err != nil {
		t.Fatalf("a truncated result is still an answer: %v", err)
	}
	if f.TruncatedBy != TruncatedByBytes {
		t.Errorf("got %q", f.TruncatedBy)
	}
	clean := Fidelity{Backend: "stub", ContentBytes: 10}
	if clean.TruncatedBy != TruncatedNone {
		t.Errorf("an untruncated result names no bound, got %q", clean.TruncatedBy)
	}
}
