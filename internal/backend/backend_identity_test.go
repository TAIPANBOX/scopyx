package backend

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// What each backend CLAIMS about itself, which is the part that reaches the
// record, and the record is the product.
//
// Enforcement is the one worth pinning hardest. It is not a field and not
// configurable, on purpose: an operator able to set `external` to per_request
// would make every record claim a control that no code in this process
// performs. Nothing had ever read these values back.

func TestEachBackendNamesItselfDistinctlyInTheRecord(t *testing.T) {
	t.Parallel()

	// A reader of a record has the backend name and nothing else to tell
	// which one produced it. Two backends sharing a name would make the
	// records indistinguishable, and the difference between them is exactly
	// what enforcement means.
	names := map[string]string{}
	for label, got := range map[string]string{
		"passthrough": NewPassthrough(1024, time.Second).Name(),
		"external":    NewExternal("acme", "https://fetch.example", "", time.Second).Name(),
	} {
		if got == "" {
			t.Errorf("%s reports no name at all", label)
		}
		if prev, seen := names[got]; seen {
			t.Errorf("%s and %s both call themselves %q", label, prev, got)
		}
		names[got] = label
	}
}

func TestTheExternalBackendCanOnlyEverClaimNavigationOnly(t *testing.T) {
	t.Parallel()

	// `external` calls a service the operator already runs. What that service
	// then reaches is outside this process entirely, so no fetch decision here
	// covers it. navigation_only is the true statement, and it is the only one
	// this backend is allowed to make, whatever it was constructed with.
	for _, tc := range []struct {
		name string
		e    *External
	}{
		{"ordinary", NewExternal("acme", "https://fetch.example", "k", time.Second)},
		{"no label", NewExternal("", "https://fetch.example", "", time.Second)},
		{"zero timeout", NewExternal("acme", "https://fetch.example", "", 0)},
	} {
		if got := tc.e.Enforcement(); got != decide.EnforcementNavigationOnly {
			t.Errorf("%s: got %v, want navigation_only; a record claiming more than the "+
				"code performs is the one failure this value exists to prevent", tc.name, got)
		}
	}
}

func TestThePassthroughBackendClaimsPerRequestBecauseItMakesExactlyOne(t *testing.T) {
	t.Parallel()

	// per_request means every request that left was decided. This backend makes
	// one request per call and `internal/fetch` decides before each, including
	// every redirect hop, so the claim is exact.
	if got := NewPassthrough(1024, time.Second).Enforcement(); got != decide.EnforcementPerRequest {
		t.Errorf("got %v, want per_request", got)
	}
}

func TestABackendWithAZeroTimeoutStillGetsAFiniteOne(t *testing.T) {
	t.Parallel()

	// An unbounded wait is a fetch that hangs rather than one that is refused,
	// and a hang is a bound that never arrives.
	e := NewExternal("acme", "https://fetch.example", "", 0)
	if e.HTTP == nil || e.HTTP.Timeout <= 0 {
		t.Fatalf("a zero timeout must become a finite one, got %#v", e.HTTP)
	}
}
