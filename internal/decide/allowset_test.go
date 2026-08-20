package decide

import (
	"context"
	"testing"
)

// The allow-set carried on the context, and the distinction that makes it
// dangerous to "harden" by accident.
//
// nil means the policy declared NO domain restriction. An empty non-nil slice
// means it declared one and it is empty, which is "allow nothing". They are
// opposites, and a reader who collapses them breaks one direction or the other:
// nil read as deny-all breaks every page an unrestricted policy permits, and
// empty read as nil silently widens a set somebody deliberately emptied.

func TestAnAllowSetSurvivesTheContextExactlyAsGiven(t *testing.T) {
	t.Parallel()

	in := []string{"example.com", "cdn.example.com"}
	got := AllowDomainsFrom(WithAllowDomains(context.Background(), in))
	if len(got) != len(in) {
		t.Fatalf("got %v, want %v", got, in)
	}
	for i := range in {
		if got[i] != in[i] {
			t.Errorf("entry %d: got %q, want %q", i, got[i], in[i])
		}
	}
}

func TestNoAllowSetIsNilAndMeansNoRestrictionRatherThanAllowNothing(t *testing.T) {
	t.Parallel()

	if got := AllowDomainsFrom(context.Background()); got != nil {
		t.Errorf("a context nobody set an allow-set on must report nil, got %#v", got)
	}
}

func TestAnEmptyAllowSetIsKeptDistinctFromNoAllowSetAtAll(t *testing.T) {
	t.Parallel()

	// This is the one that matters. Both are "falsy" to a careless reader and
	// they mean opposite things: allow nothing, versus restrict nothing.
	got := AllowDomainsFrom(WithAllowDomains(context.Background(), []string{}))
	if got == nil {
		t.Fatal("an allow-set that was declared and is empty must not come back as nil; " +
			"nil is read as 'no restriction' and this one means 'allow nothing'")
	}
	if len(got) != 0 {
		t.Errorf("got %v, want an empty set", got)
	}
}

func TestEveryVerdictPrintsSomethingAndNoTwoPrintTheSame(t *testing.T) {
	t.Parallel()

	// The verdict string is what a record carries and what an operator reads.
	// A verdict missing from the switch falls to whatever the default is, and
	// two verdicts sharing a string make a record ambiguous about which rule
	// refused a fetch.
	seen := map[string]Verdict{}
	for v := Allow; v <= DenyRobots; v++ {
		s := v.String()
		if s == "" {
			t.Errorf("verdict %d prints nothing", int(v))
			continue
		}
		if prev, dup := seen[s]; dup {
			t.Errorf("verdicts %d and %d both print %q", int(prev), int(v), s)
		}
		seen[s] = v
	}
	if len(seen) < 2 {
		t.Fatalf("only %d distinct verdict strings, so this measured nothing", len(seen))
	}
}
