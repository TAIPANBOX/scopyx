package decide

import "testing"

// Verdict.String is the word that reaches the record and the caller. It is an
// int underneath, so a wrong word is not a crash and not a wrong-looking
// report: it is a correct-looking report about a different thing.
//
// One pair matters more than the rest. DenyPolicy is the operator's own rule;
// DenyPolicyUnreachable is the policy plane not answering. Invariant 7 exists
// so those two never collapse into each other, because only one of them is the
// operator's to change, and confusing them sends somebody to repair a machine
// that is fine.
func TestEveryVerdictHasItsOwnWordAndNoneShareOne(t *testing.T) {
	want := map[Verdict]string{
		Allow:                 "allow",
		DenyScheme:            "deny_scheme",
		DenyHost:              "deny_host",
		DenyAddress:           "deny_address",
		DenyPolicy:            "deny_policy",
		DenyPolicyUnreachable: "deny_policy_unreachable",
		DenyRedirectDepth:     "deny_redirect_depth",
		DenyCap:               "deny_cap",
		DenyRobots:            "deny_robots",
	}
	seen := map[string]Verdict{}
	for v, w := range want {
		got := v.String()
		if got != w {
			t.Errorf("Verdict(%d).String() = %q, want %q", int(v), got, w)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%q is the word for both Verdict(%d) and Verdict(%d)",
				got, int(prev), int(v))
		}
		seen[got] = v
	}
}

// The distinction invariant 7 is built on, asserted on its own so a change
// that merged them is unmistakable in the failure output.
func TestARefusalByPolicyNeverReadsTheSameAsAPolicyPlaneThatCouldNotAnswer(t *testing.T) {
	if DenyPolicy.String() == DenyPolicyUnreachable.String() {
		t.Fatalf("both read as %q. One is the operator's own rule and the other "+
			"is their control plane being down. A trail that cannot tell them "+
			"apart sends somebody to repair a machine that is fine",
			DenyPolicy.String())
	}
	if DenyPolicy == DenyPolicyUnreachable {
		t.Fatal("the two verdicts are the same value")
	}
}

// Only Allow allows. Everything else is a refusal, and a new verdict added
// without a word would render as whatever the default is.
func TestAnythingThatIsNotAllowRendersAsADenial(t *testing.T) {
	all := []Verdict{
		DenyScheme, DenyHost, DenyAddress, DenyPolicy, DenyPolicyUnreachable,
		DenyRedirectDepth, DenyCap, DenyRobots,
	}
	for _, v := range all {
		if s := v.String(); s == "allow" {
			t.Fatalf("Verdict(%d) renders as %q", int(v), s)
		}
	}
	// A value outside the enum. It must not read as allow, whatever else it
	// reads as: an unrecognised verdict rendering as permission is the one
	// failure this cannot afford.
	for _, v := range []Verdict{Verdict(-1), Verdict(99)} {
		if s := v.String(); s == "allow" {
			t.Fatalf("an unknown Verdict(%d) renders as %q", int(v), s)
		}
	}
}
