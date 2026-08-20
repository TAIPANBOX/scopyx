package backend

import (
	"strings"
	"testing"
)

// The two helpers that turn a browser that would not start into something an
// operator can act on. Both were at 0%.
//
// These are diagnostics, so a failure here never breaks a fetch. It does
// something quieter: an operator whose container cannot run Chrome reads an
// error, learns nothing, and concludes scopyx is broken. The advice below is
// the difference between that and a two-minute fix, and nothing was checking
// that it still appears.

func TestSandboxAdviceOnlyAppearsWhenTheSandboxIsWhatFailed(t *testing.T) {
	saidSandbox := []string{
		"Failed to move to new namespace: ... --no-sandbox",
		"Running as root without --no-sandbox is not supported",
		"The SUID sandbox helper binary was found, but is not configured correctly",
	}
	for _, said := range saidSandbox {
		if got := sandboxAdvice(said); got == "" {
			t.Errorf("no advice for a sandbox failure:\n%s", said)
		}
	}

	// The advice names SCOPYX_CHROMIUM_NO_SANDBOX, and it has to keep saying
	// that turning the sandbox off is a decision rather than a fix. That
	// sentence is the only thing standing between an operator and disabling
	// the browser's sandbox because an error message suggested it.
	got := sandboxAdvice(saidSandbox[0])
	for _, want := range []string{"SCOPYX_CHROMIUM_NO_SANDBOX", "decision rather than a fix"} {
		if !strings.Contains(got, want) {
			t.Errorf("the advice no longer says %q:\n%s", want, got)
		}
	}

	notSandbox := []string{
		"",
		"exec: \"chromium\": executable file not found in $PATH",
		"Fontconfig error: Cannot load default config file",
	}
	for _, said := range notSandbox {
		if got := sandboxAdvice(said); got != "" {
			t.Errorf("sandbox advice offered for a failure that is not the "+
				"sandbox. It sends the operator to disable a security feature "+
				"that was never the problem.\ninput: %q\nadvice: %s", said, got)
		}
	}
}

func TestLastLinesKeepsTheEndBecauseThatIsWhereTheFailureIs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{
			"the tail is kept, not the head",
			"one\ntwo\nthree\nfour\nfive", 2, "four | five",
		},
		{
			"fewer lines than asked for are all kept",
			"only\ntwo", 5, "only | two",
		},
		{
			"trailing blank lines do not eat the message",
			"the actual error\n\n\n", 2, "the actual error",
		},
		{
			"leading blank lines do not either",
			"\n\nthe actual error", 2, "the actual error",
		},
		{
			"one line stays one line with no separator",
			"just this", 3, "just this",
		},
		{
			"nothing said is nothing rendered",
			"", 3, "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lastLines(c.in, c.n); got != c.want {
				t.Fatalf("lastLines(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
			}
		})
	}
}

// The head is what Chrome fills with noise it prints on every start. Keeping
// it instead of the tail would hand the operator a fontconfig warning as the
// explanation for a browser that never came up.
func TestLastLinesDropsTheNoiseChromePrintsOnEveryStart(t *testing.T) {
	said := strings.Join([]string{
		"Fontconfig error: Cannot load default config file",
		"libva error: vaGetDriverNameByIndex() failed",
		"[0820/143001.1:ERROR:zygote_host_impl_linux.cc(90)] Running as root without --no-sandbox is not supported",
	}, "\n")

	got := lastLines(said, 2)
	if strings.Contains(got, "Fontconfig") {
		t.Fatalf("the fontconfig warning survived into a two-line summary, "+
			"which means the real failure did not:\n%s", got)
	}
	if !strings.Contains(got, "--no-sandbox") {
		t.Fatalf("the actual failure is not in the summary:\n%s", got)
	}
}
