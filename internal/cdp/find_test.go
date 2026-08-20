package cdp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Find decides which browser scopyx drives, and the rule it enforces is in its
// own doc comment: it does NOT fall back. A backend that quietly used a
// different browser than the operator configured produces a fetch nobody can
// reproduce, and a fetch nobody can reproduce is the one thing this whole
// service exists to prevent.
//
// Nothing had ever run that rule. The function was 33% covered, and the
// covered third was the part that finds a browser rather than the part that
// refuses to guess.

// fakeBrowser writes an executable file with the given name into dir.
func fakeBrowser(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// The rule, stated as its own test because it is the one that matters: an
// explicitly configured path that is not there must NOT send Find looking
// somewhere else, even when somewhere else would succeed.
func TestAConfiguredBrowserThatIsMissingIsNeverQuietlyReplaced(t *testing.T) {
	onPath := t.TempDir()
	fakeBrowser(t, onPath, "chromium")
	t.Setenv("PATH", onPath)

	// The operator named a path. It is wrong. A perfectly good browser is
	// sitting on PATH.
	named := filepath.Join(t.TempDir(), "the-one-they-configured")
	t.Setenv("SCOPYX_CHROMIUM", named)

	got, ok := Find()
	if ok {
		t.Fatalf("Find reported success with %q. SCOPYX_CHROMIUM named a "+
			"browser that is not there, and a different one was used instead: "+
			"every fetch after this is unreproducible and nothing says so", got)
	}
	if got != named {
		t.Fatalf("Find returned %q, want the configured path %q. The caller "+
			"reports this back to the operator, and an error that does not "+
			"name the path they set is an error they cannot act on", got, named)
	}
}

// A directory is not a browser. This is the shape a wrong SCOPYX_CHROMIUM
// usually takes: the .app bundle rather than the binary inside it.
func TestADirectoryIsNotABrowser(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SCOPYX_CHROMIUM", dir)

	got, ok := Find()
	if ok {
		t.Fatalf("a directory at %q was accepted as a browser: the usual "+
			"mistake is naming Chromium.app instead of the binary inside it, "+
			"and exec would fail far from here", got)
	}
	if got != dir {
		t.Fatalf("Find returned %q, want %q", got, dir)
	}
}

func TestAConfiguredBrowserThatIsThereIsUsedAsGiven(t *testing.T) {
	// Nothing on PATH at all, so a pass here cannot come from a search.
	t.Setenv("PATH", t.TempDir())
	named := fakeBrowser(t, t.TempDir(), "my-own-build-of-chromium")
	t.Setenv("SCOPYX_CHROMIUM", named)

	got, ok := Find()
	if !ok || got != named {
		t.Fatalf("Find = (%q, %v), want (%q, true)", got, ok, named)
	}
}

// Without the environment variable, PATH is searched in the order Candidates
// declares. The order is a decision the file explains, so it is worth holding:
// a machine with both usually has Chromium because somebody wanted a headless
// browser and Chrome because somebody wanted a browser.
func TestTheSearchOrderIsTheOneCandidatesDeclares(t *testing.T) {
	dir := t.TempDir()
	// Every candidate present, so only the order can decide.
	for _, n := range Candidates {
		fakeBrowser(t, dir, n)
	}
	t.Setenv("PATH", dir)
	os.Unsetenv("SCOPYX_CHROMIUM")

	got, ok := Find()
	if !ok {
		t.Fatal("Find found nothing with every candidate on PATH")
	}
	if want := filepath.Join(dir, Candidates[0]); got != want {
		t.Fatalf("Find chose %q, want %q. The order in Candidates is a decision "+
			"with a reason written next to it, and this is what holds it",
			got, want)
	}
}

func TestEachCandidateNameIsFoundOnItsOwn(t *testing.T) {
	for _, name := range Candidates {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := fakeBrowser(t, dir, name)
			t.Setenv("PATH", dir)
			os.Unsetenv("SCOPYX_CHROMIUM")

			got, ok := Find()
			if !ok || got != p {
				t.Fatalf("with only %s on PATH, Find = (%q, %v), want (%q, true): "+
					"a candidate nobody looks for is a browser scopyx cannot use "+
					"on a machine that has only that one", name, got, ok, p)
			}
		})
	}
}

// Nothing anywhere. On darwin the two .app paths are absolute and outside this
// test's control, so the honest assertion is that any success came from one of
// them and not from somewhere unexplained.
func TestNoBrowserAnywhereIsNotFoundRatherThanAGuess(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	os.Unsetenv("SCOPYX_CHROMIUM")

	got, ok := Find()
	if !ok {
		if got != "" {
			t.Fatalf("Find failed but returned %q, and with nothing configured "+
				"there is no path to report", got)
		}
		return
	}
	if runtime.GOOS != "darwin" {
		t.Fatalf("Find returned %q with an empty PATH and no configuration", got)
	}
	found := false
	for _, p := range macCandidates {
		if got == p {
			found = true
		}
	}
	if !found {
		t.Fatalf("on darwin Find returned %q, which is neither on PATH nor one "+
			"of the two known .app paths: %v", got, macCandidates)
	}
	if !strings.HasPrefix(got, "/Applications/") {
		t.Fatalf("Find returned %q from outside /Applications", got)
	}
}
