package cdp

import (
	"os"
	"os/exec"
	"runtime"
)

// Candidates are the browsers this package will drive, in the order it looks.
//
// Chromium first, then Chrome. Not a preference between them so much as a
// preference for the one an operator installed deliberately: a machine with
// both usually has Chromium because somebody wanted a headless browser, and
// Chrome because somebody wanted a browser.
var Candidates = []string{
	"chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
}

var macCandidates = []string{
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
}

// Find locates a browser, preferring SCOPYX_CHROMIUM.
//
// It returns the path and whether one was found, and it does NOT fall back to
// anything. A backend that quietly used a different browser than the operator
// configured would be a fetch nobody can reproduce.
func Find() (string, bool) {
	if p := os.Getenv("SCOPYX_CHROMIUM"); p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
		// An explicitly configured path that is not there is a configuration
		// error, not an invitation to search. Reported as "not found" with the
		// path the operator named, one layer up.
		return p, false
	}
	for _, n := range Candidates {
		if p, err := exec.LookPath(n); err == nil {
			return p, true
		}
	}
	if runtime.GOOS == "darwin" {
		for _, p := range macCandidates {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p, true
			}
		}
	}
	return "", false
}
