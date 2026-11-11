package main

import (
	"os"
	"testing"
)

// browserTempDir is the TMPDIR a browser test hands the browser: a directory
// of the test's own, as t.TempDir() is, but with a short path.
//
// Chrome creates its SingletonSocket under TMPDIR, and a unix socket path
// stops at 107 bytes. Under t.TempDir(), whose name carries the whole test
// name, the path ran to 118 bytes and the browser exited at start with
// "Socket path too long" (Google Chrome 156 on the CI runner, 2026-11-11).
// The snap Chromium CI used until then passed these tests, so it was not seen
// before.
func browserTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "scopyx-t-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
