package cdp

import (
	"strings"
	"sync"
	"testing"
)

// The bounded buffer that carries the browser's own words into an error, and
// the connection's refusal to write after it is closed. Neither had a test.

func TestTheStderrRingKeepsTheLastWordsNotTheFirst(t *testing.T) {
	t.Parallel()

	// This is the whole point of the type and the direction is easy to get
	// backwards. A browser that dies prints its banner first and the reason
	// last; a ring that kept the first bytes would hand an operator the
	// version string and drop the failure that matters.
	r := &ring{max: 16}
	if _, err := r.Write([]byte("Chromium 141.0 starting up, all is well\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := r.Write([]byte("FATAL: no sandbox")); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := r.String()
	if len(got) > 16 {
		t.Errorf("the ring kept %d bytes, its bound is 16: %q", len(got), got)
	}
	if !strings.Contains(got, "sandbox") {
		t.Errorf("the ring must keep the END of what was written, got %q", got)
	}
	if strings.Contains(got, "starting up") {
		t.Errorf("the ring kept the beginning and dropped the failure: %q", got)
	}
}

func TestTheStderrRingReportsWhatFitsWithoutSurroundingWhitespace(t *testing.T) {
	t.Parallel()

	r := &ring{max: 64}
	if _, err := r.Write([]byte("\n\n  the browser said this  \n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := r.String(); got != "the browser said this" {
		t.Errorf("got %q, want it trimmed", got)
	}
}

func TestTheStderrRingSurvivesTwoWritersAtOnce(t *testing.T) {
	t.Parallel()

	// Chrome's stderr is written by the process while the protocol reader runs,
	// so this buffer genuinely has two writers. Run with -race, which CI does.
	r := &ring{max: 4096}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = r.Write([]byte("line of browser output\n"))
				_ = r.String()
			}
		}()
	}
	wg.Wait()
	if r.String() == "" {
		t.Error("after 400 writes the ring is empty")
	}
}

func TestAConnectionWithNoStderrReportsNothingRatherThanPanicking(t *testing.T) {
	t.Parallel()

	// Reached on the error path of a connection that never got as far as
	// attaching a buffer, which is the path least likely to be exercised and
	// the most likely to be running while something else is already wrong.
	c := &Conn{}
	if got := c.Stderr(); got != "" {
		t.Errorf("got %q, want an empty string", got)
	}
}
