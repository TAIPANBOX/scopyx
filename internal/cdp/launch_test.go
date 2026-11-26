package cdp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// # A BROWSER THAT IS THIS TEST BINARY
//
// Launch, the pipe, the stderr tail and Close are about a child process, and
// testing them against Chrome would make this package's tests need one. So the
// test binary is the browser: started with fakeBrowserEnv set, TestMain hands
// it to pipeBrowser before any test runs, and it reads frames on fd 3 and
// writes them on fd 4 exactly as `--remote-debugging-pipe` does. Everything on
// this side of the pipe is the production code, unchanged.

const fakeBrowserEnv = "SCOPYX_CDP_FAKE_BROWSER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeBrowserEnv); mode != "" {
		os.Exit(pipeBrowser(mode))
	}
	os.Exit(m.Run())
}

// pipeBrowser modes:
//
//	serve     answers Echo.args with its own argv and the session it was asked
//	          on, turns Emit.event into an event, and on Die writes a reason to
//	          stderr and exits without answering
//	stubborn  serve, but ignores its pipe closing and has to be killed
//	exit      writes a reason to stderr and exits before reading anything
func pipeBrowser(mode string) int {
	if mode == "exit" {
		fmt.Fprintln(os.Stderr, "fake browser: error while loading shared libraries: libnss3.so")
		return 1
	}
	in := bufio.NewReader(os.NewFile(3, "cdp-in"))
	out := os.NewFile(4, "cdp-out")
	write := func(m map[string]any) {
		b, _ := json.Marshal(m)
		_, _ = out.Write(append(b, 0))
	}
	for {
		frame, err := in.ReadBytes(0)
		if len(frame) > 1 {
			var m Message
			if json.Unmarshal(frame[:len(frame)-1], &m) == nil {
				switch m.Method {
				case "Echo.args":
					write(map[string]any{"id": m.ID, "sessionId": m.SessionID,
						"result": map[string]any{"args": os.Args[1:], "sessionId": m.SessionID}})
				case "Emit.event":
					write(map[string]any{"method": "Fake.sent", "sessionId": m.SessionID, "params": m.Params})
				case "Die":
					fmt.Fprintln(os.Stderr, "fake browser: cannot open display")
					return 3
				default:
					write(map[string]any{"id": m.ID, "result": map[string]any{}})
				}
			}
		}
		if err != nil {
			if mode == "stubborn" {
				// A browser that does not notice its pipe went away. Sleep,
				// not an empty select: the runtime kills a process whose every
				// goroutine is blocked, which would exit on its own.
				time.Sleep(time.Hour)
			}
			return 0
		}
	}
}

// launchFake starts the test binary as a browser in the given mode.
func launchFake(t *testing.T, mode string, args ...string) *Conn {
	t.Helper()
	t.Setenv(fakeBrowserEnv, mode)
	c, err := Launch(context.Background(), os.Args[0], args...)
	if err != nil {
		t.Fatalf("launching the fake browser: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func bounded(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The browser is started with the pipe flag first and the caller's arguments
// after it, and a call reaches it on the session it names. A launch that
// dropped the pipe flag would leave Chrome with no channel at all; one that
// reordered or lost the caller's flags would drop the per-fetch profile or the
// proxy the floor depends on.
func TestALaunchedBrowserGetsThePipeFlagAndTheCallersArgsAndAnswersOnItsSession(t *testing.T) {
	c := launchFake(t, "serve", "--headless=new", "--proxy-server=http://127.0.0.1:1")

	var out struct {
		Args      []string `json:"args"`
		SessionID string   `json:"sessionId"`
	}
	if err := c.Call(bounded(t), "S1", "Echo.args", map[string]any{"x": 1}, &out); err != nil {
		t.Fatal(err)
	}
	want := []string{"--remote-debugging-pipe", "--headless=new", "--proxy-server=http://127.0.0.1:1"}
	if strings.Join(out.Args, " ") != strings.Join(want, " ") {
		t.Errorf("the browser was started with %q, want %q", out.Args, want)
	}
	if out.SessionID != "S1" {
		t.Errorf("the call arrived on session %q, want S1", out.SessionID)
	}
}

// Send writes a frame and returns without waiting: what it carried arrives at
// the browser, and the browser's event reaches the handler.
func TestSendReachesTheBrowserWithItsSessionAndParams(t *testing.T) {
	c := launchFake(t, "serve")
	got := make(chan Message, 1)
	c.Handle(func(m Message) { got <- m })

	if err := c.Send("S2", "Emit.event", map[string]any{"requestId": "r-7"}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if m.Method != "Fake.sent" || m.SessionID != "S2" || !strings.Contains(string(m.Params), "r-7") {
			t.Errorf("the browser saw %+v, want the params on session S2", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("what Send wrote never reached the browser")
	}
}

// A browser that dies, mid-call or before it read anything, unblocks the call
// with the connection error, and its own last words are kept for the error a
// caller builds. Without the tail a missing shared library reads as "the
// browser closed the connection" and nothing else.
func TestABrowserThatDiesEndsTheCallAndLeavesItsReasonInStderr(t *testing.T) {
	for _, tc := range []struct{ mode, method, said string }{
		{"serve", "Die", "cannot open display"},
		{"exit", "Browser.getVersion", "libnss3.so"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			c := launchFake(t, tc.mode)
			err := c.Call(bounded(t), "", tc.method, nil, nil)
			if err == nil || !strings.Contains(err.Error(), "closed the connection") {
				// A deadline here means our copy of the child's write end was
				// left open, so its exit never reached the reader as EOF.
				t.Fatalf("want the connection-closed error, got %v", err)
			}
			if err := c.cmd.Wait(); err == nil {
				t.Error("the fake browser should have exited with a failure status")
			}
			if s := c.Stderr(); !strings.Contains(s, tc.said) {
				t.Errorf("Stderr() = %q, want what the browser said (%q)", s, tc.said)
			}
		})
	}
}

// A browser that cannot be started is an error naming the path, and no
// connection is returned to call on.
func TestABrowserThatCannotBeStartedIsAnErrorNamingThePath(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "no-such-browser")
	c, err := Launch(context.Background(), exe)
	if err == nil {
		_ = c.Close()
		t.Fatal("launching a path that does not exist must fail")
	}
	if !strings.Contains(err.Error(), "could not start") || !strings.Contains(err.Error(), exe) {
		t.Errorf("the error must say it could not start and name %s, got %q", exe, err)
	}
}

// Close kills the browser even when it ignores its pipe closing, returns, and
// leaves a connection nothing can be sent on. Idempotent, because a fetch
// closes on every path out and some paths overlap.
func TestCloseKillsTheBrowserAndRefusesEverythingAfter(t *testing.T) {
	c := launchFake(t, "stubborn")
	if err := c.Call(bounded(t), "", "Browser.getVersion", nil, nil); err != nil {
		t.Fatal(err)
	}

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return: a browser that ignores its pipe must be killed")
	}
	if c.cmd.ProcessState == nil {
		t.Error("Close returned before the browser process was reaped")
	}
	if err := c.Close(); err != nil {
		t.Errorf("a second Close must be a no-op, got %v", err)
	}
	// The connection's own refusal, not whatever writing to a closed file says.
	const refused = "the browser connection is closed"
	if err := c.Call(bounded(t), "", "Anything", nil, nil); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("a call after Close must be refused as closed, got %v", err)
	}
	if err := c.Send("", "Anything", nil); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("a send after Close must be refused as closed, got %v", err)
	}
}

// A call whose context ends returns the context's error and forgets its id, so
// a fetch that timed out leaves nothing behind for a late answer to land on.
func TestACallWhoseContextEndsReturnsAndForgetsItsID(t *testing.T) {
	c := fake(t, func(Message) Message { return Message{} }) // never answers
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := c.Call(ctx, "", "Page.navigate", nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the context's error, got %v", err)
	}
	c.mu.Lock()
	n := len(c.waiting)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("%d call(s) still waiting after their context ended", n)
	}
}

// A write that fails is returned naming the method, and the call does not wait
// for an answer that cannot come.
func TestAWriteThatFailsIsReturnedAndNothingIsLeftWaiting(t *testing.T) {
	r, _ := io.Pipe()
	_, w := io.Pipe()
	_ = w.Close()
	c := &Conn{w: w, r: r, waiting: map[int64]chan Message{}}

	err := c.Call(bounded(t), "", "Fetch.enable", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "Fetch.enable") {
		t.Fatalf("want the write error naming the method, got %v", err)
	}
	if len(c.waiting) != 0 {
		t.Errorf("%d call(s) left waiting after a failed write", len(c.waiting))
	}
	if err := c.Send("", "Fetch.continueRequest", nil); err == nil {
		t.Error("a send whose write fails must return the error")
	}
}

// Params that cannot be encoded are an error before anything is written, not
// a frame Chrome cannot read and a call that waits for its timeout.
func TestParamsThatCannotBeEncodedAreAnError(t *testing.T) {
	c := fake(t, func(m Message) Message { return Message{ID: m.ID} })
	bad := map[string]any{"f": func() {}}
	if err := c.Call(bounded(t), "", "Page.navigate", bad, nil); err == nil {
		t.Error("Call with unencodable params must fail")
	}
	if err := c.Send("", "Page.navigate", bad); err == nil {
		t.Error("Send with unencodable params must fail")
	}
}

// Chrome's detail is kept in the error: for a refused Fetch.continueRequest the
// data field is the only place that says which request it was about.
func TestAProtocolErrorKeepsChromesDetail(t *testing.T) {
	e := &ProtocolError{Code: -32602, Message: "Invalid parameters", Data: "Failed to deserialize params.requestId"}
	if got := e.Error(); !strings.Contains(got, "Failed to deserialize params.requestId") || !strings.Contains(got, "-32602") {
		t.Errorf("Error() = %q, want the message, code and data", got)
	}
	if got := (&ProtocolError{Code: 1, Message: "m"}).Error(); strings.HasSuffix(got, ": ") {
		t.Errorf("an error with no data must not end in an empty detail: %q", got)
	}
}
