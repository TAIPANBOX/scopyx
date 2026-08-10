package cdp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake stands in for the browser: it reads NUL-terminated frames and answers
// them, so the framing and the id matching are tested without one.
func fake(t *testing.T, answer func(m Message) Message) *Conn {
	t.Helper()
	toBrowser, weWrite := io.Pipe()
	weRead, fromBrowser := io.Pipe()

	c := &Conn{w: weWrite, r: weRead, waiting: map[int64]chan Message{}}
	go c.read()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		br := bufio.NewReader(toBrowser)
		for {
			frame, err := br.ReadBytes(0)
			if len(frame) > 1 {
				var m Message
				if json.Unmarshal(frame[:len(frame)-1], &m) == nil {
					out := answer(m)
					if b, err := json.Marshal(out); err == nil {
						_, _ = fromBrowser.Write(append(b, 0))
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		weWrite.Close()
		fromBrowser.Close()
		wg.Wait()
	})
	return c
}

// A debugging PORT is an unauthenticated remote control channel for the browser
// this plane fetches with, which is the whole reason this package speaks over a
// pipe. Refusing it here rather than documenting it means a caller cannot open
// one by passing a flag through.
func TestLaunchRefusesADebuggingPortAndSaysWhy(t *testing.T) {
	for _, arg := range []string{"--remote-debugging-port=9222", "--remote-debugging-pipe"} {
		_, err := Launch(context.Background(), "/nonexistent", arg)
		if err == nil {
			t.Fatalf("%s must be refused", arg)
		}
		if !strings.Contains(err.Error(), "pipe") {
			t.Errorf("%s: the refusal must explain the pipe, got %q", arg, err)
		}
	}
}

func TestACallGetsItsOwnAnswerBack(t *testing.T) {
	c := fake(t, func(m Message) Message {
		return Message{ID: m.ID, Result: json.RawMessage(`{"targetId":"T-` + m.Method + `"}`)}
	})

	var out struct {
		TargetID string `json:"targetId"`
	}
	if err := c.Call(context.Background(), "", "Target.createTarget", map[string]any{"url": "about:blank"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.TargetID != "T-Target.createTarget" {
		t.Errorf("targetId = %q, want the answer to THIS call", out.TargetID)
	}
}

// Answers arrive out of order on a real connection, and a client that matched
// on arrival rather than on id would hand one call another's result. That is
// the kind of fault that looks like a flaky browser.
func TestAnswersAreMatchedByIDAndNotByArrivalOrder(t *testing.T) {
	held := make(chan Message, 1)
	c := fake(t, func(m Message) Message {
		if m.Method == "Slow" {
			held <- m
			return Message{} // answered later, by the test
		}
		return Message{ID: m.ID, Result: json.RawMessage(`{"which":"fast"}`)}
	})
	slowDone := make(chan error, 1)
	go func() {
		var out struct {
			Which string `json:"which"`
		}
		err := c.Call(context.Background(), "", "Slow", nil, &out)
		if err == nil && out.Which != "slow" {
			err = io.ErrUnexpectedEOF
		}
		slowDone <- err
	}()

	slow := <-held

	var fast struct {
		Which string `json:"which"`
	}
	if err := c.Call(context.Background(), "", "Fast", nil, &fast); err != nil {
		t.Fatal(err)
	}
	if fast.Which != "fast" {
		t.Errorf("the second call got %q", fast.Which)
	}

	c.deliver(Message{ID: slow.ID, Result: json.RawMessage(`{"which":"slow"}`)})
	if err := <-slowDone; err != nil {
		t.Errorf("the first call did not get its own answer: %v", err)
	}
}

// A protocol error is an error, not an empty result. Chrome refusing a command
// and Chrome answering with nothing are different facts, and a client that
// collapsed them would let a failed Fetch.enable look like a page with no
// subresources.
func TestAProtocolErrorIsReturnedRatherThanReadAsAnEmptyResult(t *testing.T) {
	c := fake(t, func(m Message) Message {
		return Message{ID: m.ID, Error: &ProtocolError{Code: -32601, Message: "not found"}}
	})
	err := c.Call(context.Background(), "", "Nope.doThing", nil, nil)
	if err == nil {
		t.Fatal("a protocol error must not read as success")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("the error must carry what Chrome said, got %q", err)
	}
}

// Events carry no id and must reach the handler rather than a waiting caller.
func TestAnEventReachesTheHandler(t *testing.T) {
	c := fake(t, func(m Message) Message { return Message{ID: m.ID} })
	got := make(chan string, 1)
	c.Handle(func(m Message) { got <- m.Method })

	c.deliver(Message{Method: "Page.loadEventFired", SessionID: "S1"})
	select {
	case m := <-got:
		if m != "Page.loadEventFired" {
			t.Errorf("handler got %q", m)
		}
	case <-time.After(time.Second):
		t.Error("the event never reached the handler")
	}
}

// A browser that dies mid-call must unblock its callers with an error. Without
// this the fetch would sit until its own timeout and report a slow page.
func TestACallEndsWhenTheBrowserGoesAway(t *testing.T) {
	weRead, fromBrowser := io.Pipe()
	drain, weWrite := io.Pipe()
	// Drained, or the Write inside Call blocks and this measures the fixture
	// rather than the connection. In production that write is to Chrome's own
	// pipe, and a browser that stopped reading is unblocked by the context
	// killing the process, which closes it.
	go func() { _, _ = io.Copy(io.Discard, drain) }()
	c := &Conn{w: weWrite, r: weRead, waiting: map[int64]chan Message{}}
	go c.read()

	done := make(chan error, 1)
	go func() { done <- c.Call(context.Background(), "", "Anything", nil, nil) }()

	time.Sleep(50 * time.Millisecond)
	fromBrowser.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a call must not succeed after the browser closed")
		}
	case <-time.After(2 * time.Second):
		t.Error("the call never ended")
	}
}

func TestFindPrefersTheConfiguredPathAndReportsAMissingOne(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "my-chromium")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SCOPYX_CHROMIUM", exe)
	if p, ok := Find(); !ok || p != exe {
		t.Errorf("Find() = %q, %v; want the configured path", p, ok)
	}

	// A configured path that is not there is a configuration error, and
	// searching on from it would run a browser the operator did not name.
	t.Setenv("SCOPYX_CHROMIUM", filepath.Join(dir, "not-here"))
	p, ok := Find()
	if ok {
		t.Error("a missing configured browser must not be reported as found")
	}
	if p == "" {
		t.Error("the path the operator named must come back, so the error can quote it")
	}
}
