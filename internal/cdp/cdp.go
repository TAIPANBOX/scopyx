// Package cdp speaks the Chrome DevTools Protocol over a pipe.
//
// # WHY A PIPE AND NOT A PORT
//
// The usual way to drive Chrome is `--remote-debugging-port`, and it is the
// wrong shape for this component. That port is a full remote-control channel
// with no authentication: anything on the machine that can reach it can open
// pages, read cookies and evaluate scripts in the browser this plane is using
// to fetch on somebody's behalf. Building a governance component that opens one
// would be adding, on the same box, the capability the component exists to
// bound.
//
// `--remote-debugging-pipe` speaks the identical protocol over inherited file
// descriptors 3 and 4. No port, no listener, and the only process that can
// speak it is the one that launched the browser. Messages are JSON separated by
// a NUL byte.
//
// # WHY NOT A LIBRARY
//
// chromedp and its relatives are good and they bring a dependency tree. This
// repository has one direct dependency and that is a stated property rather
// than an accident: the whole point of the plane is that an operator can read
// what governs their egress. The subset actually needed here is small, and it
// is spelled out below rather than reachable through a generated API surface
// covering every domain Chrome has ever shipped.
package cdp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
)

// Message is one protocol frame, in either direction.
type Message struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *ProtocolError  `json:"error,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

// ProtocolError is Chrome refusing a call.
type ProtocolError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *ProtocolError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("cdp: %s (%d): %s", e.Message, e.Code, e.Data)
	}
	return fmt.Sprintf("cdp: %s (%d)", e.Message, e.Code)
}

// Conn is one browser process's protocol connection.
type Conn struct {
	w      io.WriteCloser
	r      io.ReadCloser
	cmd    *exec.Cmd
	stderr *ring

	next atomic.Int64

	mu      sync.Mutex
	waiting map[int64]chan Message
	handler func(Message)
	closed  bool
	readErr error
}

// Launch starts a browser and speaks to it over the pipe.
//
// `args` must NOT contain --remote-debugging-pipe or --remote-debugging-port:
// this adds the first and would be undone by the second, and a caller that
// passed a port would silently turn the reason for this package inside out.
func Launch(ctx context.Context, exe string, args ...string) (*Conn, error) {
	for _, a := range args {
		if a == "--remote-debugging-pipe" ||
			len(a) >= 22 && a[:22] == "--remote-debugging-por" {
			return nil, fmt.Errorf("cdp: refusing to launch with %q: this package speaks over a "+
				"pipe on purpose, because a debugging PORT is an unauthenticated remote control "+
				"channel for the browser this plane fetches with", a)
		}
	}

	toChild, weWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	weRead, fromChild, err := os.Pipe()
	if err != nil {
		toChild.Close()
		weWrite.Close()
		return nil, err
	}

	cmd := exec.CommandContext(ctx, exe, append([]string{"--remote-debugging-pipe"}, args...)...)
	// fd 3 is what the browser reads, fd 4 is what it writes.
	cmd.ExtraFiles = []*os.File{toChild, fromChild}

	// The browser's own complaints, kept.
	//
	// Without this a browser that refuses to start reports as "the browser
	// closed the connection", which describes the symptom and hides the
	// sentence that says why: a missing shared library, a sandbox that cannot
	// initialise, a profile it cannot write. Bounded, because a chatty build
	// should not become a memory leak in the thing doing the governing.
	tail := &ring{max: 8 << 10}
	cmd.Stderr = tail
	if err := cmd.Start(); err != nil {
		toChild.Close()
		weWrite.Close()
		weRead.Close()
		fromChild.Close()
		return nil, fmt.Errorf("cdp: could not start %s: %w", exe, err)
	}
	// Our copies of the child's ends are closed, so a browser that exits gives
	// us EOF instead of a read that blocks until the context expires.
	toChild.Close()
	fromChild.Close()

	c := &Conn{w: weWrite, r: weRead, cmd: cmd, stderr: tail, waiting: map[int64]chan Message{}}
	go c.read()
	return c, nil
}

// Handle registers the one function every event goes to.
//
// One rather than a per-method registry, because the caller here is a single
// backend with a small switch, and a registry would be a routing layer nobody
// needs between it and four event names.
func (c *Conn) Handle(fn func(Message)) {
	c.mu.Lock()
	c.handler = fn
	c.mu.Unlock()
}

func (c *Conn) read() {
	br := bufio.NewReaderSize(c.r, 1<<20)
	for {
		frame, err := br.ReadBytes(0)
		if len(frame) > 1 {
			var m Message
			if json.Unmarshal(frame[:len(frame)-1], &m) == nil {
				c.deliver(m)
			}
		}
		if err != nil {
			c.mu.Lock()
			c.readErr = err
			for id, ch := range c.waiting {
				close(ch)
				delete(c.waiting, id)
			}
			c.mu.Unlock()
			return
		}
	}
}

func (c *Conn) deliver(m Message) {
	if m.ID != 0 {
		c.mu.Lock()
		ch, ok := c.waiting[m.ID]
		delete(c.waiting, m.ID)
		c.mu.Unlock()
		if ok {
			ch <- m
			close(ch)
		}
		return
	}
	c.mu.Lock()
	h := c.handler
	c.mu.Unlock()
	if h != nil {
		h(m)
	}
}

// Call sends one command and waits for its answer.
//
// sessionID empty addresses the browser itself; a session addresses one page.
func (c *Conn) Call(ctx context.Context, sessionID, method string, params, out any) error {
	id := c.next.Add(1)
	req := map[string]any{"id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	if sessionID != "" {
		req["sessionId"] = sessionID
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	ch := make(chan Message, 1)
	c.mu.Lock()
	if c.closed || c.readErr != nil {
		c.mu.Unlock()
		return errors.New("cdp: the browser connection is closed")
	}
	c.waiting[id] = ch
	c.mu.Unlock()

	if _, err := c.w.Write(append(body, 0)); err != nil {
		c.mu.Lock()
		delete(c.waiting, id)
		c.mu.Unlock()
		return fmt.Errorf("cdp: %s: %w", method, err)
	}

	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.waiting, id)
		c.mu.Unlock()
		return ctx.Err()
	case m, ok := <-ch:
		if !ok {
			return fmt.Errorf("cdp: %s: the browser closed the connection", method)
		}
		if m.Error != nil {
			return fmt.Errorf("cdp: %s: %w", method, m.Error)
		}
		if out != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, out)
		}
		return nil
	}
}

// Send is Call without waiting, for the replies that must not block the reader.
//
// `Fetch.continueRequest` is the reason it exists: it is answered inside the
// event handler, and waiting there for a reply that arrives on the same
// goroutine reading events is a deadlock rather than a slow path.
func (c *Conn) Send(sessionID, method string, params any) error {
	id := c.next.Add(1)
	req := map[string]any{"id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	if sessionID != "" {
		req["sessionId"] = sessionID
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errors.New("cdp: the browser connection is closed")
	}
	_, err = c.w.Write(append(body, 0))
	return err
}

// Stderr reports what the browser said, for an error that needs it.
func (c *Conn) Stderr() string {
	if c.stderr == nil {
		return ""
	}
	return c.stderr.String()
}

// ring keeps the last max bytes written to it.
type ring struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
	return len(p), nil
}

func (r *ring) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.TrimSpace(string(r.buf))
}

// Close ends the protocol connection and waits for the browser to exit.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	c.w.Close()
	c.r.Close()
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	}
	return nil
}
