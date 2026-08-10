// Package browserproxy is the floor under a browser.
//
// # WHY A PROXY AND NOT THE BROWSER'S OWN INTERCEPTION
//
// A rendering backend is the first one this plane DRIVES, and it is also the
// first one that fetches things nobody named: a page is a document plus fonts,
// images, scripts and XHR, each potentially a different host. Chrome will hand
// those to us through CDP `Fetch.requestPaused`, and that is genuinely useful,
// because it carries the full URL of every request including the ones inside
// TLS.
//
// It is not a floor. It is Chrome's cooperation, and cooperation is a thing a
// bug, a flag or a version can withdraw. `Fetch` interception has never covered
// every request Chrome can make: service workers, some prefetches and parts of
// the network service have been outside it at various versions, and a
// governance component whose guarantee depends on which build of somebody
// else's browser it is talking to has no guarantee.
//
// So the browser is launched with no way out except this proxy, and this proxy
// refuses anything the plane did not decide. CDP interception rides ON TOP of
// it, for the per-request counts and the per-URL decisions it is good at. If
// the two ever disagree, the connection is the one that matters, because it is
// the one that carries bytes.
//
// This is the same argument invariant 1 makes about backends, one layer down:
// enforce here, and never on the strength of what somebody else's software
// promises to tell you.
//
// # WHAT IT SEES, EXACTLY
//
// For plaintext http the proxy sees the whole URL. For https it sees a CONNECT
// to host:port and nothing else, because this plane does NOT intercept TLS: a
// governance component that minted certificates for other people's sites would
// be building the capability it exists to govern, and it would need a private
// CA on the box.
//
// That is not the loss it looks like. Every rule `decide` applies to a
// destination is about the scheme, the host and the addresses it resolves to,
// and all three are visible in a CONNECT. The path is not, and no rule reads
// the path. What the proxy cannot do is separate two requests inside one
// tunnel, and that is what CDP interception is for.
package browserproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// Attempt is one thing the browser tried to reach, as the proxy saw it.
//
// Its own type rather than `backend.Subresource`, and not only to break an
// import cycle. This package must not know what a backend result looks like:
// it is the floor under a browser, and the day something else stands on it the
// dependency would be pointing the wrong way.
type Attempt struct {
	URL     string
	Status  int
	Blocked bool
	Failed  bool
}

// Decider answers whether a destination may be reached, and where.
//
// It returns the ADDRESSES as well as the verdict, so the proxy dials what was
// checked rather than resolving the name a second time. That is the same rule
// `internal/pin` holds for the plain backends, and it has to be repeated here
// because a proxy dials on behalf of somebody else: the browser hands over a
// name, and the name is the one thing that must not be trusted.
type Decider interface {
	Allow(ctx context.Context, scheme, host string) ([]netip.Addr, decide.Decision)
}

// DeciderFunc adapts a function.
type DeciderFunc func(ctx context.Context, scheme, host string) ([]netip.Addr, decide.Decision)

func (f DeciderFunc) Allow(ctx context.Context, scheme, host string) ([]netip.Addr, decide.Decision) {
	return f(ctx, scheme, host)
}

// Proxy is one fetch's worth of egress.
//
// One per fetch, never shared, and torn down with it. A proxy that outlived a
// fetch would be a warm path between two of them, which is invariant 4 in the
// shape it is easiest to build by accident.
type Proxy struct {
	// Decide is asked about every connection. Required: a nil one refuses
	// everything rather than allowing it, because a proxy with no decider is a
	// misconfiguration and this plane fails closed.
	Decide Decider

	// Dial opens the socket to an already-checked address. Nil is an ordinary
	// dialer. Present for the same reason `pin.TransportWith` has one: the
	// tests need real decisions over a fixture on loopback, and loopback is an
	// address `decide` refuses.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Timeout bounds one upstream connection.
	Timeout time.Duration

	ln   net.Listener
	wg   sync.WaitGroup
	once sync.Once

	mu   sync.Mutex
	seen []Attempt
}

// Start listens on loopback and serves until Close.
//
// Loopback only, and an ephemeral port. The browser is told about it and
// nothing else is, which is the whole reason it is not a unix socket: Chrome's
// --proxy-server does not speak one.
//
// WHAT THIS DOES NOT CLOSE, written down rather than left to be found. While a
// fetch is in flight, any process on the same machine that guesses the port can
// use this proxy, and it would be decided against the same policy as the fetch
// rather than refused outright. Closing it means demanding Proxy-Authorization
// with a per-fetch secret and answering the challenge over CDP
// `Fetch.authRequired`, which is a change to the CDP layer rather than a line
// here. Debt, and this is its shape.
func (p *Proxy) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.ln = ln
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer c.Close()
				p.serve(c)
			}()
		}
	}()
	return ln.Addr().String(), nil
}

// Close stops listening and waits for connections in flight.
func (p *Proxy) Close() error {
	var err error
	p.once.Do(func() {
		if p.ln != nil {
			err = p.ln.Close()
		}
		p.wg.Wait()
	})
	return err
}

// Requests reports what the browser asked for, in the order it asked.
//
// A COPY, and never nil once Start has run. The nil-versus-empty distinction is
// load-bearing one layer up: nil means the backend cannot report subresources
// at all, and this one can, so an empty slice here truthfully says the page
// asked for nothing beyond its own document.
func (p *Proxy) Requests() []Attempt {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Attempt, len(p.seen))
	copy(out, p.seen)
	return out
}

func (p *Proxy) record(s Attempt) {
	p.mu.Lock()
	p.seen = append(p.seen, s)
	p.mu.Unlock()
}

func (p *Proxy) timeout() time.Duration {
	if p.Timeout <= 0 {
		return 30 * time.Second
	}
	return p.Timeout
}

func (p *Proxy) serve(client net.Conn) {
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout())
	defer cancel()

	if req.Method == http.MethodConnect {
		p.connect(ctx, client, br, req)
		return
	}
	p.plain(ctx, client, req)
}

// allow asks the decider and records the answer.
//
// Every refusal is recorded as a blocked subresource before anything is
// written back, so a page that was cut off still reports what it tried. A
// count that only included what succeeded would make a heavily blocked page
// look like a quiet one.
func (p *Proxy) allow(ctx context.Context, scheme, host, shown string) ([]netip.Addr, bool) {
	if p.Decide == nil {
		p.record(Attempt{URL: shown, Blocked: true})
		return nil, false
	}
	addrs, d := p.Decide.Allow(ctx, scheme, host)
	if !d.Verdict.Allowed() {
		p.record(Attempt{URL: shown, Blocked: true})
		return nil, false
	}
	if len(addrs) == 0 {
		// Allowed with nothing to dial is a decider bug, and it must not become
		// "resolve it here": that would put a second lookup back in, which is
		// the whole thing this arrangement removes.
		p.record(Attempt{URL: shown, Blocked: true})
		return nil, false
	}
	return addrs, true
}

func (p *Proxy) dialChecked(ctx context.Context, addrs []netip.Addr, port string) (net.Conn, error) {
	dial := p.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: p.timeout()}
		dial = d.DialContext
	}
	var last error
	for _, a := range addrs {
		c, err := dial(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no address to try")
	}
	return nil, last
}

func (p *Proxy) connect(ctx context.Context, client net.Conn, br *bufio.Reader, req *http.Request) {
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host, port = req.Host, "443"
	}
	shown := "https://" + req.Host

	addrs, ok := p.allow(ctx, "https", host, shown)
	if !ok {
		// 403 rather than a silent close. A closed socket reads to the browser
		// as a network error and to a reader of the page as "the site was
		// down", and those are different facts from "the plane refused it".
		_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n"+
			"Content-Length: 0\r\nX-Scopyx-Refused: destination\r\n\r\n")
		return
	}

	up, err := p.dialChecked(ctx, addrs, port)
	if err != nil {
		p.record(Attempt{URL: shown, Failed: true})
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	p.record(Attempt{URL: shown, Status: 200})

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// Anything the browser pipelined behind CONNECT is already in the reader,
	// so the tunnel starts from the buffer rather than from the socket. Reading
	// the socket directly here loses those bytes, which shows up as a TLS
	// handshake that mysteriously stalls on some pages and not others.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (p *Proxy) plain(ctx context.Context, client net.Conn, req *http.Request) {
	// A proxy request carries an absolute URI. A relative one is a browser
	// talking to us as if we were an origin server, which we are not.
	if req.URL == nil || !req.URL.IsAbs() {
		_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	shown := req.URL.String()

	addrs, ok := p.allow(ctx, req.URL.Scheme, host, shown)
	if !ok {
		p.refuse(client, req)
		return
	}

	up, err := p.dialChecked(ctx, addrs, port)
	if err != nil {
		p.record(Attempt{URL: shown, Failed: true})
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()

	// Forwarded in origin form, with the hop-by-hop headers dropped. The
	// request the browser wrote is otherwise passed through unchanged: this
	// component governs WHERE a request goes and never rewrites what it says,
	// which is the same reason the tool surface has no header parameter.
	out := req.Clone(ctx)
	out.RequestURI = ""
	stripHopByHop(out.Header)
	if err := writeOrigin(up, out); err != nil {
		p.record(Attempt{URL: shown, Failed: true})
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(up), out)
	if err != nil {
		p.record(Attempt{URL: shown, Failed: true})
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	p.record(Attempt{URL: shown, Status: resp.StatusCode})

	stripHopByHop(resp.Header)
	_ = resp.Write(client)
}

func (p *Proxy) refuse(client net.Conn, req *http.Request) {
	body := "scopyx refused this request: the destination was not allowed by policy.\n"
	fmt.Fprintf(client, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"+
		"X-Scopyx-Refused: destination\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	_ = req
}

// writeOrigin sends the request in the form an origin server expects.
func writeOrigin(w io.Writer, req *http.Request) error {
	u := *req.URL
	u.Scheme, u.Host = "", ""
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", req.URL.Host)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	if req.Body != nil {
		defer req.Body.Close()
		if _, err := io.Copy(w, req.Body); err != nil {
			return err
		}
	}
	return nil
}

// hopByHop are the headers that belong to one connection and must not be
// forwarded. Passing Connection or Proxy-Authorization upstream is how a proxy
// leaks its own arrangement to the site.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}

// URLOf builds what a CONNECT would have been asking for, for a decider that
// wants a URL rather than a scheme and a host.
func URLOf(scheme, host string) string {
	u := url.URL{Scheme: scheme, Host: host, Path: "/"}
	return u.String()
}
