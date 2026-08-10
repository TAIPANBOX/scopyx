// Package pin makes a transport dial only addresses this plane has checked.
//
// # THE HOLE THIS CLOSES
//
// `internal/fetch` resolves a hostname, and `decide.Destination` refuses on
// every address the name answered with. Then the fetch happens, and every HTTP
// client in Go resolves the name AGAIN, inside the dialer, with no memory of
// what was checked. Between those two lookups a name is free to answer
// differently. That is DNS rebinding, and it is not exotic: a hostile site
// controls its own zone and its own TTLs, and the second answer costs nothing.
//
// The window is microseconds and the payoff is the whole point of the plane:
// the address checks refuse RFC1918, loopback and 169.254.169.254, so a
// destination that passes the check as a public address and rebinds to the
// metadata endpoint reads the credentials of whatever this runs on.
//
// It was recorded as debt in CLAUDE.md invariant 9 for one day, with the
// reason: closing it means pinning the dialer to the already resolved address,
// which is a change to how every backend is constructed rather than a line in
// one of them. This package is that change, made once and shared.
//
// # AND IT FAILS CLOSED, WHICH IS THE PART WORTH KEEPING
//
// The obvious implementation pins the hosts it knows and dials the rest
// normally. This one refuses to dial a host the context does not carry.
//
// That turns the transport into an enforcement point of last resort: a code
// path that reached out without going through `internal/fetch` cannot open a
// socket, whatever it thinks it is doing. Every control in this repository
// enforces above the backend by design (invariant 1), and this is the floor
// under that design rather than a second copy of it.
package pin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// ErrUnchecked is a dial to a host no decision covered.
//
// Typed so a caller can tell "the plane refused this" from "the network is
// down". Those are different facts, and collapsing them sends somebody to
// repair a machine that is fine, which is the same argument invariant 7 makes
// about an unreachable policy plane.
var ErrUnchecked = errors.New("scopyx: refusing to dial a host no decision covered")

type key struct{}

type pins map[string][]netip.Addr

// With returns a context carrying the addresses checked for host.
//
// Additive across hops: a redirect adds its own host to the same context, and
// the earlier one stays because the connection to it may still be open. The
// map is copied rather than mutated, so a context handed to two goroutines
// cannot grow under either of them.
func With(ctx context.Context, host string, addrs []netip.Addr) context.Context {
	if host == "" || len(addrs) == 0 {
		return ctx
	}
	next := pins{}
	for k, v := range from(ctx) {
		next[k] = v
	}
	next[canonical(host)] = addrs
	return context.WithValue(ctx, key{}, next)
}

// Checked reports the addresses pinned for host, and whether any were.
func Checked(ctx context.Context, host string) ([]netip.Addr, bool) {
	a, ok := from(ctx)[canonical(host)]
	return a, ok
}

func from(ctx context.Context) pins {
	p, _ := ctx.Value(key{}).(pins)
	return p
}

// canonical strips the trailing dot and lowercases, because `example.com.` and
// `Example.com` name the same host and a map keyed on the raw string would
// treat a pin for one as absent for the other. Absent means refused here, so
// this is a correctness detail rather than a tidiness one.
func canonical(host string) string {
	h := host
	for len(h) > 0 && h[len(h)-1] == '.' {
		h = h[:len(h)-1]
	}
	return toLower(h)
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// Transport builds one that dials only what the context carries.
//
// Keep-alives are OFF, and that is not a performance oversight. A pooled
// connection is reused on the strength of scheme, host and port, which is
// exactly the tuple that a rebinding attack keeps constant while changing the
// address underneath. A second fetch would then ride a socket opened to an
// address checked for the FIRST one and never dial at all, so the pin would be
// consulted once and bypassed thereafter. It is also what invariant 4 asks
// for, one layer lower than that invariant is usually read: no fetch context
// survives into the next fetch, and an open TCP connection is a fetch context.
func Transport(timeout time.Duration) *http.Transport { return TransportWith(timeout, nil) }

// TransportWith is Transport with the socket-opening step supplied.
//
// The dial it receives has ALREADY been rewritten to a checked address, so
// everything this package enforces has happened before it is called. It exists
// because the end-to-end tests need the real pin logic over a fixture server
// on loopback, and loopback is an address `decide` refuses: without this seam
// the only way to exercise the arrangement in the assembled server would be to
// loosen the address rules for tests, which is the wrong thing to weaken.
//
// A nil dial is an ordinary one, which is what production uses.
func TransportWith(timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	if dial == nil {
		dial = d.DialContext
	}
	return &http.Transport{
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: %q is not host:port", ErrUnchecked, addr)
			}
			checked, ok := Checked(ctx, host)
			if !ok {
				return nil, fmt.Errorf("%w: %s. Nothing resolved and checked this host, so no "+
					"connection to it is opened, whatever asked for one", ErrUnchecked, host)
			}

			// Every checked address is tried, in the order the resolver gave
			// them, because `decide` refuses unless ALL of them are acceptable:
			// reaching any one of them is reaching an address that passed.
			var last error
			for _, a := range checked {
				conn, err := dial(ctx, network, net.JoinHostPort(a.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			if last == nil {
				last = errors.New("no address to try")
			}
			return nil, fmt.Errorf("scopyx: none of the %d checked addresses for %s could be "+
				"reached: %w", len(checked), host, last)
		},
	}
}

// ClientWith is Client with the socket-opening step supplied. See TransportWith.
func ClientWith(timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     TransportWith(timeout, dial),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Client wraps a pinned transport in a client that never follows a redirect.
//
// Following inside a client is a second request that no decision preceded,
// which is the bypass `decide.Redirect` exists for. It is repeated here rather
// than assumed because the default in Go, and in every other language, is to
// follow.
func Client(timeout time.Duration) *http.Client { return ClientWith(timeout, nil) }
