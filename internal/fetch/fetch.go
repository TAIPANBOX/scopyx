// Package fetch is the ordering.
//
// It holds one rule that no type signature can: the decision happens BEFORE
// the backend is called. Everything else in this repository is arranged so
// that rule is possible, and this file is where it is either kept or broken.
//
// Read the sequence in Do below rather than this paragraph. If a future change
// moves the backend call above the decision, every test in this package still
// passes except the ones that count what the fixture server was asked, which
// is why those exist and why they assert a NUMBER rather than an outcome.
package fetch

import (
	"context"
	"errors"
	"net/netip"
	"net/url"

	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/policy"
)

// Resolver turns a hostname into the addresses a fetch would actually reach.
//
// An interface because `decide` must stay pure and because the interesting
// cases are all hostile: a name that answers with a private address, a name
// that answers with one of each. Those are unreachable in a test that has to
// stand up real DNS, which means they are the cases nobody would test.
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
}

// Deps are what a fetch needs from the outside world.
type Deps struct {
	Backend  backend.Backend
	Resolver Resolver
	Memo     *policy.Memo
	Limits   decide.Limits
}

// Refusal is a fetch that did not happen, and why.
//
// It carries the verdict rather than only a message so a caller can tell a
// policy refusal from an unreachable policy plane without parsing English.
type Refusal struct {
	Decision decide.Decision
}

func (r *Refusal) Error() string {
	return r.Decision.Verdict.String() + ": " + r.Decision.Reason
}

// Verdict lets a caller switch on the refusal without unwrapping strings.
func (r *Refusal) Verdict() decide.Verdict { return r.Decision.Verdict }

// Result is a governed fetch.
type Result struct {
	Body     []byte
	FinalURL string
	Fidelity decide.Fidelity
}

// Do performs one governed fetch.
//
// The order is the product:
//
//  1. parse and resolve, so a decision is made about what would ACTUALLY be
//     reached rather than about a string;
//  2. ask the policy plane;
//  3. decide, which is pure and refuses on scheme, host, address or policy;
//  4. only now, call the backend.
//
// Step 4 is unreachable for a refused destination, and that is the difference
// between a governance layer and a fetcher that logs. A refused fetch never
// reaches the operator's own service, so it never appears in their bill for it
// either.
func Do(ctx context.Context, d Deps, req backend.Request) (Result, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return Result{}, &Refusal{Decision: decide.Decision{
			Verdict: decide.DenyScheme,
			Reason:  "the URL could not be parsed: " + err.Error(),
		}}
	}

	// Resolved at the moment of the fetch, never from anything remembered.
	// Re-resolving here is what closes DNS rebinding: an address looked up
	// minutes ago would satisfy the check and the fetch would reach something
	// else.
	addrs, err := d.Resolver.Resolve(ctx, u.Hostname())
	if err != nil {
		return Result{}, &Refusal{Decision: decide.Decision{
			Verdict: decide.DenyAddress,
			Reason:  "the host could not be resolved: " + err.Error(),
		}}
	}

	answer := d.Memo.Host(ctx, u.Hostname())

	if dec := decide.Destination(req.URL, addrs, answer.PolicyAnswer); !dec.Verdict.Allowed() {
		return Result{}, &Refusal{Decision: dec}
	}

	res, err := d.Backend.Fetch(ctx, req)
	if err != nil {
		return Result{}, err
	}

	f := fidelityFor(d.Backend, res)
	if err := f.Check(); err != nil {
		return Result{}, err
	}

	final := res.FinalURL
	if final == "" {
		final = req.URL
	}
	return Result{Body: res.Body, FinalURL: final, Fidelity: f}, nil
}

// fidelityFor assembles the counts, and leaves them nil when the backend did
// not report subresources at all.
//
// The nil case is the one worth reading. `len(res.Subresources)` on a nil
// slice is 0, so the obvious implementation reports four zeroes and a reader
// concludes the page asked for nothing and everything succeeded. That is the
// silent-zero failure this estate keeps finding, and it would have been
// written here by anybody not looking for it.
func fidelityFor(b backend.Backend, res backend.Result) decide.Fidelity {
	f := decide.Fidelity{
		Backend:      b.Name(),
		Enforcement:  b.Enforcement(),
		HTTPStatus:   res.HTTPStatus,
		ContentBytes: int64(len(res.Body)),
		RedirectHops: len(res.Redirects),
		TruncatedBy:  res.TruncatedBy,
	}
	if res.Subresources == nil {
		return f
	}
	var ok, blocked, failed int
	for _, s := range res.Subresources {
		switch {
		case s.Blocked:
			blocked++
		case s.Failed:
			failed++
		default:
			ok++
		}
	}
	f.SubresourcesRequested = decide.Count(len(res.Subresources))
	f.SubresourcesOK = decide.Count(ok)
	f.SubresourcesBlockedByPolicy = decide.Count(blocked)
	f.SubresourcesFailed = decide.Count(failed)
	return f
}

// AsRefusal reports whether an error is a refusal, and which one.
func AsRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	ok := errors.As(err, &r)
	return r, ok
}
