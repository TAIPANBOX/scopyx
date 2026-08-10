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
	"fmt"
	"net/netip"
	"net/url"

	"github.com/TAIPANBOX/scopyx/internal/backend"
	"github.com/TAIPANBOX/scopyx/internal/decide"
	"github.com/TAIPANBOX/scopyx/internal/pin"
	"github.com/TAIPANBOX/scopyx/internal/policy"
	"github.com/TAIPANBOX/scopyx/internal/robots"
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

	// Robots is the site's own stated preference. Nil means not consulted,
	// which is a configuration rather than a default: see internal/robots.
	Robots *robots.Cache
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
//  4. pin the dialer to the addresses that were just checked, so nothing below
//     resolves the name a second time;
//  5. only now, call the backend.
//
// Step 5 is unreachable for a refused destination, and that is the difference
// between a governance layer and a fetcher that logs. A refused fetch never
// reaches the operator's own service, so it never appears in their bill for it
// either.
func Do(ctx context.Context, d Deps, req backend.Request) (Result, error) {
	current := req
	var hops []string

	for hop := 0; ; hop++ {
		u, err := url.Parse(current.URL)
		if err != nil {
			return Result{}, &Refusal{Decision: decide.Decision{
				Verdict: decide.DenyScheme,
				Reason:  "the URL could not be parsed: " + err.Error(),
			}}
		}

		// Resolved at the moment of the fetch, never from anything remembered,
		// and re-resolved on EVERY hop. Re-resolving is what closes DNS
		// rebinding: an address looked up minutes ago would satisfy the check
		// and the fetch would reach something else. A redirect target resolved
		// from the first hop's answer would be the same bug with extra steps.
		addrs, err := d.Resolver.Resolve(ctx, u.Hostname())
		if err != nil {
			return Result{}, &Refusal{Decision: decide.Decision{
				Verdict: decide.DenyAddress,
				Reason:  "the host could not be resolved: " + err.Error(),
			}}
		}

		answer := d.Memo.Host(ctx, u.Hostname())

		// hop 0 is the caller's own URL; every later one is a destination
		// nobody asked for, which is why it is decided rather than followed.
		var dec decide.Decision
		if hop == 0 {
			dec = decide.Destination(current.URL, addrs, answer.PolicyAnswer)
		} else {
			dec = decide.Redirect(hop, current.URL, addrs, answer.PolicyAnswer, d.Limits)
		}
		if !dec.Verdict.Allowed() {
			return Result{}, &Refusal{Decision: dec}
		}

		// Pinned only now, and this line is the point of `internal/pin`.
		//
		// Everything above decided about ADDRESSES. Everything below would
		// otherwise resolve the NAME again, inside a dialer, with no memory of
		// what was checked, and a hostile zone is free to answer differently
		// in between. From here the socket goes where the decision looked.
		//
		// After the verdict rather than before it, so a refused destination is
		// never pinned and a later code path cannot inherit permission from a
		// decision that said no.
		ctx = pin.With(ctx, u.Hostname(), addrs)

		// And the navigation's allow-set travels with it, for a backend that
		// fetches subresources this loop never sees. It decides them with the
		// same pure function and the same policy answer; without this it would
		// have to hold its own idea of what is allowed, which is invariant 1
		// broken from the inside.
		ctx = decide.WithAllowDomains(ctx, answer.PolicyAnswer.AllowDomains)

		// The site's own preference, asked AFTER the operator's policy and
		// before the fetch. The order is deliberate: a destination the
		// operator forbids is refused without this plane fetching anything
		// from it at all, not even its robots.txt, so a refused domain never
		// learns it was asked about.
		//
		// Every hop is checked, not only the first. A redirect to a path the
		// target disallows is exactly as disallowed as asking for it directly.
		if d.Robots != nil {
			r := d.Robots.Check(ctx, u.Scheme, u.Host, u.EscapedPath())
			if !r.Allowed {
				return Result{}, &Refusal{Decision: decide.Decision{
					Verdict: decide.DenyRobots,
					Reason:  r.Reason,
				}}
			}
		}

		res, err := d.Backend.Fetch(ctx, current)
		if err != nil {
			return Result{}, err
		}

		if res.RedirectTo == "" {
			if len(hops) > 0 {
				// Only when this loop followed them. A backend that follows
				// internally reports its own and must not have them overwritten
				// by an empty list.
				res.Redirects = hops
			}
			f := fidelityFor(d.Backend, res)
			if err := f.Check(); err != nil {
				return Result{}, err
			}
			final := res.FinalURL
			if final == "" {
				final = current.URL
			}
			return Result{Body: res.Body, FinalURL: final, Fidelity: f}, nil
		}

		// Resolved against the URL just fetched, so a relative Location goes to
		// the host that sent it rather than being parsed as a bare path and
		// refused as a scheme.
		target, err := u.Parse(res.RedirectTo)
		if err != nil {
			return Result{}, &Refusal{Decision: decide.Decision{
				Verdict: decide.DenyScheme,
				Reason:  "the redirect target could not be parsed: " + err.Error(),
			}}
		}
		if hop+1 > absoluteMaxRedirects {
			return Result{}, &Refusal{Decision: decide.Decision{
				Verdict: decide.DenyRedirectDepth,
				Reason: fmt.Sprintf(
					"the redirect chain passed %d hops, which this plane refuses "+
						"regardless of configured limits", absoluteMaxRedirects),
			}}
		}
		hops = append(hops, target.String())
		current.URL = target.String()
	}
}

// absoluteMaxRedirects is a liveness bound, not a policy one.
//
// `decide.Limits.MaxRedirects` is the policy bound and a zero there legally
// means "no bound", which is fine for a pure function and is a hang in a loop:
// two servers pointing at each other would spin here forever, and a fetch that
// never returns is worse than one that is refused, because nothing reports it.
// So the loop keeps its own ceiling, and says plainly that this is the one that
// stopped it rather than blaming a limit the operator set.
const absoluteMaxRedirects = 32

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
