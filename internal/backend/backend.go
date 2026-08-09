// Package backend is the seam between this plane and whatever actually
// performs a fetch.
//
// The adapter IS the product, and that is not a portability nicety. A plane
// that can only fetch through one vendor is a browser with extra steps, tied
// to that vendor's beta and its pricing. A plane that governs whatever the
// operator already runs is a governance layer, and the operator keeps the tool
// they already pay for.
//
// CLAUDE.md invariant 1 is the rule this package exists under: no control is
// delegated to a backend. Nothing here decides anything. A Backend fetches and
// reports; every refusal happens in `internal/decide`, before Fetch is called,
// and `internal/fetch` is what holds that ordering.
package backend

import (
	"context"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// Request is one fetch, after it has already been allowed.
//
// There is deliberately no field for a header, a cookie or a credential, and
// there never will be: CLAUDE.md invariant 3, and `scripts/no-caller-headers.sh`
// reads this file too.
type Request struct {
	URL     string
	Extract string
	WaitFor string
}

// Subresource is one thing a page asked for, as the backend saw it.
type Subresource struct {
	URL     string
	Status  int
	Blocked bool
	Failed  bool
}

// Result is what a backend got.
//
// Subresources is nil, not empty, when the backend cannot report them. The
// distinction is the whole reason the fidelity counts are pointers: an empty
// slice says "it asked for nothing", nil says "nobody knows", and reporting
// the second as the first claims perfect fidelity for exactly the backend that
// can see the least.
type Result struct {
	FinalURL     string
	Body         []byte
	HTTPStatus   int
	Subresources []Subresource
	Redirects    []string
	TruncatedBy  decide.Truncation

	// RedirectTo is where a hop points, for a backend that reports redirects
	// instead of following them. Empty means either "not a redirect" or "this
	// backend followed it itself".
	//
	// The two are collapsed on purpose. A backend that follows internally has
	// already made a request this plane did not decide, and there is nothing
	// left for a distinction here to protect: the honest report of that is its
	// Enforcement value, which says navigation_only, and not a field suggesting
	// the hop was available for review when it was not.
	RedirectTo string
}

// Backend performs a fetch that has already been decided.
//
// Enforcement is on the interface rather than left for the caller to know,
// because it is a property OF the backend and a caller that had to remember it
// would eventually remember wrong. A backend this plane drives can be made to
// ask before every subresource; one the operator already runs cannot, and the
// result has to say which it was.
type Backend interface {
	Name() string
	Enforcement() decide.Enforcement
	Fetch(ctx context.Context, req Request) (Result, error)
}
