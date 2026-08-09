package decide

import "errors"

// Enforcement says whether subresources were decided one by one, or merely
// observed.
//
// This field exists because the honest answer differs per backend and the
// difference is invisible in the result otherwise. A backend this plane drives
// can be made to ask before every request. A backend somebody else runs, the
// operator's existing Firecrawl or Browserbase, cannot: it fetches the page and
// hands back what it got.
//
// Reporting both cases the same way would claim a guarantee in the second that
// was only true in the first, which is the shape this whole repository exists
// to refuse. So the result says which it was, every time.
type Enforcement string

const (
	// EnforcementPerRequest: every subresource was decided before it left.
	EnforcementPerRequest Enforcement = "per_request"
	// EnforcementNavigationOnly: only the navigation was decided. The backend
	// fetched what it fetched, and the counts below are an observation rather
	// than a control.
	EnforcementNavigationOnly Enforcement = "navigation_only"
)

// Truncation names the bound that cut a result short, if one did.
type Truncation string

const (
	TruncatedNone            Truncation = ""
	TruncatedByBytes         Truncation = "bytes"
	TruncatedByTime          Truncation = "time"
	TruncatedBySubresources  Truncation = "subresource_count"
	TruncatedByRedirectDepth Truncation = "redirect_depth"
)

// Fidelity is what actually happened, and it travels with every result.
//
// The default backend's own stated safety rule is that any failure degrades to
// a blank frame or a missing element and never to a dead session. For a person
// reading a page that is the right trade. For an agent it is the worst failure
// available: the model does not know it read half a page, and it reports
// confidently on the half it got.
//
// A count the backend cannot supply is nil, never zero. Filling an unknown
// with zero reports perfect fidelity for exactly the backend that can see the
// least, which is the opposite of what a reader needs.
type Fidelity struct {
	Backend      string      `json:"backend"`
	Enforcement  Enforcement `json:"enforcement"`
	HTTPStatus   int         `json:"http_status"`
	ContentBytes int64       `json:"content_bytes"`

	SubresourcesRequested       *int `json:"subresources_requested"`
	SubresourcesOK              *int `json:"subresources_ok"`
	SubresourcesBlockedByPolicy *int `json:"subresources_blocked_by_policy"`
	SubresourcesFailed          *int `json:"subresources_failed"`

	RedirectHops int        `json:"redirect_hops"`
	TruncatedBy  Truncation `json:"truncated_by"`
}

// ErrEmptyWithFailures is returned instead of a result when nothing was
// extracted and something failed while trying.
//
// It is an error rather than an empty success on purpose, and it is the single
// most important line in this package. An empty page and a page that could not
// be read are indistinguishable to a model, and the second one silently turns
// into "the agent looked and there was nothing there".
var ErrEmptyWithFailures = errors.New(
	"nothing was extracted and at least one subresource failed, so this is a page that could not be read rather than a page with nothing on it")

// Check reports whether a result may be handed back as an answer.
//
// Deliberately narrow. It refuses the one case where an empty result is known
// to be a failure, and it does NOT refuse a genuinely empty page: a document
// that really has no text, fetched cleanly, is a legitimate answer and a check
// that refused it would be deleted by whoever hit it first.
func (f Fidelity) Check() error {
	if f.ContentBytes > 0 {
		return nil
	}
	if f.SubresourcesFailed != nil && *f.SubresourcesFailed > 0 {
		return ErrEmptyWithFailures
	}
	return nil
}

// Count is a small helper for the pointer fields, so a caller that knows a
// count writes `decide.Count(3)` rather than taking the address of a local.
func Count(n int) *int { return &n }
