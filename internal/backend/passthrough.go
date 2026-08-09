package backend

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// Passthrough fetches one URL over HTTP and renders nothing.
//
// # WHY THE DEFAULT BACKEND IS THE ONE THAT DOES LEAST
//
// It needs no vendor, no account, no API token and no browser on the host, so a
// deployment can be governed on the day it is installed rather than on the day
// somebody arranges a fetching service. Everything this plane exists for, the
// decision, the address refusals, the redirect re-evaluation, the bounds and
// the record, is in force here exactly as it is in front of a rendering
// backend, because none of it lives in the backend.
//
// That is invariant 2 stated as running code rather than as a claim: if the
// governance were in the backend, the backend that renders nothing would
// govern nothing.
//
// # WHAT IT HONESTLY IS NOT
//
// It runs no JavaScript, so a page assembled in the browser arrives as the
// shell that assembles it. An agent that needs the rendered page needs a
// rendering backend, and the fidelity block says which one answered so a reader
// is never guessing.
//
// # IT DOES NOT FOLLOW REDIRECTS, AND THAT IS THE POINT
//
// `CheckRedirect` returns `http.ErrUseLastResponse`, so a 302 comes back as a
// 302 with its target reported and NOT followed. Following it here would be a
// second request that no policy decision preceded, which is precisely the
// allowlist bypass `decide.Redirect` exists for. The hop is re-decided by
// `internal/fetch`, one layer up, where the resolver and the policy plane are.
//
// An HTTP client that follows redirects by default is the single easiest way to
// build this component wrong, and it is the default in every language.
type Passthrough struct {
	// MaxBodyBytes bounds what is read. Reached, the body is truncated and the
	// result says so rather than pretending the page ended there: invariant 5,
	// and the reason a truncation reason exists as a typed value.
	MaxBodyBytes int64

	HTTP *http.Client
}

// NewPassthrough builds one.
//
// Both bounds are finite by construction. A zero timeout is a fetch that hangs
// rather than one that is refused, and an unbounded read is how a governed
// egress path is turned into a memory exhaustion against the thing doing the
// governing.
func NewPassthrough(maxBodyBytes int64, timeout time.Duration) *Passthrough {
	if maxBodyBytes <= 0 {
		maxBodyBytes = 32 << 20
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Passthrough{
		MaxBodyBytes: maxBodyBytes,
		HTTP: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *Passthrough) Name() string { return "passthrough-http" }

// Enforcement is per_request, and it is not a boast.
//
// This backend makes exactly one request per call, and `internal/fetch` decides
// before every one of them, including each redirect hop. So every request that
// left was decided, which is what the value means.
//
// It is worth being exact about what it does NOT mean here: there are no
// subresources to police because none are fetched, not because they were
// policed and allowed. The counts say zero requested, which is the true
// statement, and a reader comparing this with a rendering backend is comparing
// "asked for nothing" with "asked for forty and blocked three".
func (p *Passthrough) Enforcement() decide.Enforcement { return decide.EnforcementPerRequest }

// Fetch performs one already-decided request.
func (p *Passthrough) Fetch(ctx context.Context, req Request) (Result, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("building the request for %s: %w", p.Name(), err)
	}
	// The only header this backend sets, and it names the component rather than
	// impersonating a browser. Invariant 9: this plane governs evasion and never
	// supplies it, and a matched browser user-agent is evasion with a polite
	// name. A site that refuses this is a site that has refused us knowingly.
	httpReq.Header.Set("User-Agent", "scopyx/1 (+https://github.com/TAIPANBOX/scopyx)")

	resp, err := p.HTTP.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("fetching %s: %w", req.URL, err)
	}
	defer resp.Body.Close()

	// Read one byte past the bound, so "exactly at the limit" is distinguishable
	// from "there was more". Reading exactly MaxBodyBytes cannot tell them
	// apart and would report a truncated page as a complete one.
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.MaxBodyBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("reading %s: %w", req.URL, err)
	}
	truncated := decide.TruncatedNone
	if int64(len(body)) > p.MaxBodyBytes {
		body = body[:p.MaxBodyBytes]
		truncated = decide.TruncatedByBytes
	}

	res := Result{
		FinalURL:   req.URL,
		Body:       body,
		HTTPStatus: resp.StatusCode,
		// Empty, not nil, and the distinction is load-bearing. Nil means "this
		// backend cannot report what the page asked for". Empty means "it asked
		// for nothing", which for a fetch that parses no HTML is exactly true.
		Subresources: []Subresource{},
		TruncatedBy:  truncated,
	}

	// A redirect is reported, never followed. `internal/fetch` re-resolves and
	// re-asks the policy plane about the target before anything goes to it.
	if isRedirect(resp.StatusCode) {
		if loc, err := resp.Location(); err == nil && loc != nil {
			res.RedirectTo = loc.String()
		}
	}
	return res, nil
}

// isRedirect covers the four hops a client may follow plus 308.
//
// 300 and 304 are deliberately absent: a 300 has no single target and a 304 is
// an answer about a cache, not a hop. Treating either as a redirect would send
// this plane looking for a Location that carries no destination.
func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}
