package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// External wraps a fetching service the operator already runs and already pays
// for: a Firecrawl account, a Browserbase account, an in-house scraper behind
// an HTTP endpoint.
//
// # THIS IS THE COMMERCIALLY IMPORTANT BACKEND AND THE LEAST IMPRESSIVE CODE
//
// Everything else in this repository is the argument; this is the part that
// makes the argument reach anybody. A customer with a working fetching setup
// does not want a better fetcher, and telling them to swap one is how a
// governance product gets declined in the first meeting. They point this at
// what they have and gain a decision, a bound and a record over a tool they
// already own. It is the same move TokenFuse makes with LLM providers: it
// ships no model.
//
// # WHAT IT HONESTLY CANNOT DO
//
// It cannot enforce per subresource. The remote service fetches the page and
// hands back what it got, so there is no moment at which this plane could
// refuse an image on a host the policy forbids. Reporting that the same way as
// a driven backend would claim a guarantee that was never in force, so
// Enforcement says `navigation_only` and the count fields stay nil.
//
// The navigation itself IS enforced, and that is not nothing: the decision
// happens before this type is called at all, so a destination the policy
// refuses never reaches the remote service and never appears in the
// customer's bill for it either.
type External struct {
	// Label names which service this is, and reaches the record as
	// `external:<label>`. Named rather than left as "external" because an
	// operator reading a trail six months later needs to know which of their
	// tools fetched the thing.
	Label string

	// Endpoint is the URL this posts to.
	Endpoint string

	// Key is the operator's credential FOR THEIR OWN SERVICE. It is
	// configuration of this deployment, never something a caller supplies:
	// CLAUDE.md invariant 3 keeps credentials out of the tool surface, and
	// this field is the reason that rule costs nothing.
	Key string

	HTTP *http.Client
}

// NewExternal builds one, with a bounded timeout for the same reason the
// policy client has one: an unbounded wait is a fetch that hangs rather than
// one that is refused, and a hang is a bound that never arrives.
func NewExternal(label, endpoint, key string, timeout time.Duration) *External {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &External{
		Label:    label,
		Endpoint: endpoint,
		Key:      key,
		HTTP:     &http.Client{Timeout: timeout},
	}
}

func (e *External) Name() string { return "external:" + e.Label }

// Enforcement is navigation_only, always.
//
// Not a field, not configurable, and not something a deployment can raise. An
// operator who could set this to per_request would be able to make the record
// claim a control that no code performs, and the record is the product.
func (e *External) Enforcement() decide.Enforcement { return decide.EnforcementNavigationOnly }

type externalRequestDTO struct {
	URL     string `json:"url"`
	Extract string `json:"extract,omitempty"`
	WaitFor string `json:"wait_for,omitempty"`
}

type externalResponseDTO struct {
	FinalURL string `json:"final_url"`
	Content  string `json:"content"`
	Status   int    `json:"status"`
}

// Fetch calls the operator's own service.
//
// It reports what it got and decides nothing. Every refusal already happened.
func (e *External) Fetch(ctx context.Context, req Request) (Result, error) {
	// Built field by field rather than converted, and staticcheck's S1016 is
	// deliberately silenced for it below.
	//
	// The two shapes are convertible TODAY, by coincidence. They are different
	// contracts: Request is what this plane's tool surface accepts, and this
	// DTO is what somebody else's service is told. A conversion would make a
	// field added to the first travel to the second automatically, which is
	// exactly what invariant 3 exists to prevent, and it would do it in a
	// commit that never opened this file.
	//
	//lint:ignore S1016 the two shapes are different contracts that happen to align; see above
	body, err := json.Marshal(externalRequestDTO{
		URL:     req.URL,
		Extract: req.Extract,
		WaitFor: req.WaitFor,
	})
	if err != nil {
		return Result{}, fmt.Errorf("encoding the request for %s: %w", e.Name(), err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("building the request for %s: %w", e.Name(), err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.Key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.Key)
	}

	resp, err := e.HTTP.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("calling %s: %w", e.Name(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return Result{}, fmt.Errorf("%s answered HTTP %d: %s",
			e.Name(), resp.StatusCode, bytes.TrimSpace(snippet))
	}

	var dto externalResponseDTO
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&dto); err != nil {
		return Result{}, fmt.Errorf("reading %s's answer: %w", e.Name(), err)
	}

	final := dto.FinalURL
	if final == "" {
		final = req.URL
	}
	return Result{
		FinalURL:   final,
		Body:       []byte(dto.Content),
		HTTPStatus: dto.Status,
		// Nil, deliberately. This service does not report what the page asked
		// for, and an empty slice here would say it asked for nothing.
		Subresources: nil,
	}, nil
}
