package decide

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Verdict is what the pipeline decided, and each value is a DIFFERENT fact for
// whoever reads the trail.
//
// Collapsing them would be the cheaper enum and the wrong one: an operator
// chasing "why did this fetch not happen" needs to know whether a policy
// refused it, whether the policy plane could not be asked, or whether it never
// reached a policy question at all because the address was one no fetch may
// reach. Those three send a person to three different places.
type Verdict int

const (
	// Allow: this fetch may proceed.
	Allow Verdict = iota
	// DenyScheme: not http or https.
	DenyScheme
	// DenyHost: the host names something inside a deployment.
	DenyHost
	// DenyAddress: the address is one no agent fetch may reach.
	DenyAddress
	// DenyPolicy: the policy plane refused it.
	DenyPolicy
	// DenyPolicyUnreachable: the policy plane could not be asked, and this
	// plane fails CLOSED (CLAUDE.md invariant 7). Deliberately distinct from
	// DenyPolicy: one means somebody decided, the other means nobody could,
	// and reporting the second as the first sends an operator to edit a policy
	// that is working.
	DenyPolicyUnreachable
	// DenyRedirectDepth: the redirect chain went past its bound.
	DenyRedirectDepth
	// DenyCap: a local rate cap refused it before anything left.
	DenyCap
	// DenyRobots: the site's own robots.txt disallows this path for this
	// user-agent.
	//
	// Distinct from DenyPolicy on purpose, and the distinction is not
	// cosmetic: one is the operator's rule and the other is somebody else's
	// preference. An operator reading a trail needs to know which of the two
	// stopped their agent, because only one of them is theirs to change.
	DenyRobots
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case DenyScheme:
		return "deny_scheme"
	case DenyHost:
		return "deny_host"
	case DenyAddress:
		return "deny_address"
	case DenyPolicy:
		return "deny_policy"
	case DenyPolicyUnreachable:
		return "deny_policy_unreachable"
	case DenyRedirectDepth:
		return "deny_redirect_depth"
	case DenyCap:
		return "deny_cap"
	case DenyRobots:
		return "deny_robots"
	}
	return "unknown"
}

// Allowed is true only for Allow. Written as a method rather than left to
// callers comparing against the zero value, because `v == 0` reads as "unset"
// and this enum's zero value is "yes, fetch it".
func (v Verdict) Allowed() bool { return v == Allow }

// Decision is a verdict and the sentence a human gets.
type Decision struct {
	Verdict Verdict
	Reason  string
}

func allow() Decision { return Decision{Verdict: Allow} }

func deny(v Verdict, format string, args ...any) Decision {
	return Decision{Verdict: v, Reason: fmt.Sprintf(format, args...)}
}

// PolicyAnswer is what the policy plane said about one destination.
//
// Unreachable is a field rather than an error return because it is not an
// error in this package's sense: the pipeline has a defined behaviour for it
// and that behaviour is a refusal. An error would invite a caller to log it
// and carry on, which is the fail-open this plane refuses.
type PolicyAnswer struct {
	Allowed      bool
	Unreachable  bool
	Reason       string
	AllowDomains []string
}

// Limits are the bounds a fetch runs inside. Every one has a finite default in
// the caller; a zero here means "no bound", which is legal for a caller that
// deliberately unset one and is never what config produces.
type Limits struct {
	MaxRedirects    int
	MaxBodyBytes    int64
	MaxSubresources int
}

// Destination decides one URL, before anything leaves.
//
// The order is the whole of it. Scheme and host are answered from the URL,
// address from what the resolver returned, and only then is the policy plane
// consulted. A cheap local refusal never becomes a network call to a policy
// plane, and, more importantly, a URL that names something inside the
// deployment is refused even when a policy would have allowed it: the policy
// language talks about domains an agent may reach, and it was never written to
// contemplate the metadata endpoint.
//
// `resolved` is what the host resolved to at fetch time, and it is a parameter
// rather than something this function looks up on purpose. Re-resolving at the
// moment of the fetch is what closes DNS rebinding, and that is the caller's
// job; passing an address here that was resolved minutes ago would satisfy
// this check and fetch something else.
func Destination(raw string, resolved []netip.Addr, policy PolicyAnswer) Decision {
	u, err := url.Parse(raw)
	if err != nil {
		return deny(DenyScheme, "the URL could not be parsed: %v", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return deny(DenyScheme, "the scheme %q is not http or https", u.Scheme)
	}

	if refused, why := HostRefused(u.Hostname()); refused {
		return deny(DenyHost, "%s", why)
	}

	// EVERY resolved address must be acceptable, not just one. A name that
	// answers with a public address and a private one is the rebinding attack
	// spelled out in a single response, and picking the first would make the
	// refusal depend on record order.
	if len(resolved) == 0 {
		return deny(DenyAddress, "the host resolved to no address, and a fetch is not attempted against a name that resolves to nothing")
	}
	for _, a := range resolved {
		if refused, why := AddressRefused(a); refused {
			return deny(DenyAddress, "%s resolved to %s: %s", u.Hostname(), a, why)
		}
	}

	if policy.Unreachable {
		return deny(DenyPolicyUnreachable,
			"the policy plane could not be asked, and this plane fails closed: %s", policy.Reason)
	}
	if !policy.Allowed {
		return deny(DenyPolicy, "the policy plane refused it: %s", policy.Reason)
	}
	return allow()
}

// Subresource decides one resource a page asked for, against the allow-set the
// policy plane returned for the navigation.
//
// A page is not one destination. It is a document plus fonts, images, scripts
// and XHR, each potentially a different host, and exfiltration through a
// subresource URL is the oldest trick there is. An empty allow-set means the
// policy declared no domain restriction, so subresources are bounded by the
// address rules and nothing else.
func Subresource(raw string, resolved []netip.Addr, allowDomains []string) Decision {
	u, err := url.Parse(raw)
	if err != nil {
		return deny(DenyScheme, "the subresource URL could not be parsed: %v", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return deny(DenyScheme, "the subresource scheme %q is not http or https", u.Scheme)
	}
	if refused, why := HostRefused(u.Hostname()); refused {
		return deny(DenyHost, "%s", why)
	}
	for _, a := range resolved {
		if refused, why := AddressRefused(a); refused {
			return deny(DenyAddress, "%s resolved to %s: %s", u.Hostname(), a, why)
		}
	}
	if len(allowDomains) > 0 && !domainAllowed(u.Hostname(), allowDomains) {
		return deny(DenyPolicy, "%s is not in the domains this agent may reach", u.Hostname())
	}
	return allow()
}

// Redirect decides one hop.
//
// Every hop is a new decision, because an allowed host answering 302 to a
// denied one is the classic allowlist bypass and it is invisible to any check
// that evaluates only the URL the caller passed. `hop` is 1 for the first
// redirect followed.
func Redirect(hop int, raw string, resolved []netip.Addr, policy PolicyAnswer, limits Limits) Decision {
	if limits.MaxRedirects > 0 && hop > limits.MaxRedirects {
		return deny(DenyRedirectDepth,
			"the redirect chain reached %d hops, past the bound of %d", hop, limits.MaxRedirects)
	}
	return Destination(raw, resolved, policy)
}

// domainAllowed matches a host against the policy's domains. A leading dot on
// an entry means "this domain and anything under it"; an entry without one
// matches the host exactly.
//
// Suffix matching without that distinction is the bug this avoids:
// `example.com` would otherwise match `notexample.com`, which is somebody
// else's domain that happens to end in the right letters.
func domainAllowed(host string, allow []string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a), "."))
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, ".") {
			if h == strings.TrimPrefix(a, ".") || strings.HasSuffix(h, a) {
				return true
			}
			continue
		}
		if h == a {
			return true
		}
	}
	return false
}

// --- the allow-set, carried to a backend that fetches subresources ---
//
// A rendering backend decides forty requests the caller never named, and it
// must decide them against the SAME allow-set the navigation was granted. It
// cannot be a field on the backend: one backend serves concurrent fetches, and
// a field would be one fetch's policy applied to another's page.
//
// So it travels with the fetch, in its context. This lives here, beside
// `Subresource`, because the allow-set is that function's parameter and a
// helper in the backend package would be a second place that knows what a
// policy answer contains.

type allowKey struct{}

// WithAllowDomains carries the navigation's allow-set.
func WithAllowDomains(ctx context.Context, domains []string) context.Context {
	return context.WithValue(ctx, allowKey{}, domains)
}

// AllowDomainsFrom reports the allow-set, or nil.
//
// Nil means the policy declared no domain restriction, which `Subresource`
// already reads as "bounded by the address rules and nothing else". It does
// NOT mean "allow nothing": a request with no allow-set still passes through
// scheme, host and address, and a backend that read nil as a refusal would
// break every page an unrestricted policy permits.
func AllowDomainsFrom(ctx context.Context) []string {
	d, _ := ctx.Value(allowKey{}).([]string)
	return d
}
