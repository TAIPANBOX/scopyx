package decide

import (
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
	Allowed     bool
	Unreachable bool
	Reason      string
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

// Subresource decides one resource a page asked for, against the policy
// plane's answer about ITS host.
//
// A page is not one destination. It is a document plus fonts, images, scripts
// and XHR, each potentially a different host, and exfiltration through a
// subresource URL is the oldest trick there is. Each host is therefore its own
// question to the policy plane, asked by the caller and answered here in the
// same order Destination keeps: scheme, host and address first, so a
// subresource naming something inside the deployment is refused before any
// policy is read, then the plane's answer, with an unreachable plane a
// refusal of its own kind rather than an allow.
//
// Until 2026-09-16 this took an allow-set the policy plane was supposed to
// return for the navigation. Wardryx sends no such list, so the set was always
// empty and every public host passed on the address rules alone, while the
// record said per_request.
func Subresource(raw string, resolved []netip.Addr, policy PolicyAnswer) Decision {
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
	if policy.Unreachable {
		return deny(DenyPolicyUnreachable,
			"the policy plane could not be asked about %s, and this plane fails closed: %s",
			u.Hostname(), policy.Reason)
	}
	if !policy.Allowed {
		return deny(DenyPolicy, "the policy plane refused %s: %s", u.Hostname(), policy.Reason)
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
