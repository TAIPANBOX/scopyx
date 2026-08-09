package decide

import (
	"net/netip"
	"strings"
	"testing"
)

func addrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("bad test address %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

func allowed() PolicyAnswer { return PolicyAnswer{Allowed: true} }

// One case per refused range. The point of enumerating them rather than
// spot-checking two is that each is here for its own reason, and a rewrite
// that dropped one would still pass a test that only tried 10.0.0.1.
func TestAnAddressNoFetchMayReachIsRefused(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"RFC 1918 ten", "10.0.0.5"},
		{"RFC 1918 172", "172.16.4.4"},
		{"RFC 1918 192", "192.168.1.1"},
		{"loopback", "127.0.0.1"},
		{"cloud metadata", "169.254.169.254"},
		{"carrier-grade NAT", "100.64.0.1"},
		{"this network", "0.0.0.0"},
		{"IPv6 loopback", "::1"},
		{"IPv6 unique local", "fd00::1"},
		{"IPv6 link-local", "fe80::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Destination("https://anything.example/x", addrs(t, c.addr), allowed())
			if d.Verdict != DenyAddress {
				t.Fatalf("got %v, want DenyAddress (reason: %s)", d.Verdict, d.Reason)
			}
			if !strings.Contains(d.Reason, c.addr) {
				t.Errorf("the reason must name the address a reader has to look up: %q", d.Reason)
			}
		})
	}
}

// An IPv4 address wearing an IPv6 hat is the same address. A prefix check
// against the mapped form matches nothing, so this is the bypass that exists
// whenever somebody forgets Unmap.
func TestAnIPv4MappedPrivateAddressIsStillPrivate(t *testing.T) {
	d := Destination("https://anything.example/x", addrs(t, "::ffff:10.0.0.5"), allowed())
	if d.Verdict != DenyAddress {
		t.Fatalf("got %v, want DenyAddress: an IPv4-mapped private address is private (reason: %s)",
			d.Verdict, d.Reason)
	}
}

// EVERY resolved address must be acceptable. A name answering with one public
// and one private address is the rebinding attack written into a single
// response, and taking the first would make the refusal depend on record order.
func TestOnePrivateAddressAmongPublicOnesRefusesTheFetch(t *testing.T) {
	d := Destination("https://anything.example/x", addrs(t, "93.184.216.34", "10.0.0.5"), allowed())
	if d.Verdict != DenyAddress {
		t.Fatalf("got %v, want DenyAddress (reason: %s)", d.Verdict, d.Reason)
	}
}

func TestAHostInsideTheDeploymentIsRefusedByName(t *testing.T) {
	for _, host := range []string{
		"vault.internal", "db.local", "svc.cluster.local", "localhost", "VAULT.INTERNAL", "vault.internal.",
	} {
		d := Destination("https://"+host+"/x", addrs(t, "93.184.216.34"), allowed())
		if d.Verdict != DenyHost {
			t.Errorf("%s: got %v, want DenyHost (reason: %s)", host, d.Verdict, d.Reason)
		}
	}
}

func TestOnlyHttpAndHttpsAreFetched(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd", "gopher://x/1", "ftp://x/y", "data:text/plain,hi",
	} {
		d := Destination(raw, addrs(t, "93.184.216.34"), allowed())
		if d.Verdict != DenyScheme {
			t.Errorf("%s: got %v, want DenyScheme", raw, d.Verdict)
		}
	}
}

// The order is load-bearing. A URL naming something inside the deployment is
// refused even when a policy would have allowed it, because the policy language
// talks about domains an agent may reach and was never written to contemplate
// the metadata endpoint.
func TestALocalAddressIsRefusedEvenWhenPolicyAllowsIt(t *testing.T) {
	d := Destination("https://friendly.example/x", addrs(t, "169.254.169.254"),
		PolicyAnswer{Allowed: true, AllowDomains: []string{"friendly.example"}})
	if d.Verdict != DenyAddress {
		t.Fatalf("got %v, want DenyAddress: a policy allow does not reach past the address rules", d.Verdict)
	}
}

// CLAUDE.md invariant 7. The estate fails open and documents it; this plane
// does not, because one that fails open is an unrestricted fetch proxy and the
// failure is silent.
func TestAnUnreachablePolicyPlaneRefusesTheFetch(t *testing.T) {
	d := Destination("https://example.com/x", addrs(t, "93.184.216.34"),
		PolicyAnswer{Unreachable: true, Reason: "dial tcp: connection refused"})
	if d.Verdict != DenyPolicyUnreachable {
		t.Fatalf("got %v, want DenyPolicyUnreachable", d.Verdict)
	}
	if d.Verdict == DenyPolicy {
		t.Fatal("an unreachable plane must not report as a refusal somebody decided")
	}
	if !strings.Contains(d.Reason, "connection refused") {
		t.Errorf("the reason must carry what went wrong underneath: %q", d.Reason)
	}
}

// The two refusals are different facts, and collapsing them sends an operator
// to edit a policy that is working.
func TestARefusalByPolicyAndOneNobodyCouldMakeAreDistinct(t *testing.T) {
	refused := Destination("https://example.com/x", addrs(t, "93.184.216.34"),
		PolicyAnswer{Allowed: false, Reason: "not in allow_domains"})
	unreachable := Destination("https://example.com/x", addrs(t, "93.184.216.34"),
		PolicyAnswer{Unreachable: true, Reason: "timeout"})
	if refused.Verdict == unreachable.Verdict {
		t.Fatal("a refusal by policy and one because policy could not be asked must not share a verdict")
	}
	if refused.Verdict != DenyPolicy || unreachable.Verdict != DenyPolicyUnreachable {
		t.Fatalf("got %v and %v", refused.Verdict, unreachable.Verdict)
	}
}

func TestAHostThatResolvesToNothingIsNotFetched(t *testing.T) {
	d := Destination("https://example.com/x", nil, allowed())
	if d.Verdict != DenyAddress {
		t.Fatalf("got %v, want DenyAddress", d.Verdict)
	}
}

func TestAnAllowedFetchIsAllowed(t *testing.T) {
	d := Destination("https://example.com/x", addrs(t, "93.184.216.34"), allowed())
	if !d.Verdict.Allowed() {
		t.Fatalf("got %v (%s), want allow", d.Verdict, d.Reason)
	}
}

// ---------------------------------------------------------------- redirects

// The classic allowlist bypass: an allowed host answers 302 to a denied one,
// and a check that evaluated only the URL the caller passed never sees it.
func TestAnAllowedHostRedirectingToADeniedOneIsRefusedAtTheHop(t *testing.T) {
	limits := Limits{MaxRedirects: 5}
	d := Redirect(1, "https://evil.example/x", addrs(t, "93.184.216.34"),
		PolicyAnswer{Allowed: false, Reason: "not in allow_domains"}, limits)
	if d.Verdict != DenyPolicy {
		t.Fatalf("got %v, want DenyPolicy at the hop", d.Verdict)
	}
}

func TestARedirectIntoALocalAddressIsRefusedAtTheHop(t *testing.T) {
	d := Redirect(1, "https://friendly.example/x", addrs(t, "169.254.169.254"), allowed(), Limits{MaxRedirects: 5})
	if d.Verdict != DenyAddress {
		t.Fatalf("got %v, want DenyAddress at the hop", d.Verdict)
	}
}

func TestARedirectChainPastItsBoundIsRefused(t *testing.T) {
	limits := Limits{MaxRedirects: 3}
	if d := Redirect(3, "https://example.com/x", addrs(t, "93.184.216.34"), allowed(), limits); !d.Verdict.Allowed() {
		t.Fatalf("hop 3 of 3 is inside the bound and must be allowed, got %v", d.Verdict)
	}
	d := Redirect(4, "https://example.com/x", addrs(t, "93.184.216.34"), allowed(), limits)
	if d.Verdict != DenyRedirectDepth {
		t.Fatalf("hop 4 of 3 must be refused, got %v", d.Verdict)
	}
}

// ------------------------------------------------------------- subresources

func TestASubresourceOutsideTheAllowSetIsRefused(t *testing.T) {
	d := Subresource("https://tracker.example/pixel.gif", addrs(t, "93.184.216.34"),
		[]string{"example.com", ".cdn.example.com"})
	if d.Verdict != DenyPolicy {
		t.Fatalf("got %v, want DenyPolicy", d.Verdict)
	}
}

func TestASubresourceInsideTheAllowSetIsAllowed(t *testing.T) {
	for _, host := range []string{"example.com", "img.cdn.example.com", "cdn.example.com"} {
		d := Subresource("https://"+host+"/a.png", addrs(t, "93.184.216.34"),
			[]string{"example.com", ".cdn.example.com"})
		if !d.Verdict.Allowed() {
			t.Errorf("%s: got %v (%s), want allow", host, d.Verdict, d.Reason)
		}
	}
}

// Suffix matching without the leading-dot distinction is the bug this avoids:
// `example.com` would otherwise match `notexample.com`, which belongs to
// somebody else and merely ends in the right letters.
func TestADomainThatMerelyEndsInAnAllowedOneIsNotAllowed(t *testing.T) {
	d := Subresource("https://notexample.com/a.png", addrs(t, "93.184.216.34"), []string{"example.com"})
	if d.Verdict != DenyPolicy {
		t.Fatalf("got %v, want DenyPolicy: notexample.com is not example.com", d.Verdict)
	}
}

// An empty allow-set means the policy declared no domain restriction, so
// subresources are bounded by the address rules and nothing else. The address
// rules still apply, which is the half worth asserting.
func TestWithNoAllowSetASubresourceIsStillBoundedByTheAddressRules(t *testing.T) {
	if d := Subresource("https://anywhere.example/a.png", addrs(t, "93.184.216.34"), nil); !d.Verdict.Allowed() {
		t.Fatalf("no allow-set means no domain restriction, got %v", d.Verdict)
	}
	if d := Subresource("https://anywhere.example/a.png", addrs(t, "169.254.169.254"), nil); d.Verdict != DenyAddress {
		t.Fatalf("the address rules still apply with no allow-set, got %v", d.Verdict)
	}
}
