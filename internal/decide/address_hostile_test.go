package decide

import (
	"net/netip"
	"strings"
	"testing"
)

// The SSRF guards, swept rather than sampled.
//
// This is the pair of functions that stops "fetch a URL an agent chose" from
// being a server-side request forgery engine, and a hole in either is silent
// by construction: the fetch succeeds, the record says it succeeded, and
// nothing anywhere reads differently from a legitimate fetch of a public page.
// There is no failing test to notice, because the thing that went wrong is
// that something worked.
//
// So both directions, and both written as sweeps. A refusal list checked with
// three examples is a list nobody knows the edges of.

func TestEveryAddressAnAgentMustNotReachIsRefused(t *testing.T) {
	cases := []struct {
		addr string
		why  string
	}{
		{"169.254.169.254", "AWS, GCP and Azure instance metadata, the whole reason this list exists"},
		{"169.254.170.2", "ECS task metadata"},
		{"127.0.0.1", "loopback: whatever else is listening on this box"},
		{"127.1.2.3", "the rest of 127/8, which is loopback too and is often forgotten"},
		{"10.0.0.1", "RFC 1918"},
		{"10.255.255.254", "the far end of RFC 1918"},
		{"172.16.0.1", "RFC 1918, the range people get wrong"},
		{"172.31.255.254", "the far end of it"},
		{"192.168.1.1", "RFC 1918, and every home router admin page"},
		{"100.64.0.1", "carrier-grade NAT"},
		{"0.0.0.0", "this network"},
		{"0.1.2.3", "the rest of 0/8"},
		{"::1", "IPv6 loopback"},
		{"fc00::1", "IPv6 unique local"},
		{"fd12:3456::1", "the rest of fc00::/7, which fd00:: is in and which a /8 check would miss"},
		{"fe80::1", "IPv6 link-local"},
		{"224.0.0.1", "multicast"},
		{"ff02::1", "IPv6 all-nodes multicast"},
		{"ff01::1", "interface-local multicast"},

		// The mapped forms. ::ffff:169.254.169.254 is the metadata endpoint
		// wearing an IPv6 hat, and a prefix check that did not unmap first
		// would match nothing at all and let it straight through.
		{"::ffff:169.254.169.254", "the metadata endpoint as a mapped IPv6 address"},
		{"::ffff:127.0.0.1", "loopback, mapped"},
		{"::ffff:10.0.0.1", "RFC 1918, mapped"},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(c.addr)
			if err != nil {
				t.Fatalf("the test's own address does not parse: %v", err)
			}
			refused, reason := AddressRefused(addr)
			if !refused {
				t.Fatalf("%s is allowed. %s. Nothing downstream would look "+
					"wrong: the fetch succeeds and the record says so",
					c.addr, c.why)
			}
			if strings.TrimSpace(reason) == "" {
				t.Fatalf("%s is refused with no reason. The reason travels into "+
					"the refusal a caller sees and the line in the record, and "+
					"a denial without a cause is a support ticket", c.addr)
			}
		})
	}
}

// An address that did not parse is refused rather than guessed at. This is the
// branch that decides what happens when resolution hands back something
// unexpected, and treating a zero value as allowed would open everything.
func TestAnAddressThatIsNotAnAddressIsRefused(t *testing.T) {
	refused, reason := AddressRefused(netip.Addr{})
	if !refused {
		t.Fatal("the zero Addr is allowed: anything that fails to parse would " +
			"be fetched")
	}
	if !strings.Contains(reason, "unparseable") && !strings.Contains(reason, "could not be parsed") {
		t.Fatalf("the reason does not say the address was unreadable: %q", reason)
	}
}

// The other direction. Refusing the public internet would make this plane
// useless, and a too-wide prefix is the easy way to get there.
func TestOrdinaryPublicAddressesAreAllowed(t *testing.T) {
	for _, s := range []string{
		"1.1.1.1", "8.8.8.8", "93.184.216.34",
		"11.0.0.1",       // just outside 10/8
		"172.15.0.1",     // just below 172.16/12
		"172.32.0.1",     // just above it
		"192.167.0.1",    // just below 192.168/16
		"100.63.255.255", // just below 100.64/10
		"128.0.0.1",      // just above 127/8
		"169.253.0.1",    // just below link-local
		"169.255.0.1",    // just above it
		"2606:4700:4700::1111",
		"2001:db8::1",
	} {
		t.Run(s, func(t *testing.T) {
			addr := netip.MustParseAddr(s)
			if refused, reason := AddressRefused(addr); refused {
				t.Fatalf("%s is refused (%q). It is on the public internet, and "+
					"a prefix one bit too wide takes real destinations with it",
					s, reason)
			}
		})
	}
}

func TestEveryInternalNameShapeIsRefused(t *testing.T) {
	cases := []string{
		"api.internal",
		"API.INTERNAL",
		"api.internal.", // fully qualified: a trailing dot must not bypass it
		"API.Internal.", // both at once
		"printer.local",
		"host.localdomain",
		"wardryx.default.svc.cluster.local",
		"localhost",
		"LOCALHOST",
		"localhost.",
		"anything.localhost",
	}
	for _, h := range cases {
		t.Run(h, func(t *testing.T) {
			refused, reason := HostRefused(h)
			if !refused {
				t.Fatalf("%q is allowed. It names something inside a deployment, "+
					"and a name is refused as well as an address because a name "+
					"that resolves publicly today can resolve elsewhere tomorrow", h)
			}
			if strings.TrimSpace(reason) == "" {
				t.Fatalf("%q is refused with no reason", h)
			}
		})
	}
}

func TestAUrlWithNoHostIsRefused(t *testing.T) {
	refused, reason := HostRefused("")
	if !refused {
		t.Fatal("an empty host is allowed")
	}
	if !strings.Contains(reason, "no host") {
		t.Fatalf("the reason does not say the URL named no host: %q", reason)
	}
}

// Names that merely contain one of the words are ordinary public names.
func TestOrdinaryPublicNamesAreAllowed(t *testing.T) {
	for _, h := range []string{
		"example.com",
		"internal.example.com", // the word, but not at the end
		"local.example.com",
		"cluster.local.example.com",
		"my-internal-docs.com",
		"nonlocaldomain.com",
	} {
		t.Run(h, func(t *testing.T) {
			if refused, reason := HostRefused(h); refused {
				t.Fatalf("%q is refused (%q). It is an ordinary public name, and "+
					"a suffix check that matched anywhere in the string would "+
					"take a great many of them", h, reason)
			}
		})
	}
}
