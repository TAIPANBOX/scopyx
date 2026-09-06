package decide

import (
	"net/netip"
	"strings"
	"testing"
)

// The ranges added after the original sweep, because the first pass missed
// them and each is a real path an SSRF payload can reach. One case per new
// prefix, for the same reason the hostile test above enumerates rather than
// samples: a rewrite that dropped one would still pass a test that only
// tried the ranges everybody remembers.
func TestEveryRefusedRangeIsRefused(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"IETF protocol assignments", "192.0.0.8"},
		{"benchmarking (RFC 2544)", "198.19.0.1"},
		{"reserved", "240.0.0.1"},
		{"limited broadcast", "255.255.255.255"},
		{"IPv6 unspecified", "::"},
		{"IPv4 unspecified", "0.0.0.0"},
		{"deprecated IPv6 site-local", "fec0::1"},
		{"NAT64 embedding RFC 1918", "64:ff9b::0a00:0001"}, // embeds 10.0.0.1
		{"6to4 embedding RFC 1918", "2002:0a00:0001::1"},   // embeds 10.0.0.1
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(c.addr)
			if err != nil {
				t.Fatalf("the test's own address does not parse: %v", err)
			}
			refused, reason := AddressRefused(addr)
			if !refused {
				t.Fatalf("%s (%s) is allowed. Nothing downstream would look "+
					"wrong: the fetch succeeds and the record says so", c.addr, c.name)
			}
			if strings.TrimSpace(reason) == "" {
				t.Fatalf("%s is refused with no reason", c.addr)
			}
		})
	}
}

// A 6to4 address is a wrapper, not a destination in its own right, and the
// wrapper must not decide the outcome by itself: a public address embedded in
// one has to stay reachable or every 6to4 client on the internet becomes
// unreachable through this plane, which is a far bigger hole than the one
// this range check closes.
func TestAPublicAddressIsStillAllowed(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"ordinary public IPv4", "8.8.8.8"},
		{"ordinary public IPv6", "2606:4700::1111"},
		{"6to4 embedding a public IPv4", "2002:0808:0808::1"},   // embeds 8.8.8.8
		{"NAT64 embedding a public IPv4", "64:ff9b::0808:0808"}, // embeds 8.8.8.8
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(c.addr)
			if err != nil {
				t.Fatalf("the test's own address does not parse: %v", err)
			}
			if refused, reason := AddressRefused(addr); refused {
				t.Fatalf("%s (%s) is refused (%q). It is on the public internet, "+
					"and a range check that swallows its wrapper too wide takes "+
					"real destinations with it", c.addr, c.name, reason)
			}
		})
	}
}
