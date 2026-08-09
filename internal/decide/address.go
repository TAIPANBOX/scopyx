// Package decide is the policy pipeline: it answers whether a fetch may
// happen, and it does so without touching the network, the disk or a clock.
//
// Everything here is a pure function of its arguments. Resolution, fetching
// and recording happen at the edges and hand this package values. That is not
// tidiness: an enforcement decision that can only be exercised with a live DNS
// server and a live policy plane is one nobody tests the interesting cases of,
// and the interesting cases here are the refusals.
package decide

import (
	"net/netip"
	"strings"
)

// Refused address ranges, and why each is here.
//
// A component whose job is "fetch a URL an agent chose" is a server-side
// request forgery engine unless it is built not to be. An injected agent asks
// for the cloud metadata endpoint or an internal admin port, and a naive
// implementation obliges.
//
// The default backend renders inside somebody else's network, which closes the
// reach-our-cluster case by construction. That argument does NOT survive a
// backend running on the operator's own machine, which the adapter allows on
// purpose, so the guard lives here rather than in a backend where it would
// hold for one implementation and quietly not for the next.
var refusedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, and every cloud metadata service
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("::1/128"),        // IPv6 loopback
	netip.MustParsePrefix("fc00::/7"),       // IPv6 unique local
	netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local
}

// Suffixes that name something inside a deployment rather than on the internet.
// Refused by name as well as by address, because a name that resolves to a
// public address today can resolve elsewhere tomorrow and the fetch would have
// been legitimate in between.
var refusedSuffixes = []string{
	".internal",
	".local",
	".localdomain",
	".cluster.local",
	"localhost",
}

// AddressRefused reports whether this address is one no agent fetch may reach,
// and the reason if so.
//
// The reason is returned rather than logged because it travels: it becomes the
// refusal a caller sees and the line in the record, and "denied" without a
// cause is a support ticket.
func AddressRefused(addr netip.Addr) (bool, string) {
	if !addr.IsValid() {
		return true, "the address could not be parsed, and an unparseable address is refused rather than guessed at"
	}
	// Unmap first: ::ffff:10.0.0.1 is 10.0.0.1 wearing an IPv6 hat, and a
	// prefix check against the mapped form matches nothing at all.
	addr = addr.Unmap()
	for _, p := range refusedPrefixes {
		if p.Contains(addr) {
			return true, "the address is in " + p.String() + ", which is not somewhere an agent fetch may reach"
		}
	}
	if addr.IsMulticast() || addr.IsInterfaceLocalMulticast() {
		return true, "the address is multicast"
	}
	return false, ""
}

// HostRefused reports whether this hostname names something inside a
// deployment. Case-insensitive, and a trailing dot (the fully qualified form)
// is stripped first: `foo.internal.` and `foo.internal` are one name and a
// check that saw two would be bypassed by typing a dot.
func HostRefused(host string) (bool, string) {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return true, "the URL names no host"
	}
	for _, s := range refusedSuffixes {
		if h == strings.TrimPrefix(s, ".") || strings.HasSuffix(h, s) {
			return true, "the host ends in " + s + ", which names something inside a deployment rather than on the internet"
		}
	}
	return false, ""
}
