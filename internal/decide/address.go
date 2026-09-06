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
	netip.MustParsePrefix("10.0.0.0/8"),         // RFC 1918
	netip.MustParsePrefix("172.16.0.0/12"),      // RFC 1918
	netip.MustParsePrefix("192.168.0.0/16"),     // RFC 1918
	netip.MustParsePrefix("127.0.0.0/8"),        // loopback
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local, and every cloud metadata service
	netip.MustParsePrefix("100.64.0.0/10"),      // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments (RFC 6890)
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking (RFC 2544)
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved for future use
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
	netip.MustParsePrefix("::1/128"),            // IPv6 loopback
	netip.MustParsePrefix("::/128"),             // IPv6 unspecified
	netip.MustParsePrefix("fc00::/7"),           // IPv6 unique local
	netip.MustParsePrefix("fe80::/10"),          // IPv6 link-local
	netip.MustParsePrefix("fec0::/10"),          // deprecated IPv6 site-local
}

// These two do not go in refusedPrefixes: they are wrappers that embed an
// IPv4 address rather than naming a destination themselves, and a translator
// may route the embedded address to RFC 1918 space. Refusing the wrapper
// outright would also refuse every ordinary public address travelling over
// NAT64 or 6to4, so the embedded address is checked against the same rules
// as any other destination instead.
var (
	nat64Prefix     = netip.MustParsePrefix("64:ff9b::/96") // NAT64 (RFC 6052)
	sixToFourPrefix = netip.MustParsePrefix("2002::/16")    // 6to4 (RFC 3056)
)

// embeddedIPv4 pulls the 32 bits at byteOffset out of addr's 16-byte form.
// NAT64 carries the IPv4 address in the last 4 bytes (offset 12); 6to4
// carries it right after the /16 prefix (offset 2).
func embeddedIPv4(addr netip.Addr, byteOffset int) netip.Addr {
	b := addr.As16()
	return netip.AddrFrom4([4]byte{b[byteOffset], b[byteOffset+1], b[byteOffset+2], b[byteOffset+3]})
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
	if addr.IsUnspecified() {
		return true, "the address is unspecified"
	}
	if nat64Prefix.Contains(addr) {
		embedded := embeddedIPv4(addr, 12)
		if refused, reason := AddressRefused(embedded); refused {
			return true, "the address embeds " + embedded.String() + " via NAT64 (64:ff9b::/96): " + reason
		}
		return false, ""
	}
	if sixToFourPrefix.Contains(addr) {
		embedded := embeddedIPv4(addr, 2)
		if refused, reason := AddressRefused(embedded); refused {
			return true, "the address embeds " + embedded.String() + " via 6to4 (2002::/16): " + reason
		}
		return false, ""
	}
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
