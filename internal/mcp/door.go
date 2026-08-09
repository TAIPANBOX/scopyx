package mcp

import (
	"crypto/subtle"
	"fmt"
	"net"
	"strings"
)

// ClientKeyHeader is the credential this plane's own door reads.
//
// Its own door, on purpose. The TokenFuse MCP broker in front of this service
// is a layer that adds four things when present, not a precondition for the
// plane working: CLAUDE.md's standalone mode is a tested path rather than a
// README claim, and a standalone deployment with no door would be an open
// fetch proxy on somebody's network.
const ClientKeyHeader = "X-Scopyx-Key"

// Keys is the set of client credentials this door accepts. Empty means the
// door authenticates nobody, which is the default and is only safe on
// loopback, which RefuseOpenBind enforces.
type Keys struct {
	accepted []string
	// identity maps a credential to the agent it belongs to. A credential with
	// no entry authenticates and names nobody.
	identity map[string]string
}

// ParseKeys reads `key1,key2,...`, and optionally `key=agent://domain/name`.
//
// # WHY THE CREDENTIAL CARRIES THE IDENTITY
//
// Invariant 6: identity comes from an authenticated caller and never from a
// claim. The only authenticated fact this door has is which credential was
// presented, so that is what an identity may be derived from. A header naming
// the agent would be the caller telling us who it is, and a policy carrying
// `deny_if_unattested` would then be satisfied by a string the caller wrote for
// itself.
//
// A credential given without an identity still authenticates. It just cannot be
// spoken for: every fetch through it reaches the policy plane with no subject,
// which `policy.Client` turns into unreachable and `decide` turns into a
// refusal that says so. That is the fail-closed path working rather than a
// special case, and it is why this returns no error for the bare form.
//
// Blank entries are dropped rather than accepted as an empty credential, which
// would let a caller sending no header match.
func ParseKeys(raw string) Keys {
	var out []string
	ids := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// SplitN, not Split: an identity is a URI and contains no `=` today,
		// but a value that grew one would otherwise be silently cut in half.
		key, id, found := strings.Cut(entry, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out = append(out, key)
		if found {
			if id = strings.TrimSpace(id); id != "" {
				ids[key] = id
			}
		}
	}
	return Keys{accepted: out, identity: ids}
}

// Identity is the agent a credential belongs to, or empty.
//
// Empty is a real answer and not an error: see ParseKeys. The caller must not
// substitute anything for it.
func (k Keys) Identity(presented string) string {
	if !k.Allow(presented) {
		return ""
	}
	return k.identity[presented]
}

// Configured reports whether any credential is required.
func (k Keys) Configured() bool { return len(k.accepted) > 0 }

// Allow reports whether a presented credential is accepted.
//
// Compared in constant time. The estate's other door notes that it uses a
// plain map lookup and that moving to a constant-time comparison is a posture
// change belonging across every plane at once rather than smuggled into one.
// This plane is new, so it starts on the right side of that rather than
// inheriting a decision made for somebody else's compatibility.
func (k Keys) Allow(presented string) bool {
	if !k.Configured() {
		return true
	}
	var ok bool
	for _, a := range k.accepted {
		if subtle.ConstantTimeCompare([]byte(a), []byte(presented)) == 1 {
			ok = true
		}
	}
	return ok
}

// IsLoopback reports whether a bind address is loopback.
//
// Asked of the standard library rather than matched as a string, for the
// reason the estate's other door records: `net.IP.IsLoopback` knows the whole
// of 127.0.0.0/8 is loopback rather than the one address a string match would
// name, and knows `::1` without it being spelled out. `localhost` is handled
// separately because it is a name, not something ParseIP accepts.
func IsLoopback(addr string) bool {
	addr = strings.TrimSpace(addr)
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RefuseOpenBind returns the error this service must refuse to start with, or
// an empty string to proceed.
//
// A non-loopback bind with no credential configured is an unauthenticated
// fetch proxy on somebody's network: anything that reaches the port can make
// this plane fetch on its behalf, under the operator's egress allowance and
// with the operator's name on the record. That is a different failure from a
// leaked credential, because there is nothing to leak.
//
// It refuses rather than warns, and the opt-out exists because an operator who
// has deliberately decided to run it open should need one variable rather than
// a fork. Two cases are unaffected on purpose: a wide bind WITH credentials,
// which is a posture an operator may choose, and the loopback default, which
// must not get harder for the common local case.
func RefuseOpenBind(addr string, keys Keys, allowOpenBind bool) string {
	if keys.Configured() || allowOpenBind || IsLoopback(addr) {
		return ""
	}
	return fmt.Sprintf(
		"refusing to start: scopyx is bound to %s, which is not loopback, and no client "+
			"credentials are configured (SCOPYX_KEYS is unset). Anything that reaches this "+
			"address could make this plane fetch on its behalf, under your egress allowance "+
			"and with your name on the record. Set SCOPYX_KEYS=\"key1,key2\" to require a "+
			"credential, bind to loopback instead (SCOPYX_ADDR=127.0.0.1:4300, the default), "+
			"or, if you have deliberately decided to run it open, set "+
			"SCOPYX_ALLOW_OPEN_BIND=1.", addr)
}

// TruthyEnv parses an opt-out variable the way the estate does: only `1` and
// `true` count.
//
// Any-non-empty-string would be the obvious reading and is wrong here. An
// operator who writes SCOPYX_ALLOW_OPEN_BIND=0 or =no means the opposite of
// what it would then do, and a security opt-out that turns itself on when told
// no is the worst possible spelling.
func TruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true":
		return true
	}
	return false
}
