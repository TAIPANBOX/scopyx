// Package robots reads a site's own stated preference, per RFC 9309.
//
// # WHY THIS EXISTS, AND WHY IT WAS A DEBT RATHER THAN A FEATURE
//
// CLAUDE.md invariant 9 said `robots.txt` is honoured by default. Nothing read
// it. The claim came from the design document, reached the README and the
// public site, and was true nowhere. It is the one clause in that invariant
// that needs CODE to be true: the others (no stealth, no CAPTCHA solving, no
// fingerprint matching, no bulk crawl) hold because no code path exists to do
// them, and an absence enforces itself.
//
// # WE ARE NOT A CRAWLER, AND THE DIFFERENCE DECIDES ONE THING
//
// RFC 9309 is written for automatic crawlers, whose defining property is
// volume. This plane fetches one page because one agent was asked for it. Every
// disallow rule is honoured exactly as written, because a site's stated
// preference does not stop applying just because we arrive once.
//
// The difference shows up in ONE place: what to do when robots.txt cannot be
// read. Crawler guidance says treat a 5xx as a complete disallow, which is
// right when you are about to make ten thousand requests and wrong here: it
// would let a site's transient error stop an operator's own governed work, and
// hand any origin a way to deny service to the agents fetching it.
//
// So an unreadable robots.txt ALLOWS, and the result says it could not be read.
// That is the estate's rule about silent zeroes applied to somebody else's
// server: "could not look" is a reportable state, never an answer. An operator
// who wants the crawler posture sets SCOPYX_ROBOTS=strict and gets a refusal
// instead.
package robots

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// UserAgent is the product token this plane matches on, and it is the same name
// it sends. A fetcher that obeyed rules written for a name it does not use
// would be honouring somebody else's robots.txt.
const UserAgent = "scopyx"

// Mode is how an unreadable robots.txt is treated.
type Mode int

const (
	// ModeReport allows the fetch and records that robots could not be read.
	// The default. See the package comment.
	ModeReport Mode = iota
	// ModeStrict refuses when robots.txt could not be read, which is the
	// crawler posture, for an operator who wants it.
	ModeStrict
	// ModeOff does not fetch robots.txt at all.
	ModeOff
)

// Result is what one lookup produced.
type Result struct {
	// Allowed is whether the path may be fetched.
	Allowed bool
	// Reason is the human sentence, and is empty when Allowed with no caveat.
	Reason string
	// Read is false when robots.txt could not be read at all. A caller must
	// not report a false here as "the site allows it": the site said nothing.
	Read bool
	// Rule is the matched Disallow line, for a refusal a reader can check.
	Rule string
}

// group is the rules for one user-agent, in the order they appeared.
type group struct {
	allow    []string
	disallow []string
}

// Cache holds one process's readings, per origin.
//
// Per origin rather than per host, because a robots.txt is served over a scheme
// and RFC 9309 treats http and https as different authorities. Collapsing them
// would apply one site's rules to another's document.
type Cache struct {
	mu   sync.Mutex
	seen map[string]entry

	Mode Mode
	TTL  time.Duration
	HTTP *http.Client
}

type entry struct {
	g    group
	read bool
	at   time.Time
}

// DefaultTTL is how long a reading is reused.
//
// Short on purpose. A crawler caches for a day because it returns constantly; a
// governed fetch happens when somebody asks, and an hour-old reading of a rule
// somebody changed to stop us is a rule we ignored for an hour.
const DefaultTTL = 15 * time.Minute

// New builds a cache. A nil client gets one with a bounded timeout, because a
// robots.txt that never answers must not hold a fetch open.
func New(mode Mode, ttl time.Duration, hc *http.Client) *Cache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if hc == nil {
		hc = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// A robots.txt that redirects off its own origin is not that
				// origin's robots.txt. RFC 9309 allows following within reason
				// and this plane does not follow at all, because a redirect
				// here is a request to a destination nobody decided.
				return http.ErrUseLastResponse
			},
		}
	}
	return &Cache{seen: map[string]entry{}, Mode: mode, TTL: ttl, HTTP: hc}
}

// Check reports whether rawURL may be fetched.
//
// It never returns an error. Every failure to read becomes a Result with
// Read false, handled per Mode, for the same reason the policy client never
// returns one: an error return invites a caller to log it and carry on.
func (c *Cache) Check(ctx context.Context, scheme, host, path string) Result {
	if c == nil || c.Mode == ModeOff {
		return Result{Allowed: true, Read: false, Reason: "robots.txt is not consulted by this deployment"}
	}
	if path == "" {
		path = "/"
	}

	g, read := c.groupFor(ctx, scheme, host)
	if !read {
		if c.Mode == ModeStrict {
			return Result{
				Allowed: false,
				Read:    false,
				Reason: "robots.txt for " + scheme + "://" + host + " could not be read, and this " +
					"deployment is configured to refuse rather than assume permission",
			}
		}
		return Result{
			Allowed: true,
			Read:    false,
			Reason: "robots.txt for " + scheme + "://" + host + " could not be read, so no rule was " +
				"applied. This is not a statement that the site allows it.",
		}
	}

	if rule, ok := g.blocks(path); ok {
		return Result{
			Allowed: false,
			Read:    true,
			Rule:    rule,
			Reason:  scheme + "://" + host + "/robots.txt disallows this path for " + UserAgent + ": " + rule,
		}
	}
	return Result{Allowed: true, Read: true}
}

func (c *Cache) groupFor(ctx context.Context, scheme, host string) (group, bool) {
	key := scheme + "://" + host
	c.mu.Lock()
	if e, ok := c.seen[key]; ok && time.Since(e.at) < c.TTL {
		c.mu.Unlock()
		return e.g, e.read
	}
	c.mu.Unlock()

	g, read := c.fetch(ctx, key)

	c.mu.Lock()
	c.seen[key] = entry{g: g, read: read, at: time.Now()}
	c.mu.Unlock()
	return g, read
}

func (c *Cache) fetch(ctx context.Context, origin string) (group, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/robots.txt", nil)
	if err != nil {
		return group{}, false
	}
	req.Header.Set("User-Agent", UserAgent+"/1 (+https://github.com/TAIPANBOX/scopyx)")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return group{}, false
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		// 512 KiB is well past any real robots.txt and stops a hostile one
		// being a memory exhaustion against the thing doing the governing.
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
		if err != nil {
			return group{}, false
		}
		return parse(string(body)), true
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// RFC 9309 section 2.3.1.3: unavailable means no rules, and 404 is by
		// far the common case. This IS a reading: the site was asked and said
		// it has nothing to say.
		return group{}, true
	default:
		return group{}, false
	}
}

// parse reads the groups and keeps the one that applies to us.
//
// The rule that matters and is easy to get wrong: a robots.txt has GROUPS, each
// introduced by one or more `User-agent` lines, and a `User-agent` line after a
// rule line starts a NEW group. Treating the file as a flat list of rules
// applies another crawler's restrictions to us, which is the wrong direction of
// wrong: it would make this plane refuse fetches nobody asked it to refuse.
func parse(body string) group {
	var (
		ours, star     group
		haveOurs       bool
		inOurs, inStar bool
		lastWasAgent   bool
	)
	for _, raw := range strings.Split(body, "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		field = strings.ToLower(strings.TrimSpace(field))
		value = strings.TrimSpace(value)

		switch field {
		case "user-agent":
			if !lastWasAgent {
				// A new group begins.
				inOurs, inStar = false, false
			}
			lastWasAgent = true
			switch {
			case strings.EqualFold(value, UserAgent):
				inOurs, haveOurs = true, true
			case value == "*":
				inStar = true
			}
		case "allow", "disallow":
			lastWasAgent = false
			target := (*group)(nil)
			if inOurs {
				target = &ours
			} else if inStar {
				target = &star
			}
			if target == nil {
				continue
			}
			if field == "allow" {
				target.allow = append(target.allow, value)
			} else {
				target.disallow = append(target.disallow, value)
			}
		default:
			lastWasAgent = false
		}
	}
	// A group naming us wins outright, even when it is empty: a site that
	// wrote `User-agent: scopyx` with no rules has said we may fetch
	// everything, and falling back to `*` would ignore what it said.
	if haveOurs {
		return ours
	}
	return star
}

// blocks reports whether path is disallowed, and by which rule.
//
// RFC 9309 section 2.2.2: the most specific match wins, measured by the length
// of the matched pattern, and Allow beats Disallow at equal length. Without the
// length rule a single `Disallow: /` would beat every `Allow:` under it, which
// is the shape most real robots.txt files use.
func (g group) blocks(path string) (string, bool) {
	best, bestLen, allowed := "", -1, false
	for _, p := range g.disallow {
		if p == "" {
			// An empty Disallow means "nothing is disallowed" and is not a
			// match on everything. This is the line most hand-rolled parsers
			// get backwards.
			continue
		}
		if n := matchLen(p, path); n > bestLen {
			best, bestLen, allowed = p, n, false
		}
	}
	for _, p := range g.allow {
		if p == "" {
			continue
		}
		if n := matchLen(p, path); n >= bestLen && n >= 0 {
			best, bestLen, allowed = p, n, true
		}
	}
	if bestLen < 0 || allowed {
		return "", false
	}
	return "Disallow: " + best, true
}

// matchLen returns the length of pattern if it matches path, or -1.
//
// Supports the two wildcards RFC 9309 defines, `*` for any run and `$` for
// end-of-path, and nothing else.
func matchLen(pattern, path string) int {
	if !strings.ContainsAny(pattern, "*$") {
		if strings.HasPrefix(path, pattern) {
			return len(pattern)
		}
		return -1
	}
	anchored := strings.HasSuffix(pattern, "$")
	p := strings.TrimSuffix(pattern, "$")
	parts := strings.Split(p, "*")

	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 {
			if !strings.HasPrefix(path[pos:], part) {
				return -1
			}
			pos += len(part)
			continue
		}
		j := strings.Index(path[pos:], part)
		if j < 0 {
			return -1
		}
		pos += j + len(part)
	}
	if anchored && pos != len(path) {
		return -1
	}
	return len(pattern)
}
