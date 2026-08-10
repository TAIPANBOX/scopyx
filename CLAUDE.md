# CLAUDE.md, working instructions for scopyx

These instructions apply to any model working in this repo. Read this file
before writing code. It holds process and invariants only: **no status.**
Status goes stale, and a stale instruction file is worse than none. For where
the code actually is, read `VALIDATION.md` and the README.

## Read before you change anything

1. `~/Development/browse-plane-plan.md`, the approved design, in full. It is
   the reasoning behind every invariant below, and where the two disagree it
   wins until somebody updates both.
2. `SPEC.md` in the sibling repo `TAIPANBOX/agent-passport`, section 6 for the
   event envelope this service emits and section 3.1 for the identifier.
3. `heraldyx`, the repository this one is shaped after. Same argument, one
   plane over: a small process that owns a single privilege and is separate
   *because* of it.

## What this service is

**A policy enforcement point for agent web egress.** It is not a browser.

The distinction is the whole design and it is easy to lose. Agents already
browse, through Firecrawl, Browserbase, a local Playwright or the model
provider's own search, and the stack sees none of it. This service supplies no
capability the operator does not already have: it sits between an agent and
whatever fetching backend it already uses, decides each destination against
policy, enforces that decision against **every subresource**, counts what
actually happened, and writes one tamper-evident record.

Anyone proposing a feature should ask whether it makes the fetch better or the
fetch more *governed*. The first belongs in a backend somebody else maintains.

This service is defensive: it exists so an organization can govern its own
agents. Never describe it, in code, docs or commit messages, as tooling for
acting against anyone else, and never build anything that defeats a third
party's controls.

## The working loop

1. Branch off `main`, one logical increment per branch.
2. Run every gate below. All must pass locally before the push.
3. Commit with Conventional Commits. End the message with the standard
   co-author trailer naming the model that actually did the work.
4. Push the branch, open a PR with `gh`.
5. Wait for all CI checks to go green. Fix forward, do not force-push over red.
6. **Ask the user before merging.** Do not self-merge.

Use `git worktree add` when working in parallel with another session.

## Gates

```sh
test -z "$(gofmt -l .)"
go vet ./...
staticcheck ./...
go test -race ./...
go build ./...
./scripts/no-caller-headers.sh
./scripts/one-way-out.sh
./scripts/readme-numbers.sh
./scripts/no-delegated-decisions.sh
./scripts/no-warm-context.sh
./scripts/no-compliance-claims.sh
./scripts/gates-have-teeth.sh   # needs a clean tree, run it after committing
```

**This list was wrong from the day it was written until 2026-08-10, and the
correction is worth more than the list.** It named these four from the first
commit and `scripts/` held one file: the other three were copied from the
sibling repositories that have them, and nothing here could run them. A model
following this file got "no such file or directory" three times.

They exist now, and each one caught something while being written, which is
the argument for writing them rather than describing them:

- `one-way-out.sh` flagged a COMMENT that named `http.Transport{` while
  explaining why only `internal/pin` may build one. A gate that fails on its
  own documentation is switched off inside a week. It strips comments now.
- `one-way-out.sh` also reported a build problem when its whole subject was
  gone, because the pure-layer check ran before the check that any Go files
  exist. The subject is established first now.
- `readme-numbers.sh` read `%20` out of the badge URL and reported twenty
  direct dependencies. Found on its first run, against itself.

All three were found by `gates-have-teeth.sh`, which is what it is for.

## Hard invariants

Each one carries how it is held today. Use `(gate: ...)`, `(test: ...)`,
`(partly gated: ...)` or `(not enforced)`, and use the weakest one that is
true. An invariant with no check, written as though it had one, is worse than
an absent invariant.

1. **Every control enforces at this layer and none is delegated to a backend.**
   The destination decision, the subresource allow-set, the address-range
   refusals, the redirect re-evaluation, the caps and the record are made
   before and around the backend call, never inside it. A backend may be
   Kitesurf, the operator's own Playwright, or their existing Firecrawl
   account: none of them is ours, and one that happens to enforce something
   today can change under us without saying so.

   This is the same reason tokenfuse checks a budget before calling a provider
   rather than reading the provider's own limits.
   *(gate: `scripts/no-delegated-decisions.sh`, which refuses a
   `decide.Decision` constructed anywhere in `internal/backend`, and refuses
   that package importing `internal/policy` or `internal/robots`. Writing it
   changed the code: the chromium backend held one verdict of its own, for the
   honest reason that it joined a resolver to a decider and had to handle
   resolution failing. It now takes ONE function that does both, supplied from
   above, and constructs nothing. What the gate cannot see is a backend that
   read a vendor's header and quietly returned fewer subresources; what catches
   that is the fidelity block being nil rather than zero, and a reader.)*

2. **The backend is an adapter and the adapter is the product.** A backend that
   cannot be swapped makes this a browser with extra steps, and ties the whole
   plane to one vendor's beta. Everything except the fetch itself is
   backend-independent. *(not enforced)*

3. **The tool takes a URL and never caller-supplied headers, cookies or
   credentials.** A free-form header parameter is a credential-laundering
   channel straight past the broker's DLP, which scans the arguments it
   understands and cannot read an opaque string map. It is also how a plane
   that refuses authenticated sessions acquires them one header at a time.
   Authenticated fetching, where it is genuinely needed, belongs to the
   backend and its own credential store.
   *(gate: `scripts/no-caller-headers.sh`, verified by planting a struct with
   a `json:"headers"` map, which it names and refuses; plus
   `TestNoToolAcceptsAHeaderCookieOrCredential` and
   `TestEveryToolRefusesUnknownArgumentsRatherThanIgnoringThem` on the
   published schemas. The two cover different surfaces: the test reads what
   this package publishes, the script reads the whole tree, because a second
   surface is how the field comes back. The script is an anchor and not a
   compiler, and a field called `extra` holding a header map would pass it.)*

4. **No fetch context is reused across two fetches.** Never a rendering
   context, a cookie jar, a cache or a storage partition, even for the same
   agent.

   This needs a gate rather than a comment because the obvious future
   optimisation is a warm session, and it is attractive: the default backend is
   slower than Chromium in wall time. Somebody will propose it as a latency
   fix, it will pass every test, and it will silently destroy cross-page and
   cross-tenant isolation.
   *(gate: `scripts/no-warm-context.sh`, four structural checks: no cookie jar
   anywhere, the browser's profile directory created per fetch and removed
   rather than named as a constant, keep-alives off in `internal/pin`, and no
   `http.Client`, `http.Transport` or `cdp.Conn` held in package-level state.
   What it cannot see is a long-lived struct field carrying a client between
   two calls of Fetch: the interface makes that awkward rather than impossible,
   and this raises the cost of the mistake rather than removing it.)*

5. **A result carries what actually happened, and an empty answer is never
   returned as if it were complete.** Bytes extracted, subresources requested,
   ok, blocked and failed, redirect hops, and which bound truncated it if one
   did.

   The reason is the default backend's own stated safety rule: any failure
   degrades to a blank frame or a missing element, never a dead session. For a
   human that is right. For an agent it is the worst failure available, because
   the model does not know it read half a page and reports confidently on the
   half it got. Zero bytes with any failed subresource is an error, not an
   empty page, and a count a backend cannot supply is `null`, never `0`.
   *(test)*

6. **Identity comes from an authenticated caller and never from a claim.**
   `AGENT_PASSPORT_ID` may fill a log line, an event's `agent_id` or a display
   name. It may never be the identity presented to the policy plane for a
   decision: agent-passport SPEC 3.1 says plainly that it is a self-declaration
   and must not be read as attestation, and a policy carrying
   `deny_if_unattested` would otherwise be satisfied by a string the caller
   wrote for itself. Where no authenticated identity exists, the request is
   refused rather than decided on a claimed one. *(test)*

7. **This plane fails CLOSED when the policy plane cannot answer.**
   `@yurii 2026-08-09`, "fail-closed так".

   It is a deliberate divergence from the rest of the estate and the divergence
   is the point. TokenFuse's LLM path fails open and documents it honestly,
   which is right there: a money plane that refuses every call when its control
   plane blinks costs an operator their production traffic over a network
   partition. An egress enforcement point is the other case. One that fails
   open is an unrestricted fetch proxy wearing a governance label, which is
   precisely the thing this component exists not to be, and the failure is
   silent: every fetch succeeds, nothing is refused, and the operator's evidence
   says the plane was working.

   So an unreachable PDP refuses the fetch and says which of the two it was, a
   refusal by policy or a refusal because policy could not be asked. Those are
   different facts to whoever reads the trail, and collapsing them sends
   somebody to repair a machine that is fine. *(test)*

8. **Spend is capped by default.** The per-hour fetch cap has a finite default
   and there is no unlimited mode without an explicit opt-out variable. The
   default backend is free in beta and unpriced at GA, which means the day it
   is priced an uncapped deployment starts spending without anybody deciding
   to. *(test)*

9. **This plane governs evasion and never supplies it.** No stealth, no CAPTCHA
   solving, no TLS-fingerprint matching, no bulk crawl and no image harvesting.
   **`robots.txt` is honoured**, built 2026-08-10 after this line claimed it
   for a day and nothing read it. Every Disallow that applies to `scopyx` is
   obeyed, per RFC 9309, including group boundaries, longest-match precedence,
   Allow beating Disallow at equal length, and the two wildcards.

   **An unreadable robots.txt ALLOWS and says so, which is not the crawler
   posture and is deliberate.** Crawler guidance treats a 5xx as a complete
   disallow, which is right when you are about to make ten thousand requests
   and wrong here: it would let a site's transient error stop an operator's own
   governed work, and hand any origin a way to deny service to the agents
   fetching it. The result carries `Read: false` so nothing downstream can
   report it as permission. `SCOPYX_ROBOTS=strict` gets the crawler behaviour
   for an operator who wants it.

   The site's preference is asked AFTER the operator's policy, so a
   destination the policy refuses is never contacted at all, not even for its
   robots.txt.
   *(test: `internal/robots` and three end-to-end cases in
   `cmd/scopyx/main_test.go`, all verified by breaking the implementation: the
   group boundary removed, first-match instead of longest-match, an empty
   Disallow read as a match on everything, `$` not anchoring, a 5xx read as a
   reading, and the cache never expiring)*

   Two of those are positioning and two are law-shaped. The estate is defensive
   tooling for an operator governing their own agents, and a component that
   defeated third-party controls would be the first one here useful to somebody
   attacking a stranger. Separately, EU AI Act Article 5(1)(e) prohibits
   untargeted scraping of facial images to build recognition databases, and a
   bulk-crawl mode is the feature that turns a governance tool into that.
   *(not enforced: this is judgement about what gets built, and the README
   states it where a deployer meets it)*

10. **A URL is personal data.** `https://crm.example/customers/12345?email=...`
   is an address and also a name, an identifier and a contact detail. The
   metadata plane gets the origin and a hash; the full URL and any content go
   to the payload plane behind the subject key, or nowhere. Nothing above debug
   ever logs a full URL. *(test)*

11. **Nothing opens a socket to an address this plane did not check.**
    `internal/fetch` resolves a name and `decide` refuses on every address it
    answered with. Then the fetch used to resolve the name AGAIN, inside a
    dialer, with no memory of what was checked, and a hostile zone is free to
    answer differently in between. That is DNS rebinding, and the payoff is
    the whole plane: a name that passes as a public address and rebinds to
    169.254.169.254 reads the credentials of whatever this runs on.

    `internal/pin` puts the checked addresses in the context and gives the
    transport a dialer that uses them. It applies to the backend and to the
    robots.txt fetch, which is the same client, so the site's own preference is
    read over the route the decision was made on.

    **It fails closed, and that is the part worth keeping.** A dial to a host
    the context does not carry is REFUSED, with a typed error. The transport is
    therefore an enforcement floor under invariant 1 rather than a second copy
    of it: a code path that reached out without going through `internal/fetch`
    cannot open a socket, whatever it thinks it is doing.

    Keep-alives are off for the same reason and it looks like a performance
    setting. A pooled connection is keyed on scheme, host and port, exactly
    what a rebinding attack holds constant, so a reused socket would consult
    the pin once and bypass it forever after.

    Two things it does NOT cover, said plainly. The `external` backend calls a
    service at an address the operator chose and no fetch decision covers that
    host, so it is not pinned; what the vendor then reaches is outside this
    process, which is why it reports `navigation_only`. The policy client is
    not pinned either, because wardryx is an internal service and a pinned
    dialer would make this plane fail closed against its own control plane.
    *(gate: `scripts/one-way-out.sh`, which refuses any `http.Transport` outside
    `internal/pin` and any `net.Dialer` outside it and `internal/browserproxy`.
    That is the structural half: a second transport is a second dialer, and a
    dialer that resolves the name itself is this hole reopened. Plus `internal/pin`,
    ten cases, verified by replacing the dialer with one that resolves the name
    itself, which reddens the two that matter; and the end-to-end harness runs on
    the real pinned client, verified by giving robots its own unpinned one and
    watching `TestADisallowedPathIsRefusedAndTheTargetNeverSeesIt` fail)*

12. **A browser this plane drives has exactly one way out, and it is not the
    browser's word for it.** The `chromium` backend launches with
    `--proxy-server` pointing at a proxy this process owns and
    `--proxy-bypass-list=<-loopback>`, which removes even Chrome's own bypass
    for localhost. That proxy refuses any destination the plane did not decide.

    CDP `Fetch` interception runs on top of it and is NOT the enforcement. It
    sees the full URL of every request including inside TLS, which the proxy
    cannot, so it produces the counts and the per-URL decisions. But it is
    Chrome's cooperation, and cooperation is a thing a bug, a flag or a version
    can withdraw. The connection is the floor because it is what carries bytes.

    **The two were measured separately.** With CDP blocking removed the refused
    subresource's server is still never reached; with the proxy decision
    removed it is still never reached; with both removed it is reached once and
    the case goes red. That is what makes the redundancy a fact rather than a
    claim.

    No TLS interception, ever. Minting certificates for other people's sites
    would put a private CA on the operator's box and build the capability this
    plane exists to bound.

    A fresh `--user-data-dir` per fetch, removed after: invariant 4, where it is
    least theoretical. A warm browser is the obvious optimisation, it would pass
    every other test, and it would join two tenants' pages in one storage
    partition.

    **No debugging PORT.** `internal/cdp` speaks over `--remote-debugging-pipe`
    and refuses to launch with a port, because a debugging port is an
    unauthenticated remote-control channel for the browser this plane fetches
    with, on the operator's own box.

    **HOME must name a directory that exists and is writable**, and the image
    sets it to `/tmp`. `useradd -M` creates no home directory, and on a k3s pod
    on EC2 that killed the browser before it opened anything, with an error
    about a crash-handler database that named nothing about a home directory.
    v0.1.1 shipped that way and could not render on a real node. Measured
    2026-08-10 on the node; NOT reproduced under `docker run` locally in any
    shape tried, so the trigger is not isolated and the fix stands on its own.

    **Nothing is bundled into the default image.** The default is 3.5 MB to
    pull and 15.4 MB on disk; the browser variant is 267 MB to pull and 1.03 GB
    on disk, under its own `-chromium` tag. TWO numbers, always, because they
    answer different questions and this file said only the disk one for a day,
    beside a sentence about pulling. Seventy-six times the transfer is the
    argument for keeping them apart. A missing browser is refused at startup with a message
    about the browser rather than at the first fetch with a message about the
    network.

    **The Dockerfile's stage ORDER is load-bearing.** `docker build .` with no
    `--target` builds the last stage, so the distroless one sits at the bottom
    and the browser variant above it. Appended at the end, the variant quietly
    became what an unqualified build produced, which `docker image ls`
    reporting the same size for both is what gave away. CI builds both, so a
    reorder is noticed.

    **In a container the sandbox question is which one to keep, not whether.**
    Chromium will not start without the user namespaces its renderer sandbox
    needs. Relaxing the container's seccomp keeps Chrome's sandbox; setting
    `SCOPYX_CHROMIUM_NO_SANDBOX=1` keeps the container's filter. Both were
    measured rendering on 2026-08-10.

    On Kubernetes that choice may already be made for the operator: a namespace
    at PodSecurity `restricted` forbids `Unconfined` outright, and the pod is
    refused rather than warned. See stack-k8s GOTCHAS 84.

    For THIS component the first is the better trade where it is available, and
    the reason is the product's own subject: with Chrome's sandbox off, a renderer exploit runs
    as the container's user and can open sockets directly, which is egress that
    never passes the proxy and never appears in the record. The container's
    seccomp filter protects the host from the container; it does not protect
    the record from a compromised renderer. The image does not choose: it ships
    with the sandbox on.
    *(test: `internal/backend/chromium_test.go` against a real browser, and
    `internal/browserproxy` and `internal/cdp` without one. The browser cases
    SKIP where there is none, loudly, and `SCOPYX_REQUIRE_CHROMIUM` turns the
    skip into a failure so CI cannot quietly stop exercising them.)*

13. **Never claim compliance.** The wording is "covers the requirements of
    Article 12", never "GDPR compliant" or "AI Act compliant". This binds the
    README, the site, PR bodies and release notes equally. A claim nobody can
    hold is worse than no claim, because a reader trusts the whole document on
    the strength of it. *(gate: `scripts/no-compliance-claims.sh`, a grep over
    every tracked Markdown file with an allowlist for the honest negative
    forms. The allowlist is the design rather than the search: the word has to
    stay usable or the rule could not be written down, here or in the README,
    so a line carrying it passes only when it also carries an enumerated
    negation. A line that fails is not necessarily wrong, it is a sentence
    somebody has to look at, which is the most a grep can honestly do.)*

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.

**Nothing here is now a mechanically checkable invariant without a check.**
Invariants 1, 4 and 13 were the last three, each named with the shape it
needed, and each got it on 2026-08-10. Invariants 2 and 9 are judgement and
stay judgement: what a backend is FOR, and what gets built.

Two of the three changed something while being written, which is the argument
for writing a gate rather than describing one. Invariant 1's moved a verdict
out of the chromium backend. Invariant 13's needed its allowlist designed
before its search, because the word has to stay usable or the rule cannot be
stated.

Invariant 11 arrived with tests rather than prose, and it took invariant 9's
one piece of recorded debt with it. Worth noting how that debt behaved: it sat
for a day described exactly, in the file, with the reason it was not closed,
and closing it took an afternoon. A debt that names its own shape is cheap; the
expensive ones are the sentences that sound finished.

The rule this estate uses: an approved decision is not finished until it is a
numbered invariant here AND a gate in `scripts/` if it can be checked
structurally. Until then it is a document, and documents do not stop code.

## Escalate, do not push through

Stop and tell the user, then wait:

- Anything that would make this plane hold a customer credential, or reach a
  site as anything other than itself.
- Adding a backend that supplies stealth, CAPTCHA solving or fingerprint
  spoofing, as opposed to governing one the operator already has.
- Enabling anything metered. The default backend is free in beta behind
  per-account limits and unpriced at GA; every other backend is metered from
  day one.
- Cutting a tag, publishing an image, or any other outward-facing action.
- Any change to the agent-event envelope, which belongs to agent-passport and
  is an edit to nine repositories.

## Conventions

- **No long dashes** anywhere: not in code comments, docs, commit messages, or
  PR bodies. Use a comma, a colon, parentheses, or a short hyphen.
- Nothing paid or metered gets enabled without telling the user first and
  getting agreement.
- Do not delete or revoke keys, tokens, or certificates on your own initiative.
