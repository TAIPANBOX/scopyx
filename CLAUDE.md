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
./scripts/one-way-out.sh
./scripts/no-caller-headers.sh
./scripts/readme-numbers.sh
./scripts/gates-have-teeth.sh   # needs a clean tree, run it after committing
```

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
   *(not enforced yet: the gate to write is one that refuses a policy decision
   derived from a backend response field)*

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
   *(not enforced yet: the gate to write asserts no code path holds a fetch
   context across two fetches)*

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
   **`robots.txt` is NOT honoured yet**, and this line said it was until
   2026-08-10. Nothing in the Go tree reads it, and the claim reached the
   README and the public site before anybody grepped for it. It is worth
   having and it is not built: the honest state is that this plane refuses the
   things above by construction and asks a site's preference not at all.
   *(not enforced, and the gate to write is a grep for the claim beside a grep
   for an implementation, which is the shape that would have caught it)*

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

11. **Never claim compliance.** The wording is "covers the requirements of
    Article 12", never "GDPR compliant" or "AI Act compliant". This binds the
    README, the site, PR bodies and release notes equally. A claim nobody can
    hold is worse than no claim, because a reader trusts the whole document on
    the strength of it. *(not enforced yet: a grep for `compliant` with an
    allowlist for the honest negative forms is the gate to write)*

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.

**Every invariant above is prose today**, because this repository is new. That
is the honest state and it is also the first work: invariants 1, 4 and 11 are
mechanically checkable and each is named above with the shape of the check it
needs. Invariants 2 and 9 are judgement and probably stay judgement.

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
