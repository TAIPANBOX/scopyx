# scopyx

**A policy enforcement point for agent web egress.** It is not a browser.

Your agents already browse. Through Firecrawl, through Browserbase, through a
local Playwright, through the model provider's own search. Whatever governance
you have does not see any of it: no decision before the request, no bound on
what comes back, no record that it happened.

scopyx does not give you a better fetcher. It sits between an agent and the
fetcher you already use, and adds the four things that were missing.

| | what it does |
|---|---|
| **decides** | every destination against your policy plane, before anything leaves |
| **re-decides** | every redirect hop, because an allowed host answering 302 to a denied one is the oldest allowlist bypass there is |
| **bounds** | bytes, redirect depth, and fetches per hour, all finite by default |
| **records** | one tamper-evident line per fetch and per refusal, in the shared agent-event envelope |

If a change would make the fetch better rather than the fetch more *governed*,
it belongs in a backend somebody else maintains.

## Run it

```bash
docker run --rm \
  -e SCOPYX_ADDR=0.0.0.0:4300 \
  -e SCOPYX_KEYS='a-secret=agent://acme.example/support-bot' \
  -e SCOPYX_WARDRYX=http://wardryx:8080 \
  -e SCOPYX_EVENTS=/var/lib/scopyx/events.ndjson \
  -v scopyx-events:/var/lib/scopyx \
  -p 4300:4300 \
  ghcr.io/taipanbox/scopyx:v0.1.0
```

Then point an MCP client at `http://localhost:4300` with the header
`X-Scopyx-Key: a-secret`. Two tools appear: `browse` and `fetch_url`.

From source, if you would rather:

```bash
go build ./cmd/scopyx && SCOPYX_WARDRYX=http://localhost:8080 ./scopyx
```

## The identity comes from the credential

`SCOPYX_KEYS` maps a credential to the agent it belongs to:

```
SCOPYX_KEYS='k1=agent://acme.example/support-bot,k2=agent://acme.example/researcher'
```

That mapping is not decoration. The only authenticated fact this service has is
which credential was presented, so that is the only thing an identity may be
derived from. A header naming the agent would be the caller telling us who it
is, and a policy carrying `deny_if_unattested` would then be satisfied by a
string the caller wrote for itself.

A credential given with no identity (`SCOPYX_KEYS='k1'`) still authenticates. It
simply cannot be spoken for: every fetch through it reaches the policy plane
with no subject, and is refused with a reason saying exactly that.

## Configuration

| variable | default | what it is |
|---|---|---|
| `SCOPYX_ADDR` | `127.0.0.1:4300` | bind address |
| `SCOPYX_KEYS` | none | `key=agent://domain/name`, comma separated |
| `SCOPYX_WARDRYX` | **required** | the policy plane's base URL |
| `SCOPYX_WARDRYX_KEY` | none | this service's credential for the policy plane |
| `SCOPYX_BACKEND` | `passthrough` | `passthrough`, `external` or `chromium` |
| `SCOPYX_EXTERNAL_ENDPOINT` | none | your own fetching service, for `external` |
| `SCOPYX_EXTERNAL_KEY` | none | your credential for your own service |
| `SCOPYX_CHROMIUM` | found on PATH | path to the browser, for `chromium` |
| `SCOPYX_EVENTS` | none (no record) | path to this plane's own journal |
| `SCOPYX_RETAIN` | none | `payload` to keep full URLs, see below |
| `SCOPYX_MAX_BYTES` | 32 MiB | body cap |
| `SCOPYX_MAX_REDIRECTS` | 10 | redirect depth |
| `SCOPYX_MAX_FETCHES_PER_HOUR` | 500 | `0` disables the cap, and startup says so |
| `SCOPYX_ALLOW_OPEN_BIND` | unset | see below |

### It refuses to start bound wide with no credentials

A non-loopback bind with no credential configured is an unauthenticated fetch
proxy on your network: anything that reaches the port can make this plane fetch
on its behalf, under your egress allowance and with your name on the record.
That is a different failure from a leaked credential, because there is nothing
to leak, and it is silent, because it works perfectly for whoever finds it.

Set `SCOPYX_KEYS`, or bind to loopback, or, if you have deliberately decided to
run it open, set `SCOPYX_ALLOW_OPEN_BIND=1`.

### The per-hour cap is finite on purpose

The `passthrough` backend is free. Every other backend is metered, and a backend
that is free today can be priced tomorrow. An uncapped deployment would then
start spending without anybody deciding to, so there is no unlimited mode
without setting `SCOPYX_MAX_FETCHES_PER_HOUR=0` deliberately, and a process
started that way warns about it at every boot.

## Backends

**`passthrough`** (default) fetches over HTTP and renders nothing. No account,
no API token, no browser on the host, so a deployment is governed on the day it
is installed. It runs no JavaScript, so a page assembled in the browser arrives
as the shell that assembles it.

**`external`** wraps a fetching service you already run and already pay for.
This is the point of the design: you do not swap your tooling, you gain a
decision, a bound and a record over the tool you already own. The navigation is
enforced, so a destination your policy refuses never reaches that service and
never appears in your bill for it either.

**What `external` honestly cannot do** is enforce per subresource. The remote
service fetches the page and hands back what it got, so there is no moment at
which this plane could refuse an image on a forbidden host. Every result says
which of the two guarantees was in force, and never claims the stronger one.

**`chromium`** drives a browser you installed. It runs the page's JavaScript,
so a document assembled in the browser arrives assembled, and it is the only
backend for which `per_request` is a measurement rather than a definition:
`passthrough` is per-request because it makes exactly one request, and a page
is a document plus forty others.

Nothing is bundled and nothing is downloaded. The image stays distroless and
small, and a missing browser is refused at startup with a message about the
browser rather than at the first fetch with a message about the network.

### How the browser is boxed in

The browser is launched with `--proxy-server` pointing at a proxy this process
owns, and `--proxy-bypass-list=<-loopback>`, which removes even Chrome's own
bypass for localhost. That proxy refuses any destination the plane did not
decide. It is the floor, and it holds because it is a socket that is not
opened.

CDP request interception runs on top of it and is not the enforcement. It sees
the full URL of every request including inside TLS, which the proxy cannot, so
it produces the counts and the per-URL decisions. But it is the browser's
cooperation, and cooperation is a thing a bug, a flag or a version can
withdraw.

The two were measured separately: with interception removed the refused
subresource's server is still never reached, with the proxy decision removed it
is still never reached, and with both removed it is reached once and the test
goes red.

Three things it does not do. **No TLS interception**, ever: minting
certificates for other people's sites would put a private CA on your box and
build the capability this plane exists to bound. **No debugging port**: the
protocol runs over an inherited pipe, because a debugging port is an
unauthenticated remote-control channel for the browser fetching on your behalf.
**No warm browser**: a fresh profile directory per fetch, removed after, so no
cookie jar, cache or storage partition is shared between two fetches.

## Every answer says what actually happened

```json
{
  "backend": "passthrough-http",
  "enforcement": "per_request",
  "http_status": 200,
  "content_bytes": 18422,
  "subresources_requested": 0,
  "subresources_blocked_by_policy": 0,
  "redirect_hops": 2,
  "truncated_by": null
}
```

A count a backend cannot supply is `null`, never `0`. The distinction is the
whole reason those fields are nullable: `0` says the page asked for nothing,
`null` says nobody knows, and reporting the second as the first claims perfect
fidelity for exactly the backend that can see the least.

Zero bytes with any failed subresource is an **error**, not an empty page. For a
human, degrading to a blank frame is right. For an agent it is the worst
available failure, because the model does not know it read half a page and will
report confidently on the half it got.

## A URL is personal data

`https://crm.example/customers/12345?email=jane@example.com` is an address and
also a name, an identifier and a contact detail.

The event carries the **origin** and a SHA-384 of the URL. The path and the
query string, which is exactly where an identifier or a session token lives, are
never assembled into the event at all. `SCOPYX_RETAIN=payload` keeps the full
URL, and names the field `url_unprotected` when it does, because this service
has no subject-keyed payload plane yet and a field called `url` would imply one.

Nothing above debug ever logs a full URL. Nothing writes a page body, ever.

## The tool takes a URL and never a header

`browse` and `fetch_url` accept a URL and two behaviour knobs. There is no
header, cookie, credential or proxy parameter, and there never will be.

A free-form header parameter is a credential-laundering channel straight past
your broker's DLP, which scans the arguments it understands and cannot read an
opaque map of strings. It is also how a plane that refuses authenticated
sessions acquires them one header at a time. Authenticated fetching, where it is
genuinely needed, belongs to the backend and its own credential store.

Unknown arguments are **refused**, not ignored. Ignoring is worse: the caller
believes their header was sent.

## What it will not do

No stealth, no CAPTCHA solving, no TLS-fingerprint matching, no bulk crawl, no
image harvesting. It identifies itself as
`scopyx/1` and never as a browser, and it honours `robots.txt`.

**An unreadable `robots.txt` allows, and the result says it could not be read.**
That is not the crawler posture and it is deliberate: crawler guidance treats a
5xx as a complete disallow, which is right when you are about to make ten
thousand requests and wrong for one agent reading one page, because it hands any
origin a way to deny service to the agents fetching it. Set
`SCOPYX_ROBOTS=strict` for the crawler behaviour, or `off` to not ask.

Two of those are positioning and two are law-shaped. This is defensive tooling
for an operator governing their own agents, and a component that defeated a
third party's controls would be the first thing here useful to somebody
attacking a stranger. Separately, EU AI Act Article 5(1)(e) prohibits untargeted
scraping of facial images to build recognition databases, and a bulk-crawl mode
is the feature that turns a governance tool into that.

## Where it sits

scopyx is one plane in the TAIPANBOX agent stack. It asks
[wardryx](https://github.com/TAIPANBOX/wardryx) for decisions, writes events in
the envelope [agent-passport](https://github.com/TAIPANBOX/agent-passport)
defines, and is shaped after
[heraldyx](https://github.com/TAIPANBOX/heraldyx): a small process that owns a
single privilege and is separate *because* of it.

It runs standalone. The TokenFuse MCP broker in front of it adds things when
present and is not a precondition, and that standalone path is covered by tests
rather than by this sentence.

## Regulatory position

This service is not an AI system under EU AI Act Article 3(1): it applies rules
an operator wrote and infers nothing. Used beside an AI system, it supplies
evidence for Article 12 record-keeping and Article 14 human oversight.

The wording throughout is "covers the requirements of Article 12", never "AI Act
compliant" or "GDPR compliant". There is no certification and no auditor behind
those words, and a claim nobody can hold is worse than no claim, because a
reader trusts the whole document on the strength of it.

## Licence

Apache-2.0.
