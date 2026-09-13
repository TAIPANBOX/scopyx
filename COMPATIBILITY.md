# Compatibility

`TAIPANBOX/scopyx` promises the surface below from its 1.0 (`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). A frozen name is not removed or renamed within a major; an additive thing may appear as a minor; an experimental thing may change in any release.

Status: proposed: this repository is at 0.x (v0.1.2), and the surface named here is what its 1.0 freezes; the gate holds it from today so that 1.0 is a tag and not a rewrite

## Frozen

### agentevent.emitted (2)

- `web_fetch`
- `web_blocked`
- held in: `internal/record/record.go`

### env (17)

- `SCOPYX_ADDR`
- `SCOPYX_KEYS`
- `SCOPYX_ALLOW_OPEN_BIND`
- `SCOPYX_WARDRYX`
- `SCOPYX_WARDRYX_KEY`
- `SCOPYX_BACKEND`
- `SCOPYX_EXTERNAL_ENDPOINT`
- `SCOPYX_EXTERNAL_KEY`
- `SCOPYX_EXTERNAL_LABEL`
- `SCOPYX_CHROMIUM`
- `SCOPYX_CHROMIUM_NO_SANDBOX`
- `SCOPYX_EVENTS`
- `SCOPYX_RETAIN`
- `SCOPYX_MAX_BYTES`
- `SCOPYX_MAX_REDIRECTS`
- `SCOPYX_MAX_FETCHES_PER_HOUR`
- `SCOPYX_ROBOTS`
- held in: `cmd/scopyx/main.go`

### env.backend_values (3)

- `passthrough`
- `external`
- `chromium`
- held in: `cmd/scopyx/main.go`

### env.robots_values (3)

- `report`
- `strict`
- `off`
- held in: `cmd/scopyx/main.go`

### http.auth_header (1)

- `X-Scopyx-Key`
- held in: `internal/mcp/door.go`

### mcp.extract_values (3)

- `text`
- `html`
- `screenshot`
- held in: `internal/mcp/tools.go`

### mcp.methods (3)

- `initialize`
- `tools/list`
- `tools/call`
- held in: `internal/mcp/server.go`

### mcp.tool_arguments (3)

- `url`
- `extract`
- `wait_for`
- held in: `internal/mcp/tools.go`

### mcp.tools (1)

- `browse`
- held in: `internal/mcp/tools.go`

## Additive within a major

- new tools under tools/list, and new optional arguments on browse
- new event types under source scopyx (agent-passport SPEC 6.2 allows them within a source)
- new SCOPYX_* names with a default that keeps today's behaviour
- the two image variants (scopyx:<tag> and scopyx:<tag>-chromium) stay; a third may appear

## Experimental

- the chromium backend's CDP details (SCOPYX_CHROMIUM, SCOPYX_CHROMIUM_NO_SANDBOX): the browser it drives and how it finds it
- the external backend's request shape (SCOPYX_EXTERNAL_*)

## Support

The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.
