#!/usr/bin/env bash
#
# Invariant 4: no fetch context is reused across two fetches.
#
# WHY THIS ONE NEEDS A GATE MORE THAN THE OTHERS
#
# It is the invariant somebody will break on purpose, believing they are
# improving things. The default backend is slower than a warm browser in wall
# time, a browser launch is the largest single cost in a rendering fetch, and
# "keep the browser between fetches" is the first optimisation anybody
# proposes. It would pass every functional test in this repository, because
# every one of them fetches once.
#
# What it would silently destroy is isolation between pages and between
# tenants: one cookie jar, one cache, one storage partition, and a site that
# set something during agent A's fetch reading it back during agent B's.
#
# WHAT IT CHECKS, all four of them structural
#
#   - No cookie jar anywhere. A `Jar` on a client is the shortest path to a
#     session that outlives a fetch.
#   - The browser's profile directory is created per fetch and removed, not
#     named as a constant. A fixed `--user-data-dir` is exactly the warm
#     browser, spelled as a path.
#   - Keep-alives stay off in `internal/pin`. This one reads as performance and
#     is not: a pooled connection is keyed on scheme, host and port, which is
#     what a rebinding attack holds constant, so a reused socket consults the
#     pin once and never again.
#   - Nothing holds an `http.Client` or a browser connection in package-level
#     state. A package variable is a fetch context with the widest possible
#     lifetime.
#
# WHAT IT CANNOT CHECK. A long-lived struct field holding a client, passed
# between two calls of Fetch, would pass this. The interface makes that awkward
# rather than impossible, and the honest position is that this gate raises the
# cost of the mistake rather than removing it.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

fail=0
note() {
	printf 'FAIL %s\n' "$1"
	fail=1
}

files=$(git ls-files '*.go' | grep -v '_test\.go$' || true)
if [ -z "$files" ]; then
	printf 'FAIL: no non-test Go files found, so this check measured nothing.\n'
	exit 1
fi

code_of() {
	perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' "$1"
}

# 1. no cookie jar
while IFS= read -r f; do
	if code_of "$f" | grep -qE 'cookiejar|Jar:[[:space:]]'; then
		note "$f gives a client a cookie jar; a session that outlives a fetch is invariant 4"
	fi
done <<<"$files"

# 2. the browser profile is per fetch
if git ls-files 'internal/backend/chromium.go' | grep -q .; then
	chromium=$(code_of internal/backend/chromium.go)
	printf '%s' "$chromium" | grep -q 'os.MkdirTemp' ||
		note "internal/backend/chromium.go does not create a temporary profile directory; a fixed --user-data-dir is a warm browser spelled as a path"
	printf '%s' "$chromium" | grep -q 'os.RemoveAll' ||
		note "internal/backend/chromium.go does not remove its profile directory; one that outlives the fetch is invariant 4 broken by storage"
	if printf '%s' "$chromium" | grep -qE '"--user-data-dir=/'; then
		note "internal/backend/chromium.go names a constant --user-data-dir; it must be created per fetch"
	fi
else
	note "internal/backend/chromium.go is gone, so the browser half of this check measured nothing"
fi

# 3. keep-alives stay off where the pin lives
if git ls-files 'internal/pin/pin.go' | grep -q .; then
	code_of internal/pin/pin.go | grep -q 'DisableKeepAlives:[[:space:]]*true' ||
		note "internal/pin no longer disables keep-alives; a pooled connection outlives the check that opened it"
else
	note "internal/pin/pin.go is gone, so the transport half of this check measured nothing"
fi

# 4. no client or browser connection in package-level state
#
# `var` or a var block at column zero, holding one of the types that carries a
# fetch context. Deliberately narrow: this looks for the shapes that ARE a
# fetch context, not for globals in general, because a global counter is not
# this invariant's business.
while IFS= read -r f; do
	if code_of "$f" | grep -qE '^var[[:space:]]+[A-Za-z_]+[[:space:]]*=?[[:space:]]*&?(http\.Client|http\.Transport|cdp\.Conn)'; then
		note "$f holds an http client or a browser connection in package-level state, which is a fetch context with the widest possible lifetime"
	fi
done <<<"$files"

if [ "$fail" -ne 0 ]; then
	printf '\nSomething can now outlive a fetch, which is invariant 4.\n'
	printf 'The warm version of this plane passes every functional test in the repository,\n'
	printf 'because every one of them fetches once, and it joins two tenants pages in one\n'
	printf 'storage partition.\n'
	exit 1
fi

n=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
printf 'OK: %s non-test Go file(s). No cookie jar, a profile directory per fetch,\n' "$n"
printf '    keep-alives off, and no client held in package-level state.\n'
