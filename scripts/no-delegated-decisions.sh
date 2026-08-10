#!/usr/bin/env bash
#
# Invariant 1: every control enforces at this layer, and none is delegated to a
# backend.
#
# WHAT THE FAILURE LOOKS LIKE, because it is not a crash
#
# A backend is somebody else's software, or a wrapper around it. Some of them
# enforce something today: a vendor refuses private addresses, a browser has its
# own blocklist. The tempting move is to lean on that, and it costs nothing
# until the vendor changes it in a release note nobody read, at which point this
# plane is still reporting that every destination was decided.
#
# So the rule is not "backends must be trustworthy". It is that no decision is
# taken there at all, and this gate holds the structural half of it.
#
# WHAT IT CHECKS
#
#   - `internal/backend` never constructs a `decide.Decision`. A backend that
#     can build a verdict can build a different one from the plane above it,
#     and no comment prevents that. The chromium backend held one of these
#     until 2026-08-10, for the honest reason that it joined a resolver to a
#     decider and had to handle resolution failing; it now takes ONE function
#     that does both, supplied from above, and constructs nothing.
#   - `internal/backend` never imports `internal/policy`. A backend that could
#     ask the policy plane itself would be a second decision point with its own
#     idea of the answer.
#   - `internal/backend` never imports `internal/robots`. The site's own
#     preference is asked by `internal/fetch`, AFTER the operator's policy, and
#     that ordering is the reason a refused destination is never contacted at
#     all. A backend asking it would ask at the wrong moment.
#   - `internal/decide` never imports a backend. The pure layer cannot depend on
#     the thing it decides about.
#
# WHAT IT CANNOT CHECK, said rather than implied. A backend that read a vendor's
# response header and quietly returned fewer subresources would pass this and
# would be invariant 1 broken. What catches that is the fidelity block being
# nil rather than zero, and a reader.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

fail=0
note() {
	printf 'FAIL %s\n' "$1"
	fail=1
}

files=$(git ls-files 'internal/backend/*.go' | grep -v '_test\.go$' || true)
if [ -z "$files" ]; then
	printf 'FAIL: no non-test files under internal/backend, so this check measured nothing.\n'
	printf '      A gate whose subject is gone says so rather than reporting OK.\n'
	exit 1
fi

# Comments discuss `decide.Decision` at length on purpose, so they are stripped
# first. Same helper and same caveat as one-way-out.sh: a `//` inside a string
# ends the line for this filter too.
code_of() {
	perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' "$1"
}

while IFS= read -r f; do
	code=$(code_of "$f")

	if printf '%s' "$code" | grep -q 'decide\.Decision{'; then
		note "$f constructs a decide.Decision; a backend that can build a verdict can build a different one from the plane above it"
	fi
	if printf '%s' "$code" | grep -q 'scopyx/internal/policy"'; then
		note "$f imports internal/policy; a backend that can ask the policy plane is a second decision point"
	fi
	if printf '%s' "$code" | grep -q 'scopyx/internal/robots"'; then
		note "$f imports internal/robots; the site's preference is asked by internal/fetch, after the operator's policy, and that ordering is the point"
	fi
done <<<"$files"

# And the other direction: the pure layer cannot depend on what it decides about.
if go list -f '{{join .Imports "\n"}}' ./internal/decide/ 2>/dev/null | grep -q 'scopyx/internal/backend'; then
	note "internal/decide imports internal/backend; the pure layer cannot depend on the thing it decides about"
fi

if [ "$fail" -ne 0 ]; then
	printf '\nA decision moved into a backend, which is invariant 1.\n'
	printf 'Backends fetch and report. Every refusal happens in internal/decide, before\n'
	printf 'Fetch is called, and internal/fetch is what holds that ordering.\n'
	exit 1
fi

n=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
printf 'OK: %s backend file(s), none of which decides anything.\n' "$n"
