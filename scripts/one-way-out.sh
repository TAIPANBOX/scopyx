#!/usr/bin/env bash
#
# One way out.
#
# This component exists to be the single place an agent's traffic leaves
# through. That claim is only worth something while there is ONE thing that
# opens sockets, and the estate's own experience says a second one arrives by
# accident rather than by decision: somebody needs a client for a small job,
# builds a transport beside the code that needs it, and the new transport
# resolves names for itself.
#
# WHY A SECOND TRANSPORT IS NOT A STYLE PROBLEM
#
# `internal/pin` puts the addresses a decision was made about into the context
# and dials THOSE. Any other `http.Transport` has an ordinary dialer, which
# looks the name up again, in the moment, with no memory of what was checked.
# Between the two lookups a hostile zone answers differently for nothing, and
# the address rules that refuse RFC1918, loopback and 169.254.169.254 are
# bypassed by a name that passed as a public address a microsecond earlier.
#
# So this gate fails when:
#
#   - anything outside `internal/pin` constructs an `http.Transport`;
#   - anything outside `internal/pin` or `internal/browserproxy` constructs a
#     `net.Dialer` (the proxy dials on the browser's behalf, at an address the
#     decider already checked and returned, which is the same rule one layer
#     over);
#   - anything outside `internal/cdp` imports `os/exec` (this process starts
#     exactly one kind of subprocess, a browser, and that privilege lives in
#     one package for the same reason SMTP does in heraldyx);
#   - `internal/decide` imports anything that performs I/O. It is the pure
#     layer, every refusal comes from it, and a decision layer that could read
#     the world could decide differently depending on the world.
#
# Test files are not considered: a test may open whatever it needs, and the
# harness cases below rely on that.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

fail=0
note() {
	printf 'FAIL %s\n' "$1"
	fail=1
}

# --- one transport, one dialer, one process launcher ------------------------
#
# Counted over the files `git ls-files` reports rather than the working tree,
# so a stray copy of the repository under here cannot make the count wrong in
# either direction.
go_files=$(git ls-files '*.go' | grep -v '_test\.go$' || true)
if [ -z "$go_files" ]; then
	printf 'FAIL: no non-test Go files found, so this check measured nothing.\n'
	printf '      A gate whose subject is gone says so rather than reporting OK.\n'
	exit 1
fi

# --- the pure layer ---------------------------------------------------------
#
# Read through `go list` rather than by grepping for import lines, because a
# grep sees the text of an import and this sees the resolved graph: a package
# that reaches I/O through one of its own dependencies is caught here and not
# there.
banned_for_decide=(os os/exec net net/http io/ioutil bufio)
decide_line=$(go list -f '{{.ImportPath}}::{{join .Imports " "}}' ./internal/decide/ 2>/dev/null)
if [ -z "$decide_line" ]; then
	printf 'FAIL: could not read internal/decide through `go list`, so nothing was checked.\n'
	printf '      This is not a pass. Fix the build first.\n'
	exit 1
fi
for imp in ${decide_line#*::}; do
	for b in "${banned_for_decide[@]}"; do
		if [ "$imp" = "$b" ]; then
			note "internal/decide imports $imp; the decision layer performs no I/O"
		fi
	done
done

# code_of strips comments before matching.
#
# Added because the harness caught this gate flagging a COMMENT that named
# `http.Transport{` while explaining why only internal/pin may build one. A gate
# that fails on its own documentation gets switched off inside a week, and this
# repository's comments discuss the forbidden constructs at length on purpose.
#
# What it does NOT handle, said rather than discovered: a `//` inside a string
# literal ends the line for this filter too, so a pattern hidden after one in
# the same string would be missed. That is a contrived shape and the cost of
# not shipping a Go parser in a shell script.
code_of() {
	perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' "$1"
}

check_confined() {
	local what="$1" pattern="$2" why="$3"
	shift 3
	local allowed=("$@") f pkg ok
	while IFS= read -r f; do
		code_of "$f" | grep -q -- "$pattern" || continue
		pkg=$(dirname "$f")
		ok=0
		for a in "${allowed[@]}"; do
			[ "$pkg" = "$a" ] && ok=1
		done
		if [ "$ok" -eq 0 ]; then
			note "$f constructs $what; $why"
		fi
	done <<<"$go_files"
}

check_confined "an http.Transport" 'http\.Transport{' \
	"only internal/pin builds one, because every other transport resolves the name again" \
	internal/pin

check_confined "a net.Dialer" 'net\.Dialer{' \
	"only internal/pin and internal/browserproxy dial, and both dial an address a decision returned" \
	internal/pin internal/browserproxy

while IFS= read -r f; do
	code_of "$f" | grep -q '"os/exec"' || continue
	pkg=$(dirname "$f")
	[ "$pkg" = "internal/cdp" ] ||
		note "$f imports os/exec; only internal/cdp starts a subprocess, and it starts a browser"
done <<<"$go_files"

if [ "$fail" -ne 0 ]; then
	printf '\nThis plane has one way out, and something else just opened another.\n'
	printf 'A second transport is a second dialer, and a dialer that resolves the name\n'
	printf 'itself is the hole internal/pin exists to close.\n'
	exit 1
fi

n=$(printf '%s\n' "$go_files" | wc -l | tr -d ' ')
printf 'OK: %s non-test Go file(s). One transport, in internal/pin. One process\n' "$n"
printf '    launcher, in internal/cdp. internal/decide performs no I/O.\n'
