#!/usr/bin/env bash
# Every number this README states about this repository, checked against the
# repository.
#
# WHY THIS EXISTS
#
# A number on a README is a claim with no owner. It is right the day it is
# written and nothing tells anybody when it stops being right, because the
# suite grows in a commit that never opens the README.
#
# Not hypothetical, and not distant: on 2026-08-05 the it-rat.com service pages
# were audited against the repositories they describe and four of seven figures
# were stale, one of them by 196 tests. Sibling repositories gained this gate
# then. This one shipped without it and carried the badge on trust for a day.
#
# WHAT "TESTS" MEANS HERE, because a number needs a definition more than it
# needs a badge
#
# `go test ./... -list '.*'` enumerates test FUNCTIONS. It does not count
# subtests created with `t.Run`, and it does not count table cases inside one
# function. So the figure is "test functions in this module", which is a real
# and checkable quantity, and it is deliberately not called "assertions" or
# "cases", both of which would be larger and neither of which anybody can
# reproduce.
#
# It also does not run them. This is a claim about how much test code exists,
# not about it passing: `go test -race ./...` in CI is what says they pass, and
# conflating the two would let a green badge mean a red suite.
#
# THE DEPENDENCY COUNT IS THE MORE INTERESTING ONE
#
# "one direct dependency" is a claim this repository makes as an argument: an
# operator can read what governs their egress. It is also the claim most likely
# to stop being true without anybody deciding it should, because adding a
# dependency is one line and the README is somewhere else entirely.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

readme="README.md"
problems=0

note() {
	printf '%s\n' "$1"
	problems=$((problems + 1))
}

if [ ! -f "$readme" ]; then
	printf 'FAIL: there is no README.md, so this check measured nothing.\n'
	exit 1
fi

# --- test functions ---------------------------------------------------------
actual=$(go test ./... -list '.*' 2>/dev/null | grep -cE '^Test')
if [ "${actual:-0}" -eq 0 ]; then
	note "the module reported no test functions at all, which means this check measured nothing"
	printf '\nA gate whose subject is gone says so rather than reporting OK on nothing.\n'
	exit 1
fi

stated=$(grep -o 'badge/tests-[0-9]*-' "$readme" | grep -o '[0-9]*' | head -1)
if [ -z "$stated" ]; then
	note "the README carries no tests badge, so this check has nothing to compare against"
	note "  add: ![tests](https://img.shields.io/badge/tests-${actual}-brightgreen.svg)"
else
	[ "$stated" = "$actual" ] ||
		note "the badge says $stated test functions and \`go test -list\` counts $actual"
fi

# --- direct dependencies ----------------------------------------------------
#
# Read from go.mod rather than `go list -m all`, which reports the whole graph
# including everything the dependencies bring. The claim is about what THIS
# module requires directly, which is the line an author writes.
deps=$(awk '
	/^require \(/ { inblock = 1; next }
	inblock && /^\)/ { inblock = 0; next }
	inblock && /\/\/ indirect/ { next }
	inblock && NF > 0 { n++ }
	/^require [^(]/ && $0 !~ /\/\/ indirect/ { n++ }
	END { print n + 0 }
' go.mod)

# Captured with sed rather than two greps, because the badge URL contains
# `%20` and `grep -o '[0-9]*'` reads the 20 out of the ESCAPE and reports
# twenty direct dependencies. Found by this gate on its first run, against
# itself, which is the argument for running a new check before trusting it.
stated_deps=$(sed -n 's/.*dependencies-\([0-9][0-9]*\)-.*/\1/p' "$readme" | head -1)
if [ -z "$stated_deps" ]; then
	note "the README carries no direct-dependency badge, so this check has nothing to compare against"
else
	[ "$stated_deps" = "$deps" ] ||
		note "the badge says $stated_deps direct dependencies and go.mod requires $deps"
fi

# --- the Go version ---------------------------------------------------------
#
# The badge is a promise about what a reader needs installed, and it is the
# figure with the longest half-life and therefore the one nobody re-reads.
gomod_go=$(awk '/^go [0-9]/ { split($2, v, "."); print v[1] "." v[2]; exit }' go.mod)
stated_go=$(grep -o 'badge/go-[0-9.]*-' "$readme" | grep -o '[0-9.]*' | head -1)
if [ -n "$stated_go" ] && [ -n "$gomod_go" ]; then
	[ "$stated_go" = "$gomod_go" ] ||
		note "the badge says Go $stated_go and go.mod says $gomod_go"
fi

if [ "$problems" -gt 0 ]; then
	printf '\n%d number(s) the README states that this repository does not support.\n' "$problems"
	printf 'Update them in the same commit as the change. That is the whole point: the\n'
	printf 'suite and go.mod change in commits that never open the README, and this is\n'
	printf 'what makes that impossible.\n'
	exit 1
fi

printf '%s test functions, %s direct dependency(ies), Go %s, and the README says so.\n' \
	"$actual" "$deps" "${gomod_go:-?}"
