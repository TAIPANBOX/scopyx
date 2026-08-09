#!/usr/bin/env bash
#
# CLAUDE.md invariant 3: the tool takes a URL and never caller-supplied
# headers, cookies or credentials.
#
# WHY A SCRIPT AS WELL AS A TEST
#
# The test in internal/mcp checks the schemas THIS package publishes. It cannot
# see a second surface: a new HTTP handler, a second tool file, a struct that
# gets decoded from a request body somewhere else. Those are how the field
# comes back, because nobody edits the file with the test beside it.
#
# So this reads the whole tree for a field name that would accept one, in a
# struct tag or a schema property, and refuses. It is an anchor and not a
# compiler, which is the best available answer here and not a good one: a field
# called `extra` holding a header map would pass. Named plainly rather than
# implied.
#
# WHAT IT DELIBERATELY DOES NOT FLAG
#
# Test files, which may construct whatever they need to prove a refusal, and
# the forbiddenFields list itself, which exists precisely to name these.
set -uo pipefail

cd "$(dirname "$0")/.."

fail=0
measured=0

# The names, taken from the one place that owns them so this script and the
# package cannot drift. If that function ever stops being readable here, this
# script must say it measured nothing rather than pass with an empty list.
fields=$(
	awk '/^var forbiddenFields = \[\]string\{/,/^\}/' internal/mcp/tools.go |
		grep -oE '"[a-zA-Z_]+"' | tr -d '"'
)

if [ -z "$fields" ]; then
	echo "FAIL: could not read forbiddenFields out of internal/mcp/tools.go, so this"
	echo "      check measured nothing. That is a red, not a pass: a check that"
	echo "      cannot see its subject reports zero forever."
	exit 1
fi

while IFS= read -r file; do
	case "$file" in
	*_test.go) continue ;;
	./internal/mcp/tools.go) continue ;; # owns the list
	esac
	measured=$((measured + 1))
	for f in $fields; do
		# A json struct tag, or a schema property key, naming a forbidden field.
		if grep -nE "json:\"${f}(,|\")|\"${f}\":[[:space:]]*(Property|\{)" "$file" >/dev/null 2>&1; then
			echo "FAIL: $file accepts a caller-supplied '${f}'."
			grep -nE "json:\"${f}(,|\")|\"${f}\":[[:space:]]*(Property|\{)" "$file" | sed 's/^/      /'
			fail=1
		fi
	done
done < <(find . -name '*.go' -not -path './.git/*')

if [ "$measured" -eq 0 ]; then
	echo "FAIL: no Go files were read, so this check measured nothing."
	exit 1
fi

if [ "$fail" -ne 0 ]; then
	echo
	echo "A free-form header, cookie or credential field is a laundering channel"
	echo "straight past the broker's DLP, which scans the arguments it understands"
	echo "and cannot read an opaque map of strings. It is also how a plane that"
	echo "refuses authenticated sessions acquires them one header at a time."
	echo "Authenticated fetching belongs to the backend and its own credential"
	echo "store. See CLAUDE.md invariant 3."
	exit 1
fi

echo "OK: ${measured} Go file(s) read, none accepts a caller-supplied header, cookie or credential."
