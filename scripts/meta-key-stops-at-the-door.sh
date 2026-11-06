#!/usr/bin/env bash
# CLAUDE.md invariant 16: the door's credential may travel in the body, and it stops
# at the door.
#
# WHY A SCRIPT AS WELL AS THE TESTS
#
# The tests hold what a request does. They cannot see the door moving: a dispatch
# that starts reading the body ahead of it, a second reader of the entry somewhere
# past it, or a method added to the list that needs no credential because it looked
# harmless. Each of those compiles and passes everything that does not send that
# one message.
#
# WHAT IT CHECKS
#
# With comments and tests masked: the entry's name appears in no Go file but
# internal/mcp/meta.go; in that file, needsNoCredential's list carries exactly
# initialize, tools/list and notifications/initialized, and it never goes by the
# absence of an id; in ServeHTTP, the door (`doorFromBody(`, then `s.Keys.Allow(`)
# comes before the first `json.NewDecoder(`.
#
# WHAT IT REFUSES TO PASS ON
#
# Either file or an anchor gone: the scan measured nothing, and that is a red.
set -uo pipefail

cd "$(dirname "$0")/.."

meta="internal/mcp/meta.go"
server="internal/mcp/server.go"
fail=0

for f in "$meta" "$server"; do
	if [ ! -f "$f" ]; then
		echo "FAIL: $f is not there, so this gate measured nothing."
		exit 1
	fi
done

code() { sed -e 's://.*$::' "$1"; }

# 1. The entry's name, in code, anywhere but the file that owns it.
leaks=$(git ls-files '*.go' | grep -v '_test\.go$' | grep -vxF "$meta" | while IFS= read -r f; do
	[ -f "$f" ] && grep -qF 'scopyx/key' <<<"$(code "$f")" && printf '%s\n' "$f"
done)
if [ -n "$leaks" ]; then
	printf 'FAIL: the entry is named outside internal/mcp/meta.go: %s\n' "$leaks"
	fail=1
fi

# 2. What needs no credential.
open=$(code "$meta" | awk '/^func needsNoCredential\(/,/^}/')
if [ -z "$open" ]; then
	echo "FAIL: $meta has no needsNoCredential, so this gate measured nothing."
	exit 1
fi
list=$(printf '%s\n' "$open" | grep -E '^[[:space:]]*case ' | tr -d '\t')
if [ "$list" != 'case "initialize", "tools/list", "notifications/initialized":' ]; then
	printf 'FAIL: what needs no credential is initialize, tools/list and the initialized notification, and it reads: %s\n' "$list"
	fail=1
fi
if grep -qE 'req\.ID|env\.ID|\.ID\)' <<<"$open"; then
	echo "FAIL: needsNoCredential goes by the absence of an id, and a tools/call with no id still fetches."
	fail=1
fi

# 3. The door before the dispatch reads the body.
serve=$(code "$server" | awk '/^func \(s \*Server\) ServeHTTP\(/,/^}/')
door=$(printf '%s\n' "$serve" | grep -n 'doorFromBody(' | head -1 | cut -d: -f1)
allow=$(printf '%s\n' "$serve" | grep -n 's.Keys.Allow(' | head -1 | cut -d: -f1)
decode=$(printf '%s\n' "$serve" | grep -n 'json.NewDecoder(' | head -1 | cut -d: -f1)
if [ -z "$door" ] || [ -z "$allow" ] || [ -z "$decode" ]; then
	echo "FAIL: ServeHTTP has lost one of its anchors, so this gate measured nothing."
	exit 1
fi
if [ "$decode" -lt "$door" ] || [ "$decode" -lt "$allow" ]; then
	echo "FAIL: the dispatch reads the body before the door has spoken."
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "OK: the door's key is read at the door, a fetch always needs one, and nothing past it names the entry."
