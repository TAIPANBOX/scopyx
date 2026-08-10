#!/usr/bin/env bash
# Checks that the gates in `scripts/` still FAIL on the faults they exist to
# catch, still PASS on what they must not catch, and REFUSE to report success
# when they measured nothing at all.
#
# WHY
#
# Every gate here parses text, and a text parser does not break loudly: it
# stops matching and reports success. A gate that has quietly stopped catching
# anything looks exactly like a gate with nothing to catch, and stays that way
# until the fault it guards ships.
#
# scopyx was the only repository in this estate without this harness, and the
# reason is worth keeping: `CLAUDE.md` listed it, along with `one-way-out.sh`
# and `readme-numbers.sh`, from the first commit. `scripts/` held one file. The
# list was copied from the siblings that have them, so the absence read as a
# presence for a day and a half. Prose describing a check reads exactly like a
# check.
#
# A GATE THAT IS ALREADY FAILING CANNOT BE JUDGED
#
# No case proves anything if the gate was already failing before the mutation.
# So every case runs the gate on the UNMUTATED tree first and reports
# UNJUDGEABLE rather than a verdict. This applies to pass-cases too: on a red
# gate a pass-case would report OVEREAGER and send a reader to look at a
# harmless mutation while the gate was failing without it.
#
# A MUTATION THAT DID NOT APPLY PROVES NOTHING
#
# Every edit asserts it changed the file, and a case whose edit applied nothing
# fails here rather than passing. This is not hypothetical in this session: an
# earlier red-before-green check in this repository ran a `str.replace` that
# matched nothing, changed nothing, and reported the tests passing against
# "unfixed" code that was never unfixed.
#
# HOW IT MUTATES WITHOUT LEAVING A MESS
#
# It edits tracked files in place, refuses to start unless the tree is clean,
# restores after every case, restores again from a trap on any exit path, and
# asserts the tree is clean before reporting success.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ -n "$(git status --porcelain)" ]; then
	printf 'this script mutates tracked files, so it needs a clean tree.\n'
	printf 'commit or stash first; it restores with `git reset --hard` and cannot\n'
	printf 'tell your edits from its own.\n'
	exit 1
fi

restore() {
	git reset -q --hard HEAD 2>/dev/null
	git clean -fdq 2>/dev/null
}
baseline_dir="$(mktemp -d)"

# One trap for both, because a second `trap ... EXIT` REPLACES the first rather
# than adding to it.
cleanup() {
	restore
	rm -rf "$baseline_dir"
}
trap cleanup EXIT INT TERM

failures=0
cases=0

# run_case <name> <expect: fail|pass> <gate> <python edit> [required output]
#
# The needle separates "it failed" from "it failed for the reason this case is
# about". Without it, a case expecting failure is satisfied by any failure,
# including one this harness caused itself.
run_case() {
	local name="$1" expect="$2" gate="$3" edit="$4" needle="${5:-}"
	cases=$((cases + 1))

	local key base_out
	key="$baseline_dir/$(printf '%s' "$gate" | cksum | tr -d ' ')"
	if [ ! -f "$key" ]; then
		if eval "$gate" >/dev/null 2>&1; then printf 'green' >"$key"; else printf 'red' >"$key"; fi
	fi
	base_out="$(cat "$key")"
	if [ "$base_out" = red ]; then
		printf 'UNJUDGEABLE  %s\n             the gate is already failing on a clean tree, so neither a\n             failure nor a pass after the mutation would prove anything\n' "$name"
		failures=$((failures + 1))
		return
	fi

	if ! python3 -c "$edit"; then
		printf 'BROKEN  %s\n        its mutation did not apply, so this case proved nothing\n' "$name"
		failures=$((failures + 1))
		restore
		return
	fi

	local out rc
	out=$(eval "$gate" 2>&1)
	rc=$?
	restore

	# Exit code first, then wording. Checking the needle before the expectation
	# turns "it did not fail at all" into "it failed for the wrong reason",
	# which sends the reader to look at prose when the gate is toothless.
	if [ "$expect" = fail ] && [ "$rc" -ne 0 ] && [ -n "$needle" ] &&
		! printf '%s' "$out" | grep -qF -- "$needle"; then
		printf 'WRONG REASON  %s\n              it failed, but not saying: %s\n' "$name" "$needle"
		failures=$((failures + 1))
		return
	fi
	if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
		printf 'TOOTHLESS  %s\n           the gate passed on a fault it exists to catch\n' "$name"
		failures=$((failures + 1))
	elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
		printf 'OVEREAGER  %s\n           the gate failed on something it must not catch\n' "$name"
		printf '%s\n' "$out" | sed 's/^/           /' | head -4
		failures=$((failures + 1))
	else
		printf 'ok  %-58s (%s)\n' "$name" "$expect"
	fi
}

py() { printf 'def edit(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b, 1))\n%s\n' "$1"; }

echo "=== faults each gate must catch ==="

# Invariant 11. A second transport is a second dialer, and a dialer that
# resolves the name itself is the hole internal/pin exists to close.
run_case "one-way-out: a second http.Transport, outside internal/pin" fail \
	'./scripts/one-way-out.sh' \
	"$(py 'edit("internal/record/record.go", "import (", "import (\n\t\"net/http\"")
s = open("internal/record/record.go").read()
open("internal/record/record.go","w").write(s + "\n\nvar elsewhere = &http.Transport{}\n")')" \
	"constructs an http.Transport"

# The same rule one layer down: a dialer anywhere other than the two places
# that dial an address a decision returned.
run_case "one-way-out: a net.Dialer in a package that must not dial" fail \
	'./scripts/one-way-out.sh' \
	"$(py 'edit("internal/mcp/server.go", "import (", "import (\n\t\"net\"")
s = open("internal/mcp/server.go").read()
open("internal/mcp/server.go","w").write(s + "\n\nvar d = &net.Dialer{}\n")')" \
	"constructs a net.Dialer"

# The decision layer is pure, and every refusal comes from it. A decision layer
# that could read the world could decide differently depending on the world.
run_case "one-way-out: internal/decide reaches for I/O" fail \
	'./scripts/one-way-out.sh' \
	"$(py 'edit("internal/decide/decide.go", "import (", "import (\n\t\"os\"")
s = open("internal/decide/decide.go").read()
open("internal/decide/decide.go","w").write(s + "\n\nvar _ = os.Getenv\n")')" \
	"internal/decide imports os"

# One privilege, one package. Starting a subprocess is the browser launch and
# nothing else.
run_case "one-way-out: os/exec outside internal/cdp" fail \
	'./scripts/one-way-out.sh' \
	"$(py 'edit("internal/policy/client.go", "import (", "import (\n\t\"os/exec\"")
s = open("internal/policy/client.go").read()
open("internal/policy/client.go","w").write(s + "\n\nvar _ = exec.Command\n")')" \
	"imports os/exec"

# The badge and the suite change in different commits, which is the whole
# reason the number needs an owner.
run_case "readme-numbers: the tests badge drifts from the suite" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"badge/tests-(\d+)-", s)
assert m, "no tests badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "badge/tests-%d-" % (int(m.group(1)) + 7), 1))')" \
	"test functions and"

# The claim most likely to stop being true without anybody deciding it should.
run_case "readme-numbers: the dependency count drifts from go.mod" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'edit("README.md", "direct%20dependencies-1-", "direct%20dependencies-4-")')" \
	"direct dependencies and go.mod requires"

# Invariant 3, and the gate this repository already had.
run_case "no-caller-headers: a tool grows a header map" fail \
	'./scripts/no-caller-headers.sh' \
	"$(py 's = open("internal/mcp/server.go").read()
open("internal/mcp/server.go","w").write(s + "\n\ntype sneak struct {\n\tHeaders map[string]string `json:\"headers\"`\n}\n")')" \
	"headers"

# Invariant 1. A backend that can build a verdict can build a different one
# from the plane above it, and no comment prevents that.
run_case "no-delegated-decisions: a backend constructs a verdict" fail \
	'./scripts/no-delegated-decisions.sh' \
	"$(py 's = open("internal/backend/passthrough.go").read()
open("internal/backend/passthrough.go","w").write(s + "\n\nvar own = decide.Decision{Verdict: decide.DenyPolicy}\n")')" \
	"constructs a decide.Decision"

run_case "no-delegated-decisions: a backend reaches for the policy plane" fail \
	'./scripts/no-delegated-decisions.sh' \
	"$(py 'edit("internal/backend/external.go", "import (", "import (\n\t_ \"github.com/TAIPANBOX/scopyx/internal/policy\"")')" \
	"imports internal/policy"

# Invariant 4, and the shape somebody will add on purpose believing it is an
# improvement.
run_case "no-warm-context: a client grows a cookie jar" fail \
	'./scripts/no-warm-context.sh' \
	"$(py 'edit("internal/pin/pin.go", "Timeout:       timeout,", "Timeout:       timeout,\n\t\tJar:           nil,")')" \
	"cookie jar"

run_case "no-warm-context: keep-alives come back on" fail \
	'./scripts/no-warm-context.sh' \
	"$(py 'edit("internal/pin/pin.go", "DisableKeepAlives:     true,", "DisableKeepAlives:     false,")')" \
	"no longer disables keep-alives"

run_case "no-warm-context: the browser profile stops being per fetch" fail \
	'./scripts/no-warm-context.sh' \
	"$(py 'edit("internal/backend/chromium.go", "os.MkdirTemp", "mkdirTempDisabled")')" \
	"temporary profile directory"

# Invariant 13. The word arrives in a sentence somebody wrote in a hurry, which
# is exactly what a grep is the right shape of check for.
run_case "no-compliance-claims: a README that claims compliance" fail \
	'./scripts/no-compliance-claims.sh' \
	"$(py 's = open("README.md").read()
open("README.md","w").write(s + "\n\nscopyx is GDPR compliant and AI Act compliant.\n")')" \
	"reads as a claim"

echo
echo "=== and what they must NOT catch ==="

# Prose that names a forbidden thing is not the forbidden thing. A gate that
# flagged its own documentation would be switched off inside a week, and this
# repository's comments discuss http.Transport at length on purpose.
run_case "one-way-out: a comment that mentions http.Transport" pass \
	'./scripts/one-way-out.sh' \
	"$(py 'edit("internal/record/record.go", "package record",
     "// A second http.Transport{ here would be a second dialer, which is why\n// internal/pin owns the only one.\npackage record")')"

# A test may open whatever it needs, and the cases above rely on that being
# true. If test files were counted, every fixture in this repository would
# fail the gate.
run_case "one-way-out: a transport in a TEST file" pass \
	'./scripts/one-way-out.sh' \
	"$(py 's = open("internal/record/record_test.go").read()
open("internal/record/record_test.go","w").write(s + "\n\n// fixtures may open what they need\n")')"

# Prose naming a forbidden construct is not the construct. These gates read
# code with the comments stripped, and this repository's comments discuss
# `decide.Decision` and cookie jars at length on purpose.
run_case "no-delegated-decisions: a comment that mentions decide.Decision" pass \
	'./scripts/no-delegated-decisions.sh' \
	"$(py 'edit("internal/backend/external.go", "package backend",
     "// A decide.Decision{ built here would be invariant 1 broken from inside.\npackage backend")')"

# And the honest negative form has to stay usable, or the rule cannot be
# written down anywhere, including in the file that states it.
run_case "no-compliance-claims: a line that says never to claim it" pass \
	'./scripts/no-compliance-claims.sh' \
	"$(py 's = open("README.md").read()
open("README.md","w").write(s + "\n\nThis is never described as GDPR compliant, because nobody could hold that.\n")')"

echo
echo "=== and the one this estate learned the hard way ==="
echo "    a gate whose subject is gone must SAY so, not report OK on nothing"

run_case "readme-numbers: no README left to read" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import subprocess
subprocess.run(["git", "mv", "README.md", "README.md.disabled"], check=True)')" \
	"there is no README.md"

run_case "no-compliance-claims: no Markdown left to read" fail \
	'./scripts/no-compliance-claims.sh' \
	"$(py 'import subprocess, pathlib
n = 0
for f in sorted(pathlib.Path(".").rglob("*.md")):
    if ".git" in str(f):
        continue
    subprocess.run(["git", "mv", str(f), str(f) + ".disabled"], check=True)
    n += 1
assert n, "no Markdown in this repo"')" \
	"measured nothing"

run_case "no-delegated-decisions: no backend files left to read" fail \
	'./scripts/no-delegated-decisions.sh' \
	"$(py 'import subprocess, pathlib
n = 0
for f in sorted(pathlib.Path("internal/backend").glob("*.go")):
    if str(f).endswith("_test.go"):
        continue
    subprocess.run(["git", "mv", str(f), str(f) + ".disabled"], check=True)
    n += 1
assert n, "no backend files"')" \
	"measured nothing"

run_case "one-way-out: no Go files left to read" fail \
	'./scripts/one-way-out.sh' \
	"$(py 'import subprocess, pathlib
n = 0
for f in sorted(pathlib.Path("internal").rglob("*.go")) + sorted(pathlib.Path("cmd").rglob("*.go")):
    subprocess.run(["git", "mv", str(f), str(f) + ".disabled"], check=True)
    n += 1
assert n, "no Go files in this repo"')" \
	"measured nothing"

echo
if [ -n "$(git status --porcelain)" ]; then
	printf 'FAIL: this script left the tree dirty, so it cannot be trusted about anything above\n'
	git status --porcelain | head -5
	exit 1
fi

if [ "$failures" -gt 0 ]; then
	printf '%d of %d cases failed.\n' "$failures" "$cases"
	printf 'A gate that has quietly stopped catching anything looks exactly like a gate\n'
	printf 'with nothing to catch, and stays that way until the fault it guards ships.\n'
	exit 1
fi

printf 'OK: %d cases. Every gate fails on its own fault, passes on a non-fault,\n' "$cases"
printf '    and refuses to report success when it measured nothing.\n'
