#!/usr/bin/env bash
#
# Invariant 13: never claim compliance.
#
# The wording this repository uses is "covers the requirements of Article 12",
# never "GDPR compliant" and never "AI Act compliant". There is no
# certification behind those words and no auditor, and a claim nobody can hold
# is worse than no claim, because a reader trusts the whole document on the
# strength of it.
#
# WHY A GREP IS ENOUGH HERE, WHEN IT USUALLY IS NOT
#
# The failure mode is a specific English word appearing in a specific role. It
# does not arrive through a refactor or an inlined helper; it arrives because
# somebody wrote a sentence, usually in a hurry, usually in a release note or a
# PR body. A grep is the right shape of check for that, and the interesting
# work is the allowlist rather than the search.
#
# THE ALLOWLIST IS THE WHOLE DESIGN
#
# The word has to be usable, or the rule cannot be stated: this file, CLAUDE.md
# and the README all need to say "never say compliant". So a line carrying the
# word passes only when it also carries a negation, and the negations are
# enumerated rather than guessed at. Anything else fails and asks for a
# rewording.
#
# A line that fails is not necessarily wrong. It is a sentence somebody has to
# look at, which is the most this can honestly do.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

# Everything a reader outside this repository could meet: the README, the
# instruction file, and any docs. Not the Go source, where the word appears in
# error strings that are themselves the honest negative form, and not this
# script.
subjects=$(git ls-files '*.md' | grep -v '^scripts/' || true)
if [ -z "$subjects" ]; then
	printf 'FAIL: no Markdown files found, so this check measured nothing.\n'
	printf '      A gate whose subject is gone says so rather than reporting OK.\n'
	exit 1
fi

# The honest negative forms. A line claiming compliance cannot contain one of
# these and still be a claim: it is either a prohibition, a statement that
# something is NOT claimed, or a quotation of the rule itself.
#
# `no-compliance-claims` is in the list because this gate's own NAME contains
# the word, and a line naming the script is a reference rather than a claim.
# Found on its first run against this repository, where it flagged the gate
# list in CLAUDE.md and the invariant that describes it. Second time a new gate
# here has failed on itself: `readme-numbers.sh` read `%20` out of a badge URL
# and reported twenty dependencies. A check meets its own documentation before
# it meets anything else, and that is where its false positives live.
negations='never|not |no |nobody|refus|avoid|instead of|rather than|without|forbidden|prohibit|cannot|would be|"compliant"|no-compliance-claims'

problems=0
while IFS= read -r f; do
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		n="${line%%:*}"
		text="${line#*:}"
		if printf '%s' "$text" | grep -qiE "$negations"; then
			continue
		fi
		printf 'FAIL %s:%s\n' "$f" "$n"
		printf '     %s\n' "$(printf '%s' "$text" | sed 's/^[[:space:]]*//' | cut -c1-100)"
		problems=$((problems + 1))
	done < <(grep -niE 'complian(t|ce)' "$f" || true)
done <<<"$subjects"

if [ "$problems" -gt 0 ]; then
	printf '\n%d line(s) use the word without a negation, which reads as a claim.\n' "$problems"
	printf 'The wording is "covers the requirements of Article 12". There is no\n'
	printf 'certification behind "compliant" and no auditor, and a reader trusts the\n'
	printf 'whole document on the strength of a claim like that.\n'
	exit 1
fi

n=$(printf '%s\n' "$subjects" | wc -l | tr -d ' ')
printf 'OK: %s Markdown file(s), and every use of the word is a negation.\n' "$n"
