# Security Policy

scopyx is a policy enforcement point for agent web egress, sitting between an
agent and the fetching backend it already uses; a defect here is a way past
the one control between an agent and the open web.

## Reporting a vulnerability

Please report security issues privately, not in public issues or pull requests: open a
GitHub private security advisory at
<https://github.com/TAIPANBOX/scopyx/security/advisories/new>. Include the affected
version or commit, a description and a minimal reproduction. We aim to acknowledge
within a few days and to fix high-severity issues before any public disclosure, with
coordinated disclosure within 90 days of the report. There is no bug-bounty programme;
reporters are credited in the advisory unless they prefer otherwise.

## Supported versions

Before this repository's 1.0, only `main` is supported: fixes land on `main` and are
not backported. From its 1.0 tag, the newest minor gets every fix and the previous
minor gets security-relevant fixes for 90 days after the newer one is tagged.

## Verifying a build

Every change passes the repository's gates before merge: `gofmt -l .`, `go vet
./...`, `staticcheck ./...`, `go test -race ./...`, `go build ./...`, plus this
repository's own gate scripts (`no-caller-headers.sh`, `one-way-out.sh`,
`readme-numbers.sh`, `no-delegated-decisions.sh`, `no-warm-context.sh`,
`no-compliance-claims.sh`, `gates-have-teeth.sh`). Release assets are signed
keyless with Sigstore and carry a provenance attestation and an SBOM; the
README's verify block shows how to check them.
