#!/usr/bin/env bash
#
# vexhub-pr.sh -- contribute the findings a vexscan run ruled out to a VEX hub.
#
# vexscan writes the OpenVEX documents; this does the git and gh steps around
# them. The split is deliberate: gh already knows about forks, commit signing,
# branch protection, 2FA and org policy, and it is the tool whose behaviour you
# can predict. The one thing this script will not do is skip the review -- it
# prints the diff and stops for a yes, because a not_affected statement in a
# public hub tells other people's scanners to stop reporting a vulnerability.
#
# Usage:
#   contrib/vexhub-pr.sh --hub OWNER/REPO --author NAME -- <vexscan args...>
#
# Example:
#   contrib/vexhub-pr.sh \
#     --hub rancher/vexhub \
#     --author 'Acme Security' \
#     -- --image rancher/hardened-kubernetes:v1.34.10-rke2r1-build20260724 --all
#
# Options:
#   --hub OWNER/REPO   the hub to contribute to (required)
#   --author NAME      the OpenVEX author to record (required)
#   --fork OWNER/REPO  push the branch here instead of to the hub; gh creates
#                      and syncs it for you if you leave this off and lack write
#   --workdir DIR      where to clone (default: a temp dir, removed on exit)
#   --yes              skip the confirmation prompt (for CI that has already
#                      reviewed the diff some other way)
#
# Requires: vexscan, git, gh (authenticated: gh auth login).

set -euo pipefail

die() { printf 'vexhub-pr: %s\n' "$*" >&2; exit 1; }
note() { printf 'vexhub-pr: %s\n' "$*" >&2; }

hub=""
author=""
fork=""
workdir=""
assume_yes=0

while [ $# -gt 0 ]; do
	case "$1" in
		--hub)     hub="${2:-}"; shift 2 ;;
		--author)  author="${2:-}"; shift 2 ;;
		--fork)    fork="${2:-}"; shift 2 ;;
		--workdir) workdir="${2:-}"; shift 2 ;;
		--yes)     assume_yes=1; shift ;;
		--)        shift; break ;;
		-h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*)         die "unknown option $1 (scan flags go after --)" ;;
	esac
done

[ -n "$hub" ]    || die "--hub OWNER/REPO is required"
[ -n "$author" ] || die "--author NAME is required"
[ $# -gt 0 ]     || die "no vexscan arguments; put them after --"

for tool in vexscan git gh; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH"
done
gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run: gh auth login"

if [ -n "$workdir" ]; then
	mkdir -p "$workdir"
else
	workdir="$(mktemp -d)"
	trap 'rm -rf "$workdir"' EXIT
fi
clone="$workdir/${hub##*/}"

# A stale clone is the failure this whole flow is most likely to hit: a branch
# based on an out-of-date default reverts everything the hub merged since. Clone
# fresh, and sync a fork before basing anything on it.
note "cloning $hub"
gh repo clone "$hub" "$clone" -- --depth 1 --quiet
if [ -n "$fork" ]; then
	note "syncing $fork with $hub"
	gh repo sync "$fork" --source "$hub" >/dev/null
fi

[ -f "$clone/index.json" ] || die "$hub has no index.json; is it a VEX hub?"

# Merge against the clone and write back into it, so the result is a git diff.
note "scanning"
vexscan "$@" \
	--vexhub "$clone" \
	--vex-out "$clone" \
	--vex-author "$author"

if git -C "$clone" diff --quiet; then
	note "no changes; the hub already covers everything this scan ruled out"
	exit 0
fi

printf '\n'
git -C "$clone" --no-pager diff --stat
printf '\n'
git -C "$clone" --no-pager diff
printf '\n'

if [ "$assume_yes" -ne 1 ]; then
	printf 'vexhub-pr: open a pull request against %s with the above? [y/N] ' "$hub" >&2
	read -r reply </dev/tty
	case "$reply" in
		y|Y|yes|YES) ;;
		*) note "stopped; the clone is at $clone"; trap - EXIT; exit 1 ;;
	esac
fi

branch="vexscan/ruled-out-$(date -u +%Y%m%d%H%M%S)"
files="$(git -C "$clone" diff --name-only | sed 's/^/- /')"
subject="Add vexscan not_affected statements"
body="$(cat <<EOF
Automated by [vexscan](https://github.com/cwayne18/vexscan) ($(vexscan --version)).

Scan: \`vexscan $*\`

These \`not_affected\` statements record findings vexscan ruled out because the
vulnerable code is not present or cannot be reached. Each carries the OpenVEX
justification behind the verdict and a sentence saying how the verdict was
reached; review before merging.

Files changed:
$files
EOF
)"

git -C "$clone" checkout -q -b "$branch"
git -C "$clone" add -A
git -C "$clone" commit -q -m "$subject" -m "$body"

if [ -n "$fork" ]; then
	git -C "$clone" remote add fork "https://github.com/$fork.git"
	git -C "$clone" push -q fork "$branch"
	head="${fork%%/*}:$branch"
else
	# No --fork: let gh decide. It offers to fork when the token cannot push.
	head="$branch"
fi

note "opening pull request"
gh pr create \
	--repo "$hub" \
	--head "$head" \
	--title "$subject" \
	--body "$body"
