---
sidebar_position: 4
title: "Contributing VEX back"
---


`--vexhub` *reads* a hub. `--vex-out` *writes* the other direction: it turns
every finding this scan **ruled out** — the `RULED OUT` section, where the
vulnerable code is not present or cannot run — into a `not_affected` statement,
and lays the documents out in a directory as a VEX hub. OpenVEX by default,
CSAF 2.0 with [`--vex-format csaf`](#writing-csaf-instead---vex-format), and for
a hub that also keeps one merged report of everything,
[`--vex-merge-into`](#merged-master-reports---vex-merge-into).

It writes files and stops there. Getting them into somebody else's hub is a pull
request, and that is git's job and `gh`'s job — both of which already know about
forks, commit signing, branch protection and org policy. So the workflow is
clone, merge, look at the diff:

```sh
gh repo clone rancher/vexhub

vexscan --image rancher/hardened-kubernetes:v1.34.10-rke2r1-build20260724 --all \
  --vexhub ./vexhub \
  --vex-out ./vexhub \
  --vex-author 'Acme Security'

git -C vexhub diff        # then commit and open the PR however you normally would
```

Point `--vexhub` and `--vex-out` at the same clone and the output *is* the hub's
own files with statements added, so `git diff` shows exactly what you would be
asking a maintainer to accept. `contrib/vexhub-pr.sh` wraps those five steps —
clone, scan, print the diff, ask, `gh pr create` — if you want them in one
command.

Each ruled-out finding becomes one statement, filed under the artifact it was
found in (`pkg:oci/…` or a Go binary's `pkg:golang/…`), scoped to the component
purl, and carrying the justification the plugin already recorded
(`component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`) plus a one-line impact statement saying
how vexscan reached the verdict.

- **The diff is the product.** Existing documents are merged, not overwritten,
  and merged at the byte level: unknown fields, key order, indent width and
  whether the file ends in a newline are all preserved. Adding one product to
  rancher/vexhub's 4381-line `index.json` is a four-line diff, which is the
  difference between a reviewable pull request and an unreviewable one.
- **A finding the hub already speaks to is never touched.** If `--vexhub` matched
  a statement for it — even an `affected` one — nothing is written for it. This
  fills gaps; it does not overrule a vendor.
- **Only a complete scan writes.** If any ecosystem failed to inventory, the run
  exits 1 and `--vex-out` does not run: a `not_affected` claim from a partial
  scan is exactly the kind of wrong this tool must never publish.
- **`--vex-author` is required, and it is you.** There is no default, because the
  author of a VEX statement is whoever is answerable for it and a
  `not_affected` claim is what tells other people's scanners to stop reporting a
  vulnerability. `"vexscan"` is not an answer to who said so. `--vex-author`
  without `--vex-out` is a command-line error (exit 2) rather than a silent
  no-op.
- **A document vexscan cannot parse is left exactly as it is.** If the hub's
  existing file for a product does not decode, nothing is written for that
  product and a `warning:` names it on stderr, rather than replacing the file
  with a fresh one. A statement this version cannot read is still one its
  publisher meant.
- **`--vex-out` without `--vexhub` bootstraps a hub.** With nothing to merge
  against, the output directory is a hub in its own right, `index.json` and all —
  useful for publishing your own.

No token is needed: `--vex-out` writes to the filesystem, and every read of the
hub goes over the same read-only path `--vexhub` already uses, so a local
directory, a raw base URL and a `github.com` URL all work as the merge base.

#### Merged "master" reports (`--vex-merge-into`)

Some hubs publish, alongside the per-product tree, one document with *every*
product's statements merged into it — [rancher/vexhub](https://github.com/rancher/vexhub)
has three under `reports/`. A CI run that scans thirty images hands its scanner
one `--vex reports/rancher.openvex.json` rather than assembling thirty
documents, which is the whole reason the file exists. It is also the file most
consumers actually read, so a contribution that updates `pkg/` and leaves it
behind is a contribution that changes nothing for them.

`--vex-merge-into` adds every statement to it as well:

```sh
vexscan --images-from fleet.txt --all \
  --vexhub ./vexhub \
  --vex-out ./vexhub \
  --vex-author 'Acme Security' \
  --vex-merge-into reports/rancher.openvex.json
```

```
vex-out: wrote 41 statement(s) across 12 product(s) to ./vexhub
  …
  reports/rancher.openvex.json: +41 statement(s) across 12 product(s), merged
```

The merge is the same byte-preserving one the per-product documents get, which
matters more here than anywhere else: rancher's merged report is 127 MB of
statements on a single line, and it comes back out as 127 MB on a single line
with the statements appended and `timestamp` moved. The hub's own `@id`,
`author` and `version` are left alone — you are adding to their document, not
reissuing it — and dedupe runs against everything already in it, so a claim the
merged report already carries is not written a second time even when the
per-product document is missing it. The reverse holds too: a finding a
per-product document (or a vendor's own statement) already answers is still
folded into a merged report that lacks it, so the aggregate a CI run reads is
brought up to date rather than left permanently behind the tree.

- **Aggregates are named, never discovered.** Nothing in the VEX Repository
  spec describes them; `index.json` maps a product to one document, and none of
  rancher's merged reports appear in it. From the outside they are
  indistinguishable from any other JSON in the tree, so vexscan will not guess —
  look in the hub, and pass the path. The flag is repeatable for a hub that
  publishes several.
- **They are never added to `index.json`.** Indexing one would tell every reader
  that the merged report is *the* document for some single product, which is
  exactly what it is not.
- **A named aggregate that cannot be written fails the run,** where an
  unreadable per-product document is warned about and stepped over. The
  difference is who chose the file: you named this one because the contribution
  is not useful without it. Nothing is on disk when the check runs, so the exit
  leaves the clone untouched rather than half updated. The three cases are a
  path the hub does not publish (usually a typo), a file that is not an OpenVEX
  document, and an unfetched Git LFS pointer:

  ```
  error: vex-out: vexpr: --vex-merge-into reports/rancher.openvex.json: it is an
  unfetched Git LFS pointer, not the document it stands for; fetch it
  (git lfs pull --include=<path>) and re-run
  ```

- **CSAF has no shape for one.** A CSAF advisory is identified by
  `document.tracking.id`, revised as a unit and attributed to one publisher, so
  one holding every product's claims would be claiming authority over all of
  them at once. `--vex-merge-into` with `--vex-format csaf` is a command-line
  error (exit 2), not a silent no-op.

`contrib/vexhub-pr.sh --merge-into PATH` does the same thing through the PR
flow, and takes care of the LFS side: it clones with `GIT_LFS_SKIP_SMUDGE=1`,
then fetches just the aggregates you named, so a 127 MB object is pulled only
when you are actually merging into it. It excludes them from the diff it prints
for review — a one-line 127 MB file has no reviewable diff — and lists them in
the PR body instead. Worth knowing before you open the PR: **each such PR pushes
a fresh copy of the whole object**, and that counts against the hub's Git LFS
storage and bandwidth quota. The script says so before it asks.

#### Writing CSAF instead (`--vex-format`)

`--vex-format csaf` writes the same verdicts as
[CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) VEX
advisories — `scan.csaf.json` next to where `scan.openvex.json` would have gone,
in the same `pkg/` tree, indexed the same way. Which findings are selected, how
they are deduplicated against the hub, and everything the bullets above say are
identical; only the serialisation differs.

```sh
vexscan --image rancher/hardened-kubernetes:v1.34.10-rke2r1-build20260724 --all \
  --vexhub ./vexhub \
  --vex-out ./vexhub \
  --vex-author 'Acme Security' \
  --vex-format csaf \
  --vex-publisher-namespace https://acme.example \
  --vex-publisher-category vendor
```

CSAF asks for an identity OpenVEX does not. Its `publisher` block is mandatory
and has three members, so `--vex-publisher-namespace` — the URI that says who
published the advisory — is **required** and has no default, for the same reason
`--vex-author` does not. `--vex-publisher-category` defaults to `other`; the
values CSAF defines are `coordinator`, `discoverer`, `other`, `translator`,
`user` and `vendor`. Both flags are an error without `--vex-format csaf`, rather
than being quietly ignored.

The mapping is one-to-one in both directions, which is what makes a document
written here readable by `--vexhub` and by anything else that reads CSAF:

| OpenVEX | CSAF |
|---|---|
| `status: not_affected` | `product_status.known_not_affected` |
| `products[].@id` | a `full_product_names` entry whose `product_identification_helper.purl` is the purl |
| `products[].subcomponents[].@id` | a `default_component_of` relationship from the component to the product |
| `justification` | `flags[].label` — the same five values, spelled identically |
| `impact_statement` | `threats[]` with `category: impact` |
| `vulnerability.name` / `.aliases` | `cve` when one of them is a CVE, and `ids[]` with a `system_name` for the rest |
| `author` / `timestamp` | `document.publisher` / `document.tracking` |

Two consequences of CSAF's own model are worth knowing before you use it:

- **A CSAF document is an advisory, and amending one issues a new version of it
  in its publisher's name.** So only a document vexscan itself wrote is added
  to. Ownership is decided by `document.tracking.id`, which is derived from the
  product (`VEXSCAN-OCI-INDEX-DOCKER-IO-EXAMPLE-SYNTHETIC`): if the id on the
  hub's document is not the one this run would have generated, nothing is
  written for that product and a `warning:` on stderr says whose advisory it is.
  When the id does match, the version is incremented, a `revision_history` entry
  is appended and `current_release_date` moves — which is what CSAF requires of
  an amended advisory, and is why a re-run that adds nothing writes nothing at
  all rather than bumping a date.
- **A hub points each product at one document, so the two formats do not mix per
  product.** Asking for CSAF where the hub already publishes OpenVEX for that
  product leaves the OpenVEX file alone and prints a `warning:` naming the flag
  that would have worked, rather than writing a second document the hub's
  `index.json` never points at. Products the hub has not seen before are filed
  in whichever format you asked for, so a hub can hold both — just not two for
  the same product.

`contrib/vexhub-pr.sh` takes the same three settings as `--format`,
`--publisher-namespace` and `--publisher-category`, and stops with an error if
every document it had statements for was left untouched.

