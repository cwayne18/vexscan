---
sidebar_position: 5
title: "JSON, SARIF, and gating"
---


The JSON is `schema_version: 2`:

```jsonc
{
  "schema_version": 2,
  "target": "...", "mode": "image",          // or "rootfs", or "repo"
  "findings": [ /* flat, sorted — jq '.findings[]' still works */ ],
  // every finding carries "fixed_version", always present: "" is the "no patch
  // has shipped" answer, so omitting it would hide the thing worth acting on
  // "fixed_versions" joins it only when the advisory patched several branches,
  // listing all of them so a consumer can pick differently than the report did

  "ecosystems": [ { "id": "os", "components": 65, "error": "" } ],
  "unreadable": { "count": 3, "paths": ["/opt/vendor"] },  // omitted when nothing was skipped
  "vex_hubs": [ { "url": "...", "author": "...", "products": 1082, "matched": 3 } ],  // only with --vexhub
  "distro_feeds": [ { "name": "SUSE Security Team", "matched": 4, "cleared": 4 } ],  // SUSE by default on a SUSE image; other feeds with --distro-feeds
  "triage": {  // only with --triage
    "epss_date": "2026-08-04", "kev_date": "2026.08.04",  // the feeds' own dates, not today's
    "epss_stale": true, "kev_stale": true,   // a cached copy was used; omitted when false
    "epss_error": "...", "kev_error": "...", // a feed failed; set instead of failing the run
    "not_in_feed": 16, "no_cve": 3,          // unscored, and why; each omitted when zero
    "catalog_size": 1660,                    // how many CVEs the KEV catalog held
    "scored": 145, "known_exploited": 0      // always present: "0 known exploited" is a finding.
                                             // counts every finding, not just the affected ones
  },
  "withheld": {  // only when --severity hid something; findings[] is already the kept set
    "severities": ["CRITICAL", "HIGH"],
    "count": 123,
    "by_severity": { "UNKNOWN": 36, "MEDIUM": 78, "LOW": 9 }
  },
  "corrections": {  // only when an advisory's own ranges excluded the version it was matched against
    "count": 25,
    "advisories": ["GO-2024-2535", "GO-2024-2537"],
    "details": ["GO-2024-2535 does not apply to github.com/rancher/rancher@v2.15.0 (the record's own ranges are 2.6.0-2.6.14, 2.7.0-2.7.10, 2.8.0-2.8.2)"]
  },
  "descriptor": {  // what produced this report
    "tool": "vexscan", "version": "v0.6.2",
    "started": "2026-08-05T22:56:50Z", "duration": "4.3s",
    "advisory_source": "https://api.osv.dev/v1",
    "advisories_as_of": "2026-08-05T22:56:54Z"  // zero when nothing was resolved
  }
}
```

`descriptor` is there because a report outlives the run that made it. An empty
report raises two questions — which build wrote it, and how old the advisories
behind it are — and neither is answerable from `findings`. `advisories_as_of`
is when OSV actually answered, so a report saved six months ago says so rather
than reading as current. The text output carries the same facts on one
`scanned by:` line under the header.

Adding it did not bump `schema_version`: the field is additive and omitted when
empty, so a consumer pinned to 2 is unaffected.

Each finding carries ecosystem-neutral identity (`ecosystem`, `id`, `package`,
`version`, `location`, `purl`) plus `status`, `method`, `justification` and
`evidence`, and `severity`/`cvss` when an advisory was resolved for it. Both are
omitted when none was, which is not the same fact as `UNKNOWN`. With
[`--vexhub`](./vex-sources.md) a finding also carries `product` (the artifact
it was found in) and, when one matched, `vex` — the statement's `status`,
`justification`, `impact_statement`, `action_statement`, `author`, the product
purl that matched and the hub it came from, so a consumer can audit the claim
without re-fetching. With [`--triage`](./severity-and-filtering.md#prioritising-by-exploitation-evidence---triage)
it carries `priority`: `{"cve": "...", "scored": true, "epss": 0.03249,
"percentile": 0.871}` plus `kev` when it is listed. `scored: false` means the
lookup ran and found nothing, which is not a score of zero; the block is absent
entirely when the flag was off. The v1 Go
spellings (`cve`, `module`, `binary`, `go_id`, `packages`,
`granularity`, `stripped`) are still emitted for Go findings, mirrored from the
neutral fields so they cannot drift.

| Status | Meaning | VEX justification |
|---|---|---|
| `not_present` | vulnerable code is not in the artifact | `vulnerable_code_not_present` or `component_not_present` |
| `not_in_execute_path` | present but nothing can reach it | `vulnerable_code_not_in_execute_path` |
| `linked` | genuinely present, or nothing could rule it out | *(none — treat as affected)* |
| `reachable` | vulnerable symbol is called (Go repo mode) | *(none — treat as affected)* |
| `undetermined` | nothing could be concluded | *(manual review)* |

`component_not_present` is expressed through `justification` rather than a sixth
status, because VEX consumers already read that field.

#### An HTML dashboard (`contrib/vexscan-dashboard.py`)

The text report is written for the person who ran the scan. `contrib/vexscan-dashboard.py`
is for the other audience — the one handed a link:

```sh
vexscan --image myorg/app:latest --all --triage --format json > scan.json
contrib/vexscan-dashboard.py scan.json -o scan.html
```

That is one self-contained file. No CDN, no web font, no JavaScript from
anywhere else, no network access when it is generated and none when it is read,
so it opens the same from a `file://` URL, a CI artifact store or GitHub Pages.
It is Python 3.8+ and the standard library; nothing to install.

A [batch report](../guides/fleet.md) renders as a directory
instead — an index of the fleet, worst image first, and one page per target:

```sh
vexscan --images-from fleet.txt --all --triage --format json > fleet.json
contrib/vexscan-dashboard.py fleet.json -o site/
```

The mode is read from the JSON, not from a flag.

**It is a renderer, not a second opinion.** Every number on the page is read out
of the report; nothing is re-derived. The four sections, their order, which
columns each one shows and how the rows within it sort are all the same rules
[the text report](./reports.md#the-text-report) uses, because a dashboard that disagreed with
the terminal about how many findings are AFFECTED would be worse than no
dashboard at all. Concretely, on a `rancher/hardened-kubernetes` scan where
[`--format summary`](./reports.md) counts 32 affected, 56 vexed and 26 ruled
out, and reads `affected by severity: 10 high, 12 unknown, 10 medium`, the page
says the same.

That is also why the `EPSS` column shows the **percentile** — the same figure
`--format text` puts under the same heading. The probability itself is on the
badge's tooltip and in the expanded row, spelled `4.7% percentile (epss 0.00214)`
exactly as `--details` spells it. Two columns named EPSS showing different
numbers is the mistake this avoids.

Each row expands to the `--details` view: the evidence, the matched VEX
statement with its author, impact and action text, the purl, the binary, the
other branches a fix landed in. A filter box narrows by CVE, package, binary or
justification; sections open while filtering so a match inside a collapsed
RULED OUT is not silently missed. There is a dark theme, following the system
preference unless you override it, and printing the page expands every row.

Below the findings is the coverage block, which reports the absences as loudly
as the totals: an ecosystem that failed, paths that could not be read, what
`--severity` hid, what `--triage`'s feeds could not score and how old they were,
which hubs answered. An incomplete scan says so in a banner above its own counts
— a clean total over a hole in the inventory is the one reading of the page that
would be actively harmful.

Being a contrib script and not a `--format html` is deliberate. The JSON is
already the stable contract, so the renderer can change without touching the
binary; and nine hundred lines of CSS and a theme toggle do not belong in a tool
whose [standard library](../flags.md#standard-library) discipline is the reason it has no
third-party dependencies at all.

### SARIF

`--format sarif` emits SARIF 2.1.0, the format GitHub code scanning and most CI
security dashboards ingest. It exists so a vexscan run can land in the Security
tab beside every other scanner — but carrying the one thing this tool has that a
version scanner does not.

**A ruled-out finding becomes a suppressed result.** `not_present` and
`not_in_execute_path` are emitted as SARIF results with a `suppressions` entry
of `kind: external` whose `justification` is the finding's OpenVEX
justification. A dashboard shows those as dismissed-with-a-reason rather than as
noise a human has to triage again — the same distinction the text report draws
with its `RULED OUT` section, in the vocabulary a dashboard understands.
`linked`, `reachable` and `undetermined` stay open results.

```jsonc
{
  "ruleId": "CVE-2022-27943",
  "level": "warning",
  "message": { "text": "CVE-2022-27943 affects gcc-12 12.2.0-14+deb12u1 (status: not_present, pkgdb-no-code)" },
  "suppressions": [ { "kind": "external", "justification": "vulnerable_code_not_present" } ],
  "properties": { "status": "not_present", "purl": "pkg:deb/debian/gcc-12-base@...", "method": "pkgdb-no-code" }
}
```

Each advisory becomes one `reportingDescriptor` rule, referenced by every result
it produced, so one CVE fanned over three packages is one rule and three
results. The rule carries `security-severity` — the CVSS number GitHub reads to
colour an alert — derived from the finding's vector, or from its severity label
when no vector was published. `level` maps severity to SARIF's `error` /
`warning` / `note`, with an unrated finding warning rather than passing, the same
rule the tool applies everywhere else. Every finding's `purl`, `status`,
`method`, `justification`, EPSS and KEV land in `properties` for a consumer that
wants them. Like `--format json` it is a machine document, so colour is never
written to it.


**An empty report is never silently produced.** If an ecosystem is detected but
cannot be read, no findings are emitted for it, `ecosystems[].error` says why,
the text report prints an `INCOMPLETE:` line, and the process exits 1. The same
applies to a directory the scan could not enter, which is reported under
`unreadable` and exits 1 for the same reason. A CVE id
that matched no component anywhere still appears once, as `undetermined` with
`no_component_matched`, so a missing id never reads as a clean one.

`--format inventory` is a third output: every OS database and language ecosystem
the target carries, each under the directory it was read from, with the file
count and the names OSV will be queried by. It is the fastest way to check that
a reader found what you expected before trusting a finding — or an absent one.

Exit status: `0` the scan completed, `1` the scan failed, an ecosystem could not
be read, or part of the tree could not be read, `2` the command line was wrong,
`3` the scan completed and `--fail-on` matched.

### Gating a pipeline (`--fail-on`)

`--fail-on` is off by default. Given a severity it exits `3` when a finding
meets it:

```sh
vexscan --image myorg/app:latest --all --fail-on high
```

What counts is the part worth having. By default only findings whose vulnerable
code is **present and loadable** are weighed — `linked` or `reachable`, and not
already answered by a VEX statement. So `--fail-on high` here means *a HIGH
whose code the closure actually reached*, not *a HIGH whose version string
appears in a package database*. A passing gate is a statement about the image,
not about a filter. No version-matching scanner can offer that distinction,
because it never computed the closure.

`--fail-on-status` widens it to any comma-separated set of `affected`,
`undetermined`, `vexed`, `cleared`, or `all`:

```sh
# the stricter reading: anything we could not rule out also fails the build
vexscan --image myorg/app:latest --all --fail-on high --fail-on-status affected,undetermined
```

Three properties are deliberate:

- **Exit `3`, never `1`.** Exit `1` means the scan did not complete. A caller
  that cannot tell "found something" from "the package database was
  unreadable" has lost the distinction the tool is built on.
- **A failed scan is not gated at all.** If an ecosystem errored, the run exits
  `1` and says `--fail-on was not evaluated` — a finding count taken from a
  partial scan is not a number to decide a build on.
- **Unrated findings are announced, not dropped.** Severities order the way the
  table orders them, so an unrated finding counts from `MEDIUM` down. Above
  that it cannot be weighed, and the run says how many it could not weigh:

  ```
  note: 46 counted finding(s) have no published severity and could not be weighed against HIGH.
        Use --fail-on any to gate on their presence.
  ```

  This matters most on SUSE, which publishes no CVSS at all. `--fail-on any`
  gates on presence rather than rating.

