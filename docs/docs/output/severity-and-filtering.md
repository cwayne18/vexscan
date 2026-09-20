---
sidebar_position: 2
title: "Severity and filtering"
---


`SEVERITY` is scored from the CVSS vector OSV already returns with each
advisory, so it costs no extra requests. Where a publisher also states a label
(GitHub does, as `MODERATE`/`HIGH`/…), the **more severe** of the two is used —
measured over 442 GHSA records the vector is milder than GitHub's own label 27
times and harsher 20 times, so neither source can be trusted to be the ceiling.
Erring upward costs a reader time on a finding milder than billed; erring
downward costs them the finding.

`UNKNOWN` sorts above `MEDIUM`, deliberately. A severity nobody published is not
evidence that the problem is small, and in a report several hundred rows long
anything sorted to the bottom stops being read.

Two things report `UNKNOWN` that are worth knowing about:

- **CVSS 4.0-only records are not scored.** A v4 base score is a 270-entry
  MacroVector lookup with interpolation, not a formula. Records carrying only a
  v4 vector report `UNKNOWN` rather than a number this tool made up. Most
  advisories still publish v3 alongside; on `debian:12` 36 of 161 findings are
  unrated, from a mix of v4-only and pre-CVSS records.
- **`--repo` Go findings carry no severity at all.** That path resolves
  advisories inside govulncheck, which is run with `-format openvex`, and OpenVEX
  carries no severity field. Image mode goes entirely through the resolver and is
  fully covered — on `debian:12 --all` every finding gets a rating.

### Filtering by severity (`--severity`)

`--severity CRITICAL,HIGH` reports only the findings at those ratings. It is
comma-separated or repeatable, case-insensitive, accepts `MODERATE` for
`MEDIUM`, and a name it does not recognize is a command-line error (exit 2)
rather than a silently empty report.

```console
$ vexscan --image debian:12 --all --ecosystem os --severity CRITICAL,HIGH
vexscan report (image) for debian:12
NOTE: --severity CRITICAL,HIGH withheld 123 of 161 findings:
      36 unknown (no rating was published), 78 medium, 9 low

  os       Debian:12                  88 components    38 findings
  affected by severity: 10 critical, 26 high
```

The filter is applied to the result, not to the rendering, so `--format json`
shrinks the same way and gains a `withheld` block that matches the banner
exactly. It also runs before the LLM overlay, so `--severity CRITICAL --llm`
only pays for criticals.

Three things about it are worth knowing before you put it in CI:

- **`UNKNOWN` is a severity you have to ask for.** As in Trivy, a `--severity`
  that does not name it drops it — 36 findings on `debian:12` above. Those are
  unrated, not unimportant ([above](./severity-and-filtering)), so every filtered run prints
  what it withheld and glosses the unrated count. Name `UNKNOWN` alongside the
  ratings you want to keep them.
- **`--repo` mode has no severities at all**, for the reason in the previous
  section, so any `--severity` that omits `UNKNOWN` filters out *everything*.
  That does not print as a clean scan:

  ```console
  $ vexscan --repo https://github.com/cwayne18/vexscan --all --severity HIGH,CRITICAL
  No findings at these severities.
  --severity HIGH,CRITICAL withheld all 1 finding(s): 1 unknown (no rating was published).
  This is a filtered view, not a clean result.
  ```

- **A `--cves` id that matched nothing is never filtered.** Those rows exist so
  that an id you named by hand cannot vanish from the report; they carry no
  severity, and hiding them would recreate exactly the silence they are there to
  prevent.

Exit codes are unchanged: `0` the scan completed, `1` it could not read
something, `2` the command line was wrong. Findings existing — at any severity —
is not a failure, which is what keeps exit `1` worth acting on.

### Filtering to what you can fix (`--fixed-only`)

`--fixed-only` keeps the findings some published version closes, and drops the
ones nothing can be done about yet. It is the answer to "just show me the work",
and it is Trivy's `--ignore-unfixed` under a name that says what survives rather
than what disappears.

```console
$ vexscan --image registry.rancher.com/rancher/nginx-ingress-controller:v1.15.1-prime11 --all --fixed-only
NOTE: --fixed-only withheld 2 of 10 findings no fix has been published for:
      2 unknown (no rating was published)
      2 of those are AFFECTED: vulnerable, with no fix to upgrade to.

  affected by severity: 7 unknown
  7 affected: 7 fixable, 0 with no fix yet
```

The third line of that banner is the point. The first two read like a filter
tidying up, and the rows behind them are not untidy: they are open, they apply
to this image, and the only reason they are gone is that nobody has shipped a
version to move to. Hiding them is a reasonable thing to want from a sprint
board and a dangerous thing to do to a security report, so the count comes with
every run and `--format json` gains a `withheld_unfixed` block carrying the same
three numbers.

- **It asks about the fix, not about you.** A `RULED OUT` finding with a fix
  stays; an `AFFECTED` finding without one goes. Those are separate axes, and
  collapsing them would make the flag mean something no reader of
  `--ignore-unfixed` expects.
- **It composes with `--severity`, and each says what it hid.** `--severity`
  runs first over everything, `--fixed-only` over what survived, so the two
  banners are two stages rather than two views of one number. If between them
  they empty the report, both lines still print, because a reader dropping one
  of the two flags needs to know which one was hiding what.
- **A `--cves` id that matched nothing is never filtered**, for the same reason
  `--severity` never filters it: those rows exist so an id you named by hand
  cannot vanish, and they have no fix to publish.

It runs after the fix versions are resolved — it has to, since that is what
decides which rows have one — but before the VEX, distro-feed, triage and LLM
overlays, so `--fixed-only --llm` only pays for the rows you will read.

### Prioritising by exploitation evidence (`--triage`)

Severity says how bad a vulnerability would be if exploited. It says nothing
about whether anyone is exploiting it. `--triage` adds the second question, from
two public feeds: [EPSS](https://www.first.org/epss/), a daily per-CVE forecast
of exploitation activity, and
[CISA's known-exploited catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
a list of what is being exploited in the wild right now.

```console
$ vexscan --image debian:12 --all --ecosystem os --triage
vexscan report (image) for debian:12
NOTE: --triage could not score 16 of 161 findings, so they sort last for lack of data rather than lack of risk:
      16 have a CVE the feed has not scored yet, which usually means it was published in the last day or two

  os       Debian:12                  88 components   161 findings
  affected by severity: 10 critical, 26 high, 34 unknown, 75 medium, 9 low
  priority: none in CISA's known-exploited catalog, 3 at or above the 90th EPSS percentile, 138 scored, 16 unscored
  priority data: EPSS 2026-08-04, KEV catalog 2026.08.04

AFFECTED (154) - vulnerable code is present and can be loaded
SEVERITY  ADVISORY          PACKAGE       VERSION                 EPSS   BASIS
UNKNOWN   CVE-2011-3389     libgnutls30   3.7.9-2+deb12u7         99.4%  elf-needed-closure
HIGH      CVE-2018-20796    libc-bin      2.36-9+deb12u14         92.4%  elf-needed-closure
UNKNOWN   CVE-2005-2541     tar           1.34+dfsg-1.2+deb12u1   89.5%  elf-needed-closure
CRITICAL  CVE-2019-1010022  libc-bin      2.36-9+deb12u14         87.1%  elf-needed-closure
```

That reordering is the point, and it is large. The likeliest-to-be-exploited
finding in `debian:12` is **unrated**, so a `--severity CRITICAL,HIGH` run throws
it away. Six of the image's eight CRITICALs sit between the 28th and 40th
percentile — below the median:

| CVE | Severity | EPSS percentile |
|---|---|---|
| CVE-2019-1010022 | CRITICAL | 87th |
| CVE-2023-45853 | CRITICAL | 86th |
| CVE-2026-5450 | CRITICAL | 40th |
| CVE-2026-8376 | CRITICAL | 36th |
| CVE-2026-13221 | CRITICAL | 35th |
| CVE-2026-42496 | CRITICAL | 35th |
| CVE-2026-12087 | CRITICAL | 30th |
| CVE-2026-57433 | CRITICAL | 28th |

**Nothing is hidden and nothing is rewritten.** The flag adds two columns and
changes the order: known-exploited rows first, then by EPSS percentile
descending, then everything unscored in the severity order it had before. No
status changes and no severity changes — whether a vulnerability is being
exploited on someone else's network says nothing about whether the code is
present in this image, which is the only question this tool answers. Use
[`--severity`](#filtering-by-severity---severity) if you want fewer rows;
`--triage` only decides which of them you read first.

**There is no blended score.** vexscan will not emit a
`priority = f(cvss, epss, kev)` number, because the two inputs measure different
things and any weighting would be this tool's opinion dressed as arithmetic. It
shows the facts and orders by them.

The `EPSS` column is the **percentile**, not the raw probability: `0.03` reads as
negligible until you know it is the 87th percentile of all 355,094 scored CVEs.
`--details` prints both, along with the id the score was looked up under:

```
  epss:     0.03249 (87.1th percentile), as CVE-2019-1010022
```

Six things are worth knowing before you rely on it:

- **A distro advisory is a bundle, and it is scored at its worst member.**
  `SUSE-SU-2026:0312-1` fixes eight CVEs and `RHSA-2024:2447` seven; one Red Hat
  advisory on `ubi9` fixes thirty-two. The row takes the highest EPSS percentile
  and any KEV hit across the whole set, because the package is as exposed as the
  most-exploited thing the patch addresses — averaging would let seven quiet
  CVEs bury one being exploited today. `--details` names every CVE and says
  which one the score came from:

  ```
  fixes:    CVE-2025-15467, CVE-2025-68160, CVE-2025-69418, CVE-2025-69419, CVE-2025-69420 (+3 more)
  epss:     98.7% percentile (epss 0.47621) for CVE-2025-15467, highest of 8
  ```

  This matters most on SUSE, which publishes **no CVSS at all** — all 46
  advisories on `bci/bci-base:15.6` render UNKNOWN, so EPSS is the only ordering
  signal that distro has. Before v0.5.1 it scored **0 of 47** findings there,
  because SUSE and Red Hat ids name no CVE and carry no aliases; it now scores
  41, and the six at or above the 90th percentile sort to the top of a table
  that was previously in no meaningful order.

- **Both feeds are keyed by CVE, and many advisories are not.** On the Rancher
  image below, *not one* of 865 findings carries a CVE in any of its own fields —
  they are all `GHSA-` and `GO-` ids. Expanding each through the OSV alias list
  the resolver already fetched is what scores 834 of them anyway; the remaining
  31 have no CVE alias anywhere and can never be scored by either feed. Those are
  counted, named in a `NOTE:`, and sorted last — which in a list ordered by
  likelihood reads as "least likely", so the note says in as many words that they
  sort last for lack of data rather than lack of risk.
- **A CVE published in the last day or two has no score yet.** EPSS lags new
  CVEs by about a day; the 16 unscored findings on `debian:12` above are two such
  ids across eight packages each. This is counted separately from "no CVE at
  all", because the two have different fixes (wait a day; nothing).
- **Absence from the KEV catalog means nothing at all.** It is 1,660 entries
  against EPSS's 355,094, and it fired on **zero** of the 1,026 findings across
  both images here. It is worth carrying because when it does fire it ends the
  argument, but a report with no KEV rows is the normal case and not a clean bill
  of health.
- **A catalog hit is reported even on a row this scan ruled out.** Every other
  number on the `priority:` line counts the affected rows only, because those are
  the work to do — but "is this in the catalog" is a question about the scan, and
  it is answered in two other places (the `--triage` log line, and
  `known_exploited` in the JSON) that count *every* finding. So a hit outside the
  affected rows is still named, and named as being outside them:

  ```console
  $ vexscan --image debian:12 --ecosystem os --cves CVE-2021-3156 --triage
    priority: no affected row is in CISA's known-exploited catalog, but 1 other row is

  UNDETERMINED (1) - not enough evidence to decide either way
  SEVERITY  ADVISORY       PACKAGE  VERSION  EPSS   KEV  BASIS
  UNKNOWN   CVE-2021-3156                    99.9%  yes
  ```

  Before v0.6.1 that line was absent and the summary said nothing, while the log
  said `Triage: 1 finding(s) are in CISA's known-exploited catalog`. Two counts of
  the same scan are allowed to differ; they are not allowed to differ silently.
- **EPSS predicts observed exploitation activity anywhere in the next 30 days**,
  not risk to you. A high percentile on a library your entrypoint never loads is
  still a finding vexscan has already told you is `not_present`.

`--triage` downloads about 4 MB the first time (2.5 MB gzipped EPSS, 1.5 MB KEV)
and takes well under a second. Both are cached under `VEXSCAN_TRIAGE_CACHE`, or
`os.UserCacheDir()/vexscan/triage` by default. EPSS is served under a dated
filename, so a second scan the same day re-downloads nothing at all; KEV is
revalidated with an `ETag` and normally answers `304`. A feed that cannot be
reached falls back to the cached copy, and both the summary and the caveat mark
it `(cached)` with the date it is from — a percentile is a claim about a day, and
a CI log read next month must not be able to pretend otherwise.

An unreachable feed with no cache prints a `NOTE:` and **does not fail the run**,
for the same reason [`--vexhub`](./vex-sources.md) does not: it leaves the rows
in the order they were already in, which over-reports rather than under-reports.
The report says so explicitly, because a table with an empty KEV column must
never be readable as "nothing here is being exploited".

