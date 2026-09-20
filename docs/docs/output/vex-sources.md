---
sidebar_position: 3
title: "VEX and vendor sources"
---


Some vendors have already triaged the CVEs in their own images and published the
answers. `--vexhub` points at one of those published sets — a
[VEX Repository](https://github.com/aquasecurity/vex-repo-spec), such as
[rancher/vexhub](https://github.com/rancher/vexhub) — and marks the findings a
statement already covers, so attention goes to the rows nobody has spoken to.

```sh
vexscan --image rancher/hardened-kubernetes:v1.34.10-rke2r1-build20260724 --all \
  --vexhub https://github.com/rancher/vexhub
```

```
  affected by severity: 6 high, 26 unknown, 28 medium
  already vexed: 3 by Rancher Security team

AFFECTED (60) - vulnerable code is present and can be loaded
...

ALREADY VEXED (3) - a published statement answers these; vexscan's own verdict is unchanged
SEVERITY  ADVISORY             PACKAGE                            VERSION  VEX STATUS    JUSTIFICATION
HIGH      GHSA-cgrx-mc8f-2prm  github.com/opencontainers/selinux  v1.11.1  not_affected  vulnerable_code_not_in_execute_path
```

**A statement never rewrites `status`.** A `--vexhub` run and a plain run agree
on every finding's verdict and on the JSON's `status` field; the hub changes
only which section the row is printed under, and therefore what the affected
count draws the eye to. `--details` prints the vendor's own sentence, which is
usually the most useful thing in the document:

```
  vendor:   Rancher Security team says not_affected (vulnerable_code_not_in_execute_path)
            Manually confirmed, only exploitable when running runc directly.
            product pkg:golang/k8s.io/kubernetes, published 2026-06-19T00:00:00Z
            matched loosely: statement names pkg:golang/github.com/opencontainers/selinux@v1.11.0; component is pkg:golang/github.com/opencontainers/selinux@v1.11.1
```

Only `not_affected` and `fixed` move a row. A vendor `affected` or
`under_investigation` stays in `AFFECTED` and is annotated there — a vendor
confirming a finding must not make it quieter. The flag is repeatable and the
earliest hub to speak wins, so an internal hub listed first overrides a
vendor's.

**Either serialisation is read.** A hub's documents may be OpenVEX or
[CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) VEX
advisories, and which one is decided from the bytes rather than from the file
name — a hub's `index.json` publishes locations, not a naming convention, so the
name at the end of one is data and not a promise. CSAF's indirection is resolved
on the way in: `product_tree` branches and `full_product_names` are walked down
to the purls in their `product_identification_helper`, and a
`default_component_of` relationship becomes exactly the subcomponent scope
OpenVEX states directly. A CSAF `flags[].label` is the same five-value
vocabulary as an OpenVEX `justification`, byte for byte. Both formats therefore
arrive at the matcher as the same thing, and an `ALREADY VEXED` row looks the
same whichever one the vendor published.

What is looked up: the scanned image (`pkg:oci/…`) and each Go binary's own main
module (`pkg:golang/…`), which is how a hub actually files Go statements. The
hub's `index.json` is fetched once and only the documents for products actually
present in the scan are pulled — the spec's transport is a ~30 MB tarball, and
this reads two files out of it. Three caveats, all measured:

- **Coverage is entirely a function of whether the hub has a document for the
  exact product you scanned.** rancher/vexhub is 1,082 products — Rancher, SUSE,
  Longhorn, NeuVector, StackState — and nothing else. `debian:12 --vexhub
  https://github.com/rancher/vexhub` correctly matches nothing and prints no
  `ALREADY VEXED` section at all.
- **Subcomponents are matched on purl *type and name only*.** Real data leaves
  no choice: the hub writes `pkg:rpm/suse/libgcrypt20` where vexscan emits
  `pkg:rpm/sles/libgcrypt20@…?arch=x86_64`, and statements are pinned to the
  version the vendor scanned (`selinux@v1.11.0`) rather than the one in your
  image (`v1.11.1`). Namespace, version and qualifiers are ignored; every
  disagreement that tolerance swallowed is written out in the evidence line and
  under `--details` as `matched loosely`, so you can see what was actually
  compared. A statement about an older version is applied to a newer one —
  usually right for a "code not reachable" claim, and visible when it is not.
- **The two sides name advisories differently, and the match depends on OSV
  aliases to bridge them.** On the Rancher image above, vexscan's 13 advisories
  are all `GHSA-`/`GO-` ids and the hub's 133 are almost all `CVE-`, with zero
  literal overlap; expanding each finding through the alias list the resolver
  already fetched is what makes any of them meet. A finding whose advisory OSV
  gives no aliases for can only match a hub using the same spelling.

An unreachable hub prints a `NOTE:` and **does not fail the run** — unlike an
ecosystem that could not be read, which exits 1. The asymmetry is deliberate: an
unreadable package database makes the report claim a clean image it never
examined, while an unreachable hub only leaves rows in `AFFECTED` that a vendor
had already answered. The first under-reports, which is the way this tool must
never be wrong; the second over-reports, which is merely tiring.

### Distribution security feeds (`--distro-feeds`)

A VEX hub is a vendor publishing statements about *their own images*. A
distribution publishes the same kind of judgement about *its packages*, in its
own security feed, and `--distro-feeds` reads it the same way — as a second
opinion that can move a row out of `AFFECTED`, never as a verdict that rewrites a
`status`.

The question it answers is the one the reachability closure cannot: whether the
distribution built the vulnerable code into the package at all. Debian routinely
marks a CVE not-affected for a source package because the flaw is in a code path
they do not compile, or fixed it in a point release whose version an upstream OSV
range does not know about. Both are false positives that a version match — and
vexscan's own OSV lookup — still flags.

```sh
vexscan --image debian:12 --all --distro-feeds
```

Today this reads the [Debian security
tracker](https://security-tracker.debian.org/tracker/) for Debian images
(`ID=debian`) and SUSE's CSAF-VEX feed for the SUSE Linux Enterprise family
including BCI (`ID=sles` and kin — see below); Ubuntu, Alpine and Red Hat track
security in separate databases and will be separate feeds. Two verdicts, and only
two, move a row:

- **not-affected** — the tracker's `fixed_version: "0"` for the image's release,
  meaning Debian's build never contained the flaw.
- **already fixed** — a `resolved` advisory whose fix landed at or below the
  installed version, compared with Debian's own version rules
  (`internal/debver`). A fix *newer* than what is installed leaves the finding
  standing.

Everything else — an `open` advisory, an `undetermined` release, a `nodsa` note
(Debian is affected but will not issue an update), or a release the image's
`VERSION_ID` cannot be mapped to a codename — clears nothing. When the release
cannot be named the feed declines rather than guess, because a verdict read off
the wrong release is exactly the kind of wrong answer this tool must not produce.

**It never rewrites `status`,** exactly like `--vexhub`, and it runs *after* it,
so an explicit `--vexhub` statement always outranks the automatic feed. A cleared
row moves to `ALREADY VEXED`, carries `Evidence{Origin: "distro-feed"}`, and
keeps the local verdict it had. An unreachable feed prints a `NOTE:` and does not
fail the run, for the same reason an unreachable hub does not: it can only leave a
false positive sitting in `AFFECTED`, never invent a clean.

The tracker's bulk JSON is large, so the feed is streamed and filtered to the
handful of source packages the scan actually asked about rather than held in
memory whole. If the download is truncated or malformed the whole feed is
rejected — a short read never partially clears findings. It is off by default
because it is a network fetch; `--distro-feeds` turns it on.

**Known limitation: package provenance.** The feed is keyed by the image's
`VERSION_ID` (e.g. Debian 12 → bookworm), so a verdict is read from that
release's column. A package installed from `bookworm-backports`, `testing`, or a
third-party repository is a different build than the one the tracker describes,
so its not-affected or fixed verdict may not apply. This is the same trust model
`--vexhub` already uses — and the same assumption the base OS scan makes, since
the OSV lookup keys off the release too — and because a distro feed never
rewrites `status`, a wrong verdict can only misfile a row into `ALREADY VEXED`
for triage, never publish it as clean. A strict publication path keys off
`status`, not the vexed bucket.

#### SUSE / BCI (CSAF-VEX)

The SUSE Linux Enterprise family — including the SLE BCI base images the RKE2 and
K3s hardened builds sit on — is covered by a second provider that reads [SUSE's
CSAF-VEX feed](https://ftp.suse.com/pub/projects/security/csaf-vex/). It handles
`ID=sles`, `sled`, `sles_sap`, `sle_hpc`, `sle-micro` and `sle-micro-rt`.
(openSUSE Leap and Tumbleweed track separately and are left to a future provider
rather than answered for with enterprise verdicts.)

SUSE publishes **one CSAF document per CVE** at a stable URL, so unlike Debian's
one bulk file this provider fetches exactly the advisories the scan found — the
CVE ids on the findings — and nothing else. A `404` means SUSE has no record for
that CVE, which is a silent decline, not a failure.

The join key is **CPE**, read from the image's own `os-release` `CPE_NAME`
(a BCI base image reports `cpe:/o:suse:sles:15:sp5`). A CSAF document names dozens
of products — Server, Desktop, HPC, the SLE modules, SUSE Micro, several service
packs — whose verdicts differ, and the image's exact CPE selects the one product
whose column applies. This is what keeps a Desktop not-affected off a Server
image. When `os-release` carries no CPE, or the document names no product with
it, the provider declines rather than guess — the same fail-closed rule the
Debian feed uses for an unmappable release. Should one CPE name several products
with conflicting verdicts, an `affected` product wins over a `not-affected` one.

The same two verdicts move a row: **not-affected** (SUSE did not build the
vulnerable code into that binary package) and **already fixed** (a `recommended`
update whose version the installed one has reached, compared with rpm's own
version rules in `internal/rpmver`). A fix *newer* than what is installed, or a
package SUSE lists as plain `known_affected`, leaves the finding standing.
Matching is by **binary** package name only — never the source — because one SUSE
source builds several binaries with opposite verdicts (`libopenssl1_1`
not-affected while `libopenssl1_0_0` is affected by the same CVE), so matching a
source name against a binary list would clear the wrong package. Installed rpm
versions always carry an epoch the CSAF fix omits; the comparison fails closed on
that mismatch so a non-zero epoch can never clear a package whose version is below
the fix.

### Favouring a vendor's own score (`--prefer-vendor`)

By default a finding's rating is the OSV-derived CVSS — usually NVD's or GitHub's.
A distribution often scores the same CVE differently, because the number that
matters to them is how the flaw behaves *in their build*, on their default
configuration. `--prefer-vendor` says: when this vendor has published a score for
a CVE, use theirs.

```sh
# Rate every finding SUSE has scored by SUSE's own CVSS, falling back to OSV
vexscan --image docker.io/rancher/k3s:v1.36.3-k3s1 --all --prefer-vendor suse
```

It is the same idea as
[`rke2-toolbox`](https://github.com/cwayne18/rke2-toolbox), which always favours
SUSE's rating of a CVE and only falls back to another source when SUSE has not
scored it. The flag is **ordered and repeatable** — `--prefer-vendor suse
--prefer-vendor debian` tries SUSE first, then Debian, then the OSV rating — and
a name matches a vendor case-insensitively, so `suse` selects *SUSE Security
Team*.

**It is keyed by CVE, not by package.** A vendor rates a CVE once, and that
rating is as true of a Go module or an npm package that bundles the flaw as of an
OS package — so `--prefer-vendor` rescores findings in **every ecosystem**, not
just the OS layer. It needs no `--distro-feeds`, no `os-release` and no CPE: those
drive the *false-positive clearing* in [`--distro-feeds`](#distribution-security-feeds---distro-feeds),
which is a product-level join; scoring is a plain CVE lookup. (When you do pass
both, the SUSE CSAF documents are downloaded once and shared between the two.)

A finding vexscan reports under a `GO-2026-xxxx` id with no CVE of its own is
still rescored: it is matched through the advisory's alias set — the same record
that gives it a severity — which resolves the Go id to the `CVE-2026-xxxx` the
vendor feed is keyed by. So `GO-2026-1234` picks up SUSE's score for its
underlying CVE without you naming the CVE.

SUSE's CSAF carries a CVSS v3 base score and vector per CVE
(`vulnerabilities[].scores[].cvss_v3`). It is the first — and today only — vendor
vexscan can score; a name it does not recognise (`--prefer-vendor debian`, which
publishes no score) is reported on stderr and ignored rather than silently doing
nothing.

Two properties are worth stating plainly, because this is the **one overlay that
changes a finding's `severity` and `cvss`** where every other second opinion
(`--vexhub`, `--triage`, `--distro-feeds`) is forbidden to:

- **The vendor's score is authoritative — it wins even when it is lower.** If
  SUSE rates a CVE `MEDIUM` that NVD calls `HIGH`, the row becomes `MEDIUM`, and
  `--severity` and `--fail-on` weigh it as `MEDIUM`. That is the point: it lets a
  gate reflect your distribution's assessment rather than the upstream worst case.
  The change is applied **before** the severity filter and the fail gate so both
  see the vendor's number, and every override records an
  `Evidence{Origin: "prefer-vendor"}` line naming the vendor and the rating it
  displaced, so a reader can always see why a row is scored the way it is. When a
  finding relates to several CVEs and the vendor scored more than one, the most
  severe of the vendor's own numbers is used.
- **It can score what OSV left `UNKNOWN`.** SUSE's *OSV export* publishes no CVSS
  at all — the [triage section](./severity-and-filtering.md#prioritising-by-exploitation-evidence---triage) notes every
  SUSE advisory renders `UNKNOWN` there — and govulncheck's OpenVEX carries none
  either, so Go findings in repo mode are `UNKNOWN` too. SUSE's *CSAF* does carry
  a score, so `--prefer-vendor suse` gives a real rating to findings that would
  otherwise have none, which `--severity` can then filter and `--fail-on` gate on.

A finding whose CVE the preferred vendor did not score keeps its OSV rating — the
flag only ever *adds* a vendor's opinion where they have one, and never blanks a
rating on its absence.

