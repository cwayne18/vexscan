---
sidebar_position: 1
title: "Reports and formatting"
---


`--format summary` is the count at the top of the report without the report:
one row per ecosystem, plus a total, so a scan of hundreds of findings fits a
few lines. It carries the number no version scanner can give — `RULED OUT`, the
findings a version match would have raised that the presence test cleared — next
to `AFFECTED`, the ones that need action.

```console
$ vexscan --image debian:12 --all --format summary
vexscan report (image) for debian:12
scanned by: vexscan vX.Y.Z -- advisories from https://api.osv.dev/v1

SUMMARY
ECOSYSTEM       COMPONENTS  AFFECTED  RULED OUT
os (Debian:12)  88          165       7

affected by severity: 10 critical, 26 high, 38 unknown, 82 medium, 9 low
```

`VEXED` and `UNDETERMINED` columns appear only when a scan has any, and an
ecosystem that found no inventory is left out — the same "earns its place" rule
the findings table uses. The buckets are exactly the sections of `--format
text`, counted rather than listed, so the two never disagree. The header and its
`INCOMPLETE` caveats are shared with every other format, so a summary of a scan
that could not read part of the target still says so rather than reading clean.

### The text report

Findings are grouped by what you have to do about them and sorted by severity.
Abridged from `--image debian:12 --all --ecosystem os` (170 lines in full):

```
vexscan report (image) for debian:12

  os       Debian:12                  88 components   159 findings
  affected by severity: 10 critical, 26 high, 34 unknown, 73 medium, 9 low

AFFECTED (152) - vulnerable code is present and can be loaded
SEVERITY  ADVISORY          PACKAGE             VERSION                 BASIS
CRITICAL  CVE-2019-1010022  libc6               2.36-9+deb12u14         elf-needed-closure
MEDIUM    CVE-2022-27943    libgcc-s1           12.2.0-14+deb12u1       elf-needed-closure
MEDIUM    CVE-2022-27943    libstdc++6          12.2.0-14+deb12u1       elf-needed-closure

RULED OUT (7) - the vulnerable code is not present or cannot run
SEVERITY  ADVISORY        PACKAGE         VERSION            BASIS
HIGH      CVE-2025-8941   libpam-runtime  1.5.2-6+deb12u2    pkgdb-no-code
MEDIUM    CVE-2022-27943  gcc-12-base     12.2.0-14+deb12u1  pkgdb-no-code
```

Three sections — `AFFECTED` (`linked`, `reachable`), `UNDETERMINED`, `RULED OUT`
(`not_present`, `not_in_execute_path`) — and an empty one is not printed. Ruled
out is last but still printed in full: it is the tool's proof of work, and the
reason the short list above it is believable. A `VERDICT` column appears only
when a section holds more than one status, so a Debian image (everything
`linked`) does not get a column repeating that 152 times, and a repo scan mixing
`linked` and `reachable` gets one automatically.

A `LOCATION` column appears the same way, and only when a finding names a
specific binary — which today means a Go image scan. One module can be linked
into several binaries in the same image at the same version, so `golang.org/x/net
0.17.0` can be two rows with identical `PACKAGE` and `VERSION` and a different
answer for each binary; `LOCATION` is what tells them apart. An OS scan sets no
binary (the package is the unit), so the column stays absent rather than blank,
and the path is truncated from the left so the basename that identifies the file
survives.

`PACKAGE` is the **installed** package, not the source package the advisory is
filed against. Those differ constantly and the difference is load-bearing:
`CVE-2022-27943` is filed against Debian's `gcc-12` source, which ships as
`gcc-12-base` (no ELF object, so ruled out), `libgcc-s1` and `libstdc++6` (both
linked). Printing the source name would show the same row three times with two
contradictory verdicts. The source package is shown under `--details`, where it
differs.

`BASIS` is `method` verbatim rather than a sentence, because one method means
different things under different statuses (`elf-needed-closure` covers
not-in-path, linked-with-taint and linked-and-loaded) and prose per row would
drift from what the method asserts. `ADVISORY` drops a distro prefix only when a
well-formed CVE id remains, so `DEBIAN-CVE-2022-27943` prints as
`CVE-2022-27943` and a `DSA-5678-1` is left alone; the full OSV id stays in the
JSON and in `--details`.

`--details` prints the full evidence block under each row — every field above
plus `purl`, `evidence` and the plugin's own characterization of the
reachability. That is the pre-table output, and it is verbose on purpose: the
same scan is 3,990 lines.

### Remediation: `FIXED IN` and `--format fixplan`

When a scan runs against an image that is behind on patches, two more things
appear. A `FIXED IN` column, and a line in the summary that says how much of the
report is actionable:

```
  292 affected: 162 unique advisories, 138 fixable, 154 with no fix yet

AFFECTED (292) - vulnerable code is present and can be loaded
SEVERITY  ADVISORY          PACKAGE      VERSION          FIXED IN            BASIS
CRITICAL  CVE-2026-33845    libgnutls30  3.7.9-2          3.7.9-2+deb12u7     elf-needed-closure
HIGH      CVE-2023-4911     libc6        2.36-9+deb12u1   2.36-9+deb12u3      elf-needed-closure
CRITICAL  CVE-2019-1010022  libc6        2.36-9+deb12u1   no fix              elf-needed-closure
```

The target version is read from the OSV record's `fixed` range, scoped to the
release the scan is for — a bookworm scan reports the bookworm fix, never the
`sid` one. `FIXED IN` earns its place like every other optional column: it
appears only when a section holds at least one row with a published fix, so a
fully-patched image or an ecosystem that ships no fixed versions gets no column
of blanks. `no fix` and an empty cell are kept distinct on purpose: `no fix` is
data (the advisory is acknowledged and no patch has shipped), while a blank
would read as missing data — and for the same reason `fixed_version` is one of
the few JSON fields with no `omitempty`. The summary's `N fixable, M with no fix
yet` clause is printed even when nothing is fixable, where it reads `154 with no
fix yet`: a fully-patched image is the case a reader most wants confirmed, and
silence in a summary reads as a missing measurement rather than a measured zero.
It never phrases it as `0 fixable`.

One advisory often publishes more than one fix. A vendor maintaining several
branches patches them all: `GO-2022-0623` fixed Vault in `1.5.9`, `1.6.5` **and**
`1.7.2`, and 22 of the 110 records for that module read the same way. Those are
alternatives, not a progression, so the target depends on the branch you are on
— for a `1.5.4` install the answer is `1.5.9`, and naming `1.7.2` would prescribe
two major versions of unrelated change to close one advisory. vexscan keeps every
published fix, picks the lowest one that is actually an upgrade, and shows the
rest under `--details`:

```
  fixed in: 1.5.9 (also fixed in 1.6.5, 1.7.2)
```

Picking needs a version order, and where the tool has none it keeps the newest
fix — the behaviour it had before it kept the list — and still discloses the
alternatives, so an overshoot is visible rather than silent. The ordered
ecosystems are Debian and Ubuntu (dpkg's own algorithm, `internal/debver`) and Go
and npm (semver, which both databases publish by definition). PyPI is
deliberately absent: PEP 440 sorts `1.0rc1` before `1.0` and semver sorts it
after, so ordering Python fixes with semver would silently invert the pair. So
are the RPM distros, because `rpmvercmp` is not dpkg's `verrevcmp` however
similar they look. The asymmetry is the reason for the caution — too high a
target is a bigger upgrade than necessary, while too low is a version that does
not contain the fix, reported as the version that does. Distro records are
single-branch, so on Debian and Ubuntu this almost never comes up.

`--format fixplan` reorganizes the same affected findings by the action that
clears them. Instead of one row per advisory, it is one row per **upgrade** —
the package, the version to move to, and how many advisories that single upgrade
clears:

```
$ vexscan --image debian:bookworm-20230919 --all --ecosystem os --format fixplan
vexscan report (image) for debian:bookworm-20230919

  138 of 292 affected findings have a fix.
  upgrading 28 packages clears 86 advisories; 154 findings have no fix yet.

UPGRADE (28) - apply these to clear the fixable findings
PACKAGE       CURRENT           FIXED IN            CLEARS  SEVERITY
libgnutls30   3.7.9-2           3.7.9-2+deb12u7     27      CRITICAL
libc6         2.36-9+deb12u1    2.36-9+deb12u14     24      HIGH
libsystemd0   252.12-1~deb12u1  252.39-1~deb12u2    9       HIGH
...

NO FIX YET (154) - affected, but no patch has shipped
SEVERITY  ADVISORY          PACKAGE   VERSION
CRITICAL  CVE-2019-1010022  libc6     2.36-9+deb12u1
...
```

A package with a dozen advisories, each fixed in a different point release,
becomes one row whose target is the **newest** of those versions, because a
distro point release is cumulative: installing the latest clears every earlier
one. That collapse needs to order versions, which the rest of the tool never
does (whether a package is affected is OSV's answer, made server-side), so it is
scoped to the ecosystems whose versions it can order with confidence — Debian
and Ubuntu, using dpkg's own algorithm. For any other ecosystem it will not
guess an order (a semver pre-release sorts the opposite way to a Debian
revision), and findings stay split by their published fixed version rather than
risk naming the wrong target as newest. It is a view, not a filter: every
affected finding with no fix is still listed under `NO FIX YET`, because a
remediation plan that quietly dropped the un-fixable rows would read as
complete when it is not. The rows it genuinely has nothing to plan for — the
ones a vendor VEX statement already answered, and the undetermined ones — are
counted in the summary rather than left out of the arithmetic.

The rows are sorted worst-first — known-exploited, then severity, then the
upgrades that clear the most — so the first line is the one to do first.


### Reading a long report

`debian:12 --all --ecosystem os` is 172 lines, 154 of which are the `AFFECTED`
table. That is not padding to trim — it is what the image installs — so two
things make it navigable instead.

**A report longer than one screen is paged**, through `$VEXSCAN_PAGER`,
`$PAGER`, or `less` if neither is set. This happens only when stdout is a
terminal: piped, redirected, or written with `--out` it never pages, and the
bytes are identical either way. A bare `less` is given `LESS=FRX` (unless you
have your own `LESS`), so a short report does not trap you in a pager and the
text stays on screen after you quit.

```sh
vexscan --image debian:12 --all --no-pager   # not this run
VEXSCAN_PAGER= vexscan --image debian:12 --all   # not ever
VEXSCAN_PAGER='less -S' vexscan --image debian:12 --all   # chop long lines
```

If the pager cannot be started, the report is printed normally and a warning
goes to stderr. A scan that took forty seconds should not end in a blank
terminal because a dotfile names a pager that is no longer installed.

**A long report repeats its summary at the bottom**, along with anything that
changes how it should be read:

```
NOTE: --severity CRITICAL,HIGH withheld 123 of 161 findings:
      36 unknown (no rating was published), 78 medium, 9 low
  os       Debian:12                  88 components    38 findings
  affected by severity: 10 critical, 26 high
  38 findings in 2 section(s): AFFECTED (36), RULED OUT (2)
```

That matters most for the `INCOMPLETE:` banners. They are printed first
precisely so they cannot be missed, but 154 rows will push anything off a
terminal, and a CI log, a `--out` file and a gist are all read from the end. The
threshold is 30 lines of report — counted from the report, never from the
terminal, so the same scan produces the same bytes wherever it goes.

### Colour (`--color`)

The `SEVERITY` column, the verdicts, the section headings and the
`INCOMPLETE:` / `NOTE:` prefixes are coloured, using the eight basic ANSI
colours and bold. Nothing else, and nothing at all in 256-colour: a grey that
reads well on one terminal theme is invisible on another, and the eight are the
ones every theme remaps to something legible.

**Nothing is said in colour alone.** Every severity and every verdict is
spelled out in the cell beside it — the colour makes the worst rows findable in
a 300-row table and carries no information of its own. Stripping the escapes
from a coloured report reproduces the uncoloured one byte for byte, which is
asserted by a test rather than intended:

```sh
diff <(vexscan --image debian:12 --all --no-pager --color never) \
     <(vexscan --image debian:12 --all --no-pager --color always | sed 's/\x1b\[[0-9;]*m//g')
```

`auto` (the default) colours only when **all** of these hold: stdout is a
terminal, `NO_COLOR` is unset or empty, `--out` was not given, `--gist` was not
given, and the format is not `json`. The last three are not politeness — the
same rendered string is what gets written to the file and uploaded to the gist,
so an escape sequence reaching either is stored permanently in a document that
will be read by something that does not interpret it.

`--color always` overrides all of that except JSON, which is what you want when
piping to `less -R`. It does not override JSON because escapes there would make
the output unparseable, which is past the line between looking wrong and being
wrong.

```sh
vexscan --image debian:12 --all --color always | less -R
NO_COLOR=1 vexscan --image debian:12 --all         # off, whatever the value
```

