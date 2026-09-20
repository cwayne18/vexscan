---
sidebar_position: 10
title: "Where the advisories come from"
---


Advisories come from `api.osv.dev` unless you say otherwise. Two flags say
otherwise, and they differ in **who decides which advisories apply**, not just
in where the bytes come from. Pass one or the other, never both.

```sh
# A different server that speaks the OSV v1 API
vexscan --image myorg/app:latest --all --osv-url http://osv-proxy.corp:8000

# No server at all: OSV's published data export, on disk
gsutil -m rsync -r gs://osv-vulnerabilities /srv/osv
vexscan --image myorg/app:latest --all --osv-dir /srv/osv
```

### `--osv-url` — a different server, the same answers

Still a v1 OSV API: a caching proxy in front of osv.dev, or a mirror serving
your own feed. osv.dev — or whatever stands in for it — still does the version
matching, so the verdicts are the ones you would have got anyway. Use it to cut
egress, to survive an osv.dev outage, or to pin a scan to a vendor's advisory
set.

### `--osv-dir` — no network, and the matching moves here

Reads [OSV's published data export](https://google.github.io/osv.dev/data/#data-dumps)
— the same records the API serves — from a directory or an `all.zip`, which
makes it the flag for an air-gapped host. Either layout works, and a directory
of per-ecosystem zips is read without unpacking:

```
/srv/osv/Debian/DEBIAN-CVE-2024-0001.json    # rsynced tree
/srv/osv/Debian/all.zip                      # or the per-ecosystem zip
/srv/osv/all.zip                             # or one zip of everything
```

**The one thing that actually moves is version matching.** Against the API,
whether `libssl3 3.0.11-1~deb12u2` falls inside an advisory's range is
osv.dev's answer. Against an export there is nobody to ask, so that arithmetic
happens on this machine, against the ordering each ecosystem really uses:

| Ecosystem | Ordering |
|---|---|
| Debian, Ubuntu | `dpkg`'s `verrevcmp` (`internal/debver`) |
| Red Hat, SUSE, Rocky, Alma, Oracle, Photon, Mageia, openEuler, openSUSE | `rpmvercmp` (`internal/rpmver`) |
| Alpine, Wolfi, Chainguard, Alpaquita, MinimOS | apk (`internal/apkver`) |
| Go, npm, crates.io, Hex, Pub, GitHub Actions | semver |
| PyPI | PEP 440 (`internal/pep440`) |
| Maven | Maven's `ComparableVersion` (`internal/mavenver`) |

Every ecosystem `vexscan` has a scanner for is in that table, so in normal use
nothing is left unordered. An SBOM or an `--osv-ecosystem` override can still
name one that is not — RubyGems, NuGet, Packagist, CRAN — and **where no
comparator can order an ecosystem the advisory is kept, not dropped**, and the
report says how many and which:

```
NOTE: advisories were matched from a local OSV export, not by the OSV API, so
      the installed-version check was done here. Where it could not be done the
      advisory was kept rather than dropped:
      3 advisory match(es) for RubyGems were kept without checking the installed
      version: matching offline errs toward reporting. For example GHSA-gems-0001.
```

Over-matching costs a reader a dismissal; under-matching costs them the
vulnerability. That is the direction the whole offline path is bent in, and the
note is what keeps the result checkable — a scan that quietly widened its
matches is not one you can act on.

The gap is narrower than the list of ecosystems looks, because those databases
usually publish an explicit `versions[]` enumeration next to the range, and an
enumeration needs no comparator at all.

### One difference from the API, handled for you

The export ships **withdrawn** records — advisories the publisher retracted —
and the API silently does not. `vexscan` drops them at load, which is what
makes the two sources agree; the count is logged. On a stock `debian:12.0`
that was ten rows the API would never have shown you.

Measured both ways on the same images, the reports are byte-identical apart
from the provenance line, which names its source either way:

```
scanned by: vexscan v0.9.1 -- 2026-08-08 00:48 UTC, 19.4s -- advisories from local OSV export /srv/osv
```

The full export is around 2 GB and covers every ecosystem; a single ecosystem
is far smaller (`gsutil -m rsync -r gs://osv-vulnerabilities/Debian /srv/osv/Debian`).

Both flags read an environment variable too — `VEXSCAN_OSV_URL` and
`VEXSCAN_OSV_DIR` — so a build host can be pointed at its mirror once rather
than on every invocation. The flag wins when both are set.

