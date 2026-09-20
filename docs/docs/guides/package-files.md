---
sidebar_position: 4
title: "Scanning package files (--rpm)"
---


`--rpm` scans an RPM that was never installed anywhere: a file, a directory of
them, or a URL. It is for the question you have before a package reaches a
machine — *is this build carrying anything?* — and for the case where there is
no machine to point at, such as a mirror you are about to sync or an artifact a
build just produced.

```sh
vexscan --rpm ./openssl-libs-3.5.5-2.el9_8.x86_64.rpm --all
vexscan --rpm https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/o/openssl-libs-3.5.5-2.el9_8.x86_64.rpm --all
vexscan --rpm ./repo/x86_64/ --format inventory
```

The flag is repeatable and mutually exclusive with `--image`, `--rootfs`,
`--repo` and `--sbom`. A directory is walked for `*.rpm`, sorted, so a repeated scan queries
in the same order. The report says `"mode": "rpm"`.

### It reads the header, not the package

An RPM is a 96-byte lead, a signature header, the main header, and then a
compressed cpio payload that is nearly all of the file. Every field `vexscan`
needs is in the main header, and each section states its own length in its first
16 bytes — so the reader knows exactly where the header ends and stops there.
Over HTTP that is a plain `GET` with the body closed early, not a range request,
so it works against mirrors that ignore `Range`. Measured:

| | file | read | |
|---|---|---|---|
| `openssl-libs-3.5.5-2.el9_8.x86_64.rpm` (Rocky 9, over HTTP) | 2.3 MB | 17.5 KB | **0.7%** |
| `libopenssl3-3.1.4-150600.2.19.x86_64.rpm` (SLE 15.6, local) | 1.7 MB | 82.9 KB | 4.6% |
| `python3-jinja2-2.11.3-8.el9_5.noarch.rpm` (Rocky 9, over HTTP) | 227.6 KB | 23.5 KB | 10.3% |

The payload is never decompressed, and there is no xz or zstd dependency: the
file list and `file(1)`'s classification of every entry are both carried in the
header, which is what makes "does this package ship any code at all" answerable
without unpacking anything.

### The source name is why this finds anything

Red Hat and SUSE file advisories under the **source** package, and the binary
package you have is usually named something else. `vexscan` queries both, from
`SOURCERPM` in the header — which on the SLE package above is the difference
between 32 findings and none:

| queried as | ecosystem | findings |
|---|---|---|
| `libopenssl3` (the binary name) | SUSE | 0 |
| `openssl-3` (the source name) | SUSE | 32 |

The distribution comes from the `VENDOR` and `DISTRIBUTION` headers, so no
`/etc/os-release` is needed: `Rocky Linux 9` → `Rocky Linux:9`,
`SUSE Linux Enterprise 15` → `SUSE`, and so on for openSUSE, AlmaLinux,
Alpaquita, openEuler, Mageia, Azure Linux and Red Hat. A distribution OSV does
not carry — Fedora, Oracle Linux, CentOS Stream — is **an error naming
`--osv-ecosystem`**, not a guess at a near neighbour: querying the wrong
ecosystem answers with nothing, which reads exactly like a clean package. Two
distributions in one directory is the same error, for the same reason.

### What it cannot tell you

There is no filesystem, so no `DT_NEEDED` closure can run, so **nothing is ever
`linked` and nothing is ever `not_in_execute_path`**. Every finding for a package
that ships an ELF object is `undetermined`, and the report says so at both ends:

```
NOTE: this read package metadata, not an installed system. No ELF
      reachability test could run -- there is no filesystem to trace.
      32 finding(s) below are undetermined for that reason. For scale: on a
      measured SUSE 15.6 image that test ruled out 1 finding of 47.
```

That last number is the honest measure of what you give up. On
`registry.suse.com/bci/bci-base:15.6` the reachability test ruled out exactly one
finding of 47, and it did so via `pkgdb-no-code` — the one verdict the header can
reach on its own. So a package that ships no ELF object at all is still ruled
out here, on the same evidence an installed scan would have used:

```
RULED OUT (2) - the vulnerable code is not present or cannot run
SEVERITY  ADVISORY         PACKAGE       VERSION          BASIS
CRITICAL  RLSA-2026:25239  openssl-perl  1:3.5.5-2.el9_8  pkgdb-no-code
HIGH      RLSA-2026:22312  openssl-perl  1:3.5.5-2.el9_8  pkgdb-no-code
```

Three further caveats:

- **An `.rpm` is a claim about what *would* be installed.** The file list is what
  the package declares, not what is on a disk somewhere, and nothing here checks
  that any of it was ever unpacked.
- **`updates.suse.com` returns 403 without SCC credentials.** URL input works
  against openSUSE, Rocky, AlmaLinux and Fedora mirrors; SLE-proper packages have
  to be local files.
- **A `.src.rpm` is skipped, with a log line.** It is a build input, not
  something that installs. A directory holding nothing else is an error rather
  than a clean scan.

One package file in a directory that will not parse does not cost you the other
three hundred: it is recorded, named with its reason, and reported the same way
an unreadable directory is — which means the scan **exits 1**.

```
Reading 3 rpm package file(s) from /tmp/rpmdir...
  rpm: 2 packages from /tmp/rpmdir
  ! 1 rpm package file(s) could not be read; the scan does not account for them
    ! /tmp/rpmdir/broken.rpm: not an rpm package file (bad lead magic)
```

### Looking inside the package (`--rpm-deep`)

`--rpm-deep` is the opt-in that trades the header-only read above for one that
decompresses the cpio payload and writes out the ELF objects the header listed.
It exists for exactly one verdict the header cannot reach on its own: when an
advisory names a function and the package's own library is from the right
software but does not export that function, the row can move from `undetermined`
to `not_present` on the `elf-dynsym-absent` test — the same per-object test an
installed scan runs.

```sh
vexscan --rpm https://.../openssl-libs-3.5.5-2.el9_8.x86_64.rpm \
        --rpm-deep --mine-advisories --llm --all
```

Three things are worth being clear about before you reach for it:

- **It needs `--mine-advisories --llm`.** The dynsym test has nothing to look
  for until a symbol is mined from the advisory text; on its own `--rpm-deep`
  extracts objects that no test then consults, and `vexscan` warns as much. With
  no mined symbol every row stays `undetermined`, exactly as without the flag.
- **It downloads the whole package.** The kilobytes-not-megabytes property in the
  table above is a property of the header read; deep mode has to read and
  decompress the payload, so a URL now costs the full file. Decompression is
  pure-Go (gzip, xz, zstd, bzip2), so there is still no `rpm`, `xz` or `zstd`
  binary in the loop.
- **It still cannot run the reachability closure.** There is no entrypoint and no
  sibling packages, so `DT_NEEDED` has nothing to walk: **nothing becomes
  `linked` and nothing becomes `not_in_execute_path`, ever.** Deep mode only ever
  upgrades an `undetermined` row to `not_present`, and only when the function is
  provably absent from the build. A package that *does* export the vulnerable
  function stays `undetermined` — that the code is present is not in question;
  whether it can run is, and no `--rpm` scan can answer it.

