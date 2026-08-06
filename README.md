# vexscan

`vexscan` answers one question, for a container image, a filesystem tree, a
source repo, or an RPM that was never installed: **is this CVE's vulnerable code
actually present, and can it actually run?**

Scanners flag a CVE whenever a vulnerable *version* is installed. That is the
right default for a scanner and the wrong basis for a triage decision — the
linker may have dead-code-eliminated the vulnerable package, the vulnerable
function may be unreachable, or the shared library may sit on disk with nothing
loading it. `vexscan` distinguishes those cases so you can publish accurate
[VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
statements instead of hand-waving at a scan report.

**Every ecosystem brings its own deterministic presence test.** That is the
governing rule of the tool. An LLM never decides a status; it only comments on
what the deterministic tests could not rule out.

| Ecosystem | Selector | Deterministic test |
|---|---|---|
| Go modules and stdlib | `--package golang:PATH` | pclntab dead-code-elimination evidence; govulncheck call-graph reachability |
| OS packages (deb, rpm, apk) | `--package deb:NAME` etc. | package-database inventory; the dynamic linker's `DT_NEEDED` closure from the entrypoint (or `--roots`) |
| Python (PyPI) | `--package pypi:NAME` | `dist-info`/`RECORD` inventory; a static import closure from the entrypoint (or `--roots`) |
| npm | `--package npm:NAME` | `node_modules` manifest inventory; a static require/import closure from the entrypoint (or `--roots`) |
| Java (Maven) | `--package maven:GROUP:ARTIFACT` | jar/war/ear coordinate inventory; class presence in the archive's central directory |

Python and npm answer a **narrower** question than Go does, and the tool is
built to say so rather than to guess. Neither language removes dead code at
build time, so `not_present` can only mean "not installed"; reachability is the
one remaining lever, and it is blocked far more often than the `DT_NEEDED`
closure is. Read [Known limits](#known-limits--read-this-before-trusting-a-result)
before trusting a clean answer from either.

Java answers a narrower question again — there is no reference graph, so nothing
here comes from reachability — but its presence test is the only one in the
table that routinely **contradicts** a version scanner. The mitigation Apache
published for Log4Shell was

```sh
zip -d log4j-core.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

and the artifact is still `org.apache.logging.log4j:log4j-core@2.14.1`
afterwards. Listing a zip's central directory settles that; comparing versions
cannot.

`vexscan` was previously released as `gomod-vex`, which did the Go half only.
Existing `--module` command lines and `GOMODVEX_*` environment variables keep
working.

## Quick start

```sh
# Where does this CVE land, anywhere in the image? (searches every ecosystem)
vexscan --image debian:12 --cves CVE-2024-5535

# One Go module in a container image
vexscan --image rancher/hardened-kubernetes:v1.30.1 \
  --package golang:golang.org/x/net --cves CVE-2023-39325,CVE-2023-44487

# One OS package, with the shared-library closure as the presence test
vexscan --image debian:12 --package deb:openssl

# Everything the image installs, OS packages only
vexscan --image registry.access.redhat.com/ubi9/ubi:latest --all --ecosystem os

# One Python distribution, with the import graph as the reachability test
vexscan --image apache/airflow:latest --package pypi:requests

# Every npm package in the image
vexscan --image node:22-slim --all --ecosystem npm

# Every Java artifact in the image, jars nested inside a war or fat jar included
vexscan --image jenkins/jenkins:lts --all --ecosystem maven

# A filesystem tree rather than an image — an unpacked image, a mounted
# volume, a machine's own / (see below: no entrypoint, so pass --roots)
vexscan --rootfs /mnt/rootfs --all --roots /usr/bin/myapp

# An RPM nobody installed — a file, a directory of them, or a URL. Reads only
# the header, so the URL below costs 17 KB of a 2.3 MB package (see below)
vexscan --rpm ./openssl-libs-3.5.5-2.el9_8.x86_64.rpm --all
vexscan --rpm https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/o/openssl-libs-3.5.5-2.el9_8.x86_64.rpm --all

# A CycloneDX bill of materials, from a file or a pipe. Every finding is
# undetermined — a component names a package and nothing else (see below)
vexscan --sbom sbom.cdx.json --all
syft debian:12 -o cyclonedx-json | vexscan --sbom - --all

# Source repo (govulncheck source-mode reachability)
vexscan --repo github.com/rancher/rancher \
  --package golang:golang.org/x/net --cves CVE-2023-39325

# Source repo, lock file inventory (no import graph — see below)
vexscan --repo github.com/npm/cli --all --ecosystem npm

# Just list what is installed, with the names OSV will be queried by
vexscan --image debian:12 --format inventory
vexscan --rootfs /mnt/rootfs --format inventory
vexscan --rpm ./repo/x86_64/ --format inventory
```

## Selecting what to check

A `--package SPEC` is a purl, an `ecosystem:name` shorthand, or a bare name
resolved against whatever inventory contains it:

```
golang:golang.org/x/net    deb:openssl    apk:musl    rpm:glibc    openssl
pypi:PyYAML    npm:@babel/core    maven:org.apache.logging.log4j:log4j-core
org.apache.logging.log4j:log4j-core    log4j-core
pkg:golang/golang.org%2Fx%2Fnet@v0.17.0    pkg:pypi/pyyaml@6.0.3    pkg:npm/%40babel/core@7.24.0
pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
```

`deb`, `dpkg`, `rpm` and `apk` are package *formats* rather than OSV ecosystem
names; they all select the OS plugin, which is the only thing that could answer
them. `go` is accepted for `golang`, `std` for `stdlib`, `python` and `pip` for
`pypi`, `node` and `nodejs` for `npm`, and `java` and `jar` for `maven`.

PyPI names are matched after PEP 503 normalization — lowercased, with runs of
`-`, `_` and `.` collapsed to a single `-` — so `PyYAML` and `pyyaml` select the
same distribution, as do `typing_extensions` and `typing-extensions`. npm names
are matched verbatim, scope included, because that is how the registry and OSV
key them.

A Maven coordinate is itself colon-separated, so
`org.apache.logging.log4j:log4j-core` needs no `maven:` prefix — a prefix with a
dot in it is read as a groupId rather than an ecosystem, since no ecosystem name
contains one. A bare artifactId (`log4j-core`) also selects, which is ambiguous
in principle because two groups can publish the same artifactId, and in practice
resolves into extra findings rather than missing ones.

`--package` is repeatable and accepts comma-separated values, so
`--package a --package b` and `--package a,b` are the same.

Three ways to say what to check, and you need exactly one of them:

| | Meaning |
|---|---|
| `--package SPEC...` | these components, every advisory that applies to them (or just `--cves`) |
| `--cves LIST` alone | resolve these ids against the whole target, wherever they land |
| `--all` | everything each selected ecosystem can enumerate |

`--ecosystem` (repeatable) restricts which plugins run. Naming one that no
plugin provides is an error rather than a silent empty report — as is a
`--package` aimed at an ecosystem that is not selected.

`--cves` matches an id anywhere the advisory is known by it, including as one of
the CVEs a distro advisory says its patch fixes. This matters on SUSE and Red
Hat, where the published id names no CVE at all: `SUSE-SU-2026:0312-1` addresses
eight and `RHSA-2024:2447` seven, and neither carries an alias. Asking for one
of those CVEs finds the advisory that patches it, reported under the id you
asked about, with `--details` listing the rest of the bundle so you can see the
upgrade covers more than you asked for.

> Before v0.5.1 this matched nothing on those distros. `--cves` against a SUSE
> image returned an unmatched-id row for every CVE, which read as "not
> affected". If you scanned SUSE or RHEL by CVE with an earlier release, rerun
> it.

## Scanning a filesystem instead of an image (`--rootfs`)

`--rootfs DIR` runs everything image mode runs, against a tree already on disk:
an unpacked image, a mounted volume or snapshot, a chroot, a machine's own `/`.
No pull, no extraction, no registry credentials.

```sh
vexscan --rootfs /mnt/rootfs --all --ecosystem os
vexscan --rootfs / --package deb:openssl --roots /usr/sbin/nginx
docker export "$(docker create myapp:latest)" | tar -x -C /tmp/rootfs
vexscan --rootfs /tmp/rootfs --all
```

Every ecosystem works: the package databases, the `DT_NEEDED` closure, the
Python and npm import graphs, the jar reader, and the Go binary walk all read
paths, not registries. `--format inventory` works the same way. The report says
`"mode": "rootfs"` and names the directory as its target.

**Nothing is deleted.** The directory you name is yours; only the temporary
directory image mode extracts into is ever removed.

### What it costs: there is no image config

A directory does not carry an Entrypoint, a Cmd, an env or a PATH, and `vexscan`
does not invent one. That is the whole difference between the two modes, and it
lands on the reachability tests:

| Ecosystem | Without a config |
|---|---|
| OS packages | the ELF closure roots **every** program it finds, records the `no-entrypoint` taint, and keeps going — the taint is non-blocking, so `not_in_execute_path` is still reachable, just rarer |
| Python, npm | `no-entrypoint` is a **blocking** taint: no `not_in_execute_path` at all until you supply a root |
| Go, Java | unaffected — neither reads the config |

`--roots` is the remedy, and it is the same flag image mode already uses for an
image whose real command comes from outside its config:

```sh
vexscan --rootfs /mnt/rootfs --all --roots /usr/bin/myapp --roots /usr/bin/worker
```

Name what actually runs. A root that is a wrapper script rather than a real
program makes things *worse*, not better — see the npm measurement below.

### Measured against the same image, both ways

`docker export` of `debian:12` into a directory, scanned with `--rootfs`, versus
`--image debian:12`:

| | packages | findings | `not_present` | `linked` |
|---|---|---|---|---|
| `--image debian:12` | 88 | 159 | 7 | 152 |
| `--rootfs` (exported) | 88 | 159 | 7 | 152 |

The reports are identical except for one string: the ELF closure records its
root reason as `no entrypoint` rather than `shell entrypoint`. Both escalate to
rooting every program, so every conclusion matches. That is a happy case rather
than a general result — `debian:12` ships `bash` as Cmd, which was already
telling the closure nothing.

`node:22-slim`, same comparison, `--ecosystem npm`: 14 findings, all `linked`,
in both modes. The blocking taint differs (`no-entrypoint` versus the image's
`foreign-entrypoint`, since `docker-entrypoint.sh` is not a Node script) and
changes nothing, because both block.

Adding `--roots /usr/local/bin/npm` to the rootfs run narrows the graph from 215
roots to 1 — and still concludes nothing, because npm's launcher has no
`node_modules` beside it, which is its own blocking taint. A root has to be the
real program with its dependencies in place.

### Permissions: a tree you cannot fully read

A rootfs owned by root and scanned by someone else is the common case, and the
one that matters most here. A directory the walk cannot list contributes no
findings — exactly what a directory with nothing wrong in it contributes.

So every path a walk could not enter is recorded, named in both the text report
and the inventory above the results, carried in the JSON as `unreadable`, and
**exits 1**. A scan that could not read the tree never exits 0.

```
INCOMPLETE: 3 path(s) could not be read, so this report does not account for them:
  /opt/vendor
  /srv/data
  /root
```

Run as root, or `sudo`, or fix the modes — but do not read the result as clean
until that line is gone. (Image mode effectively never prints it: extraction
creates every directory `0755`.)

`/proc`, `/sys` and `/dev` are skipped rather than reported. They ship no code,
and `/proc` alone is tens of thousands of synthetic entries that stat as regular
files.

## Scanning package files (`--rpm`)

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

## Scanning a bill of materials (`--sbom`)

`--sbom` scans the components named in a CycloneDX JSON document — the standard
hand-off between a build system and a scanner, and the one input every other
scanner accepts. It is for the case where the SBOM is what you have: a build
published one, a vendor sent one, a policy requires one.

```sh
vexscan --sbom sbom.cdx.json --all
syft debian:12 -o cyclonedx-json | vexscan --sbom - --all
vexscan --sbom sbom.cdx.json --all --ecosystem golang
vexscan --sbom sbom.cdx.json --format inventory
```

`-` reads standard input. The flag is mutually exclusive with `--image`,
`--rootfs`, `--repo` and `--rpm`, and the report says `"mode": "sbom"`.

Components are routed to the plugin that can query them, from the purl type:
`pkg:golang` → Go, `pkg:npm` → npm, `pkg:pypi` → PyPI, `pkg:maven` → Maven, and
`pkg:deb` / `pkg:rpm` / `pkg:apk` → the OS plugin. `--ecosystem` and the
per-ecosystem outcome list behave exactly as they do for an image.

### Read this part before trusting a result

**Every finding is `undetermined`.** Not some — every one. `--rpm` has no
filesystem either, but an rpm header still lists the files the package installs
and `file(1)`'s verdict on each, which is enough to rule out a package that
ships no executable code. A CycloneDX component carries a name, a version and a
purl. There is nothing in it to rule anything out with, so nothing is ruled out:

```
NOTE: this read a bill of materials, not an installed system. No ELF
      reachability test could run -- there is no filesystem to trace -- and a
      CycloneDX component does not list the files it installs, so unlike a
      package file it cannot rule a package out for shipping no code either.
      Every row below is a package the document says is installed, and
      nothing here can say whether its code would ever run.
      89 finding(s) below are undetermined for that reason. Scan the image
      or tree these components came from to get an answer.
```

That note prints at both ends of the report, and it prints on a clean one too:
"no findings" out of a bill of materials is a much weaker statement than the
same words out of an image, and the difference has to be on the page.

So this mode answers *which advisories apply to what this document says is
installed* — the same question a version-matching scanner answers, and nothing
more. Point `vexscan` at the image or the tree when you want the answer only it
can give.

### The source name is why this finds anything

Debian, Alpine and the RPM distributions all file advisories against the
**source** package, and the binary package in the document is usually named
something else. Both producers say so, in different places: syft writes
`upstream=openssl` as a purl qualifier, trivy writes an
`aquasecurity:trivy:SrcName` property. `vexscan` reads both and queries the
binary and source names together. Missing it queries a name OSV has no records
under, which reads exactly like a clean package.

The distribution comes from the `distro=` qualifier — `distro=debian-12`,
and Alpine's bare `distro=3.19.9` resolved through the purl namespace. A
document that states no distribution, or states two, is **an error naming
`--osv-ecosystem`**, on the same reasoning as `--rpm`: an OSV query with no
ecosystem finds nothing and reads like a clean scan.

### Nothing is dropped quietly

A document with 400 components of which 120 were unusable must not print as a
scan of 280. Two things can be wrong with an entry, and they are not the same:

- **Skipped** — it named no package to begin with. The `operating-system` row,
  trivy's `go.mod` marker, a purl type `vexscan` has no ecosystem for, or a
  component with no version to match a range against. Each is logged with its
  reason. These are ordinary, and not a loss.
- **Failed** — it had a package URL and the URL would not parse. That is a
  component that went unexamined, so it lands in `unreadable` alongside a
  directory that could not be read, is named with its reason, and the scan
  **exits 1**.

A document nobody could read at all is an error, never an empty result — and so
is one where every entry resolved and none of them was a package this tool can
query. Scanning clean is the one outcome an empty result may never produce.

Only CycloneDX JSON is read today. An SPDX document is told what it is rather
than scanned as a document with no components in it.

## How the tests work

### Go, image mode

For every Go binary that links the target module:

1. **Resolve the vulnerable packages** from the [OSV](https://osv.dev) Go
   database, keyed by module plus the version embedded in the binary's build
   info (`debug/buildinfo`) — no Trivy report or manual version input needed.
2. **govulncheck (binary mode)**, for non-stripped binaries: linked but
   unreachable is `vulnerable_code_not_in_execute_path`.
3. **pclntab presence test.** A Go binary keeps its function-name table even
   when fully stripped (`-ldflags=-s -w`). If none of a CVE's vulnerable
   packages appear in it, the linker eliminated them:
   `vulnerable_code_not_present`.

With `--all`, the module list comes from each binary's build info — its
dependencies, its own main module, and the toolchain (`stdlib`), since stdlib
advisories apply to every Go binary by definition.

### Go, repo mode

The repo is cloned (shallow) and analyzed with **govulncheck source mode**,
whose call-graph reachability is authoritative for a source tree — strictly
better than the pclntab test, which only exists because shipped binaries are
stripped. Each advisory is classified `reachable` (the vulnerable symbol is
actually called), `not_in_execute_path` (imported but unreachable), or
`not_present` (unused). A local checkout path or `file://` URL is scanned in
place without cloning.

> **Large repos:** source-mode analysis builds a whole-program call graph and
> can need several GB of RAM. Very large repos (e.g. `rancher/rancher`) may
> exhaust memory — govulncheck gets OOM-killed (`signal: killed`). Give the
> process more memory (in a container, e.g. `docker run --memory=8g`), scope the
> scan with `--repo-path <subdir>`, or fall back to `--image` mode.

### OS packages

The package database is read in-process — `/var/lib/dpkg/status`,
`/lib/apk/db/installed`, or the rpm database (sqlite, BDB, or ndb). **OSV keys
deb and rpm advisories on the *source* package** while the database lists binary
packages, so the source mapping (`Source:`, `SOURCERPM`, apk's `o:`) is applied
before querying; `--format inventory` shows both names.

Presence is then decided by a **`DT_NEEDED` closure**: every ELF in the image is
read for `DT_SONAME` / `DT_NEEDED` / `DT_RPATH` / `DT_RUNPATH`, resolved in
`ld.so`'s search order (RPATH → `LD_LIBRARY_PATH` → RUNPATH → `ld.so.conf` →
default dirs, matching the referrer's ELF class and machine), and reached
transitively from the image's Entrypoint and Cmd. Directories the dynamic loader
opens by name rather than by `DT_NEEDED` — `libnss_*`, PAM modules, gconv
converters, OpenSSL engines and providers, `*.node`, `site-packages/**/*.so` —
are always roots.

| Situation | Status | Justification | Method |
|---|---|---|---|
| not installed at all | `not_present` | `component_not_present` | `pkgdb-inventory` |
| installed, owns no ELF (docs, data, scripts) | `not_present` | `vulnerable_code_not_present` | `pkgdb-no-code` |
| owns ELFs, none reachable, nothing blocking | `not_in_execute_path` | `vulnerable_code_not_in_execute_path` | `elf-needed-closure` |
| a validated mined symbol is defined by nothing the package installs | `not_present` | `vulnerable_code_not_present` | `elf-dynsym-absent` |
| reachable, or anything blocking | `linked` | *(none — treat as affected)* | `elf-needed-closure` |

#### Taints

A taint never sets a status. It *blocks* the closure from concluding
`not_affected`, and is always emitted as evidence, so the report says why it
could not answer rather than answering wrongly.

| Taint | Trigger | Effect |
|---|---|---|
| `unresolved-needed` | a `DT_NEEDED` that resolved to nothing | scoped to that soname |
| `dlopen` | a reachable ELF references `dlopen`/`dlmopen` | global, unless `--dlopen-policy=assume-none` |
| `static-elf` | a reachable ELF has no `PT_INTERP`/`.dynamic` | blocks all C-library conclusions |
| `shell-entrypoint` | argv[0] is a shell or init shim (`sh`, `busybox`, `tini`, `s6-*`) | every ELF in the standard bin dirs becomes a root |
| `no-entrypoint` | the image config has neither Entrypoint nor Cmd — or there is no config at all, as in `--rootfs` mode | same escalation |

`--roots /path/to/bin` adds entrypoints for an image whose real command comes
from outside its own config — a Kubernetes `command:`, a sidecar, an operator —
and for a `--rootfs` tree, which has no config to read.
Supplying them is usually the difference between a useful answer and
`shell-entrypoint` tainting everything.

### Python and npm, image mode

Both work the same way, and the way is the OS closure with the linker swapped
for an import resolver.

**Inventory.** For Python, every `*.dist-info/` and `*.egg-info/` under any
`site-packages` or `dist-packages` directory: name and version from `METADATA`,
file list from `RECORD`, import names from `top_level.txt`. This is exactly as
authoritative as `/var/lib/dpkg/status` — it is the installer's own record. For
npm, every `node_modules/*/package.json`, including nested ones, since that is
how npm carries two versions of one package and each nesting level is a distinct
installed instance.

`RECORD` is the load-bearing part and it is not always there: `pip` installs
itself without one. A file list that had to be *reconstructed* by walking
directories can be empty because the walk looked in the wrong place, so it never
supports a `not_present` — the finding stays `linked` and says why.

**Reachability** is a static import closure rooted at what the image actually
runs, the direct analog of the `DT_NEEDED` closure. Python resolves absolute and
relative imports against a modelled `sys.path` (script dir, `PYTHONPATH`, each
`site-packages`, the stdlib), including PEP 420 namespace packages; Node does
extension probing, `package.json#main`, `index.js`, upward `node_modules` walks,
and the tractable subset of `exports`.

`.pth` files are read the way the interpreter reads them: a bare path extends the
modelled `sys.path`, and an `import x` line makes `x` a root, because the
interpreter imports it at startup and nothing else in the image refers to it.
`sitecustomize.py` and `usercustomize.py` are rooted for the same reason. These
are Python's analog of the plugin directories `elfgraph` always roots. A `.pth`
line that is neither — arbitrary startup code — is a global blocking taint, and
it is the thing that decides the Airflow result below.

The scanners are line-oriented lexers, not parsers. They over-approximate —
imports under `if TYPE_CHECKING:`, in dead branches, in strings — which is the
safe direction, since a larger reachable set only ever *prevents* a
`not_affected`. What they under-approximate is computed imports, and that is
exactly what the `dynamic-import` taint covers.

| Situation | Status | Justification | Method |
|---|---|---|---|
| not installed at all | `not_present` | `component_not_present` | `pydist-inventory` / `npmdist-inventory` |
| installed, ships no importable code (stubs-only, data-only) | `not_present` | `vulnerable_code_not_present` | `pydist-no-code` / `npmdist-no-code` |
| a validated mined module is provided by nothing the package installs | `not_present` | `vulnerable_code_not_present` | `py-module-absent` / `npm-module-absent` |
| ships code, nothing reachable imports it, nothing blocking | `not_in_execute_path` | `vulnerable_code_not_in_execute_path` | `py-import-graph` / `npm-require-graph` |
| reached, but nothing imports the validated mined module | `linked` + evidence; `not_in_execute_path` only with `--trust-import-absence` | — | `py-import-absent` / `npm-import-absent` |
| reached, or anything blocking | `linked` | *(none — treat as affected)* | `py-import-graph` / `npm-require-graph` |
| an installed distribution could not be identified at all | `undetermined` | — | `pydist-inventory` / `npmdist-inventory` |

That last row is why an unreadable `dist-info` does not become a clean answer:
"no distribution here is named X" is not a claim a scan can make when one of the
distributions has no readable name.

#### Taints

| Taint | Trigger | Effect |
|---|---|---|
| `unresolved-import` | a specifier that resolved to no file | scoped to that specifier |
| `dynamic-import` | `importlib.import_module(x)` / `__import__(x)` / `require(x)` with a **computed** argument; also `python -c`, a program on stdin, and a `.pth` file that runs something other than a plain import | scoped to the importing distribution and everything it requires, or global when the importing code belongs to no installed distribution. `--dynamic-import-policy=assume-none` demotes it to non-blocking |
| `plugin-discovery` | reachable code calls `entry_points()` / `pkgutil.iter_modules` | roots every entry-point module declared on disk; blocking and global only when there was nothing to enumerate |
| `foreign-entrypoint` | argv[0] is not this language's interpreter | global; every installed module becomes a root |
| `no-entrypoint` | no Entrypoint and no Cmd, a bare interactive interpreter, or no config at all (`--rootfs`) | same escalation |
| `bundled-entrypoint` | (npm) a reachable root's tree contains no `node_modules` | global |
| `unreadable-module` | a reachable file that could not be read | global — everything downstream of it is missing |

A **literal** argument is not a dynamic import: `importlib.import_module("foo.bar")`
and `require("lit")` resolve exactly like static imports and are followed as
ordinary edges. Without that distinction nearly every Python image taints, which
is the same honest-but-useless failure `shell-entrypoint` guards against.
`plugin-discovery` likewise resolves rather than surrenders — `entry_points.txt`
is on disk inside each `dist-info`, so the set of plugins discovery *could*
return is knowable, and rooting those distributions is a real answer where a
global taint would be a shrug.

### Java (Maven), image mode

A jar is a zip, and its central directory names every class the artifact ships.
Listing it executes nothing and runs no parser over attacker-supplied bytes, so
**"this artifact does not contain the vulnerable class" is a fact read off the
disk** rather than an inference. That is the whole reason the ecosystem is here,
and it is the one presence test in this tool that regularly disagrees with a
version scanner.

There is no reference graph. Nothing reads a constant pool, so an artifact that
ships the class is reported `linked` — present and loadable, with no claim about
whether anything calls it.

**Inventory.** Every `.jar`, `.war` and `.ear` anywhere in the image, plus one
level of the dependency archives they carry inside: `BOOT-INF/lib/` (Spring Boot
fat jars), `WEB-INF/lib/` (wars) and `APP-INF/lib/` and `lib/` (ears). A nested
archive is addressed with the JVM's own spelling —
`/usr/share/jenkins/jenkins.war!/WEB-INF/lib/spring-core-7.0.8.jar` — and each
one is bounded at 256 MiB decompressed. Without this a Spring Boot image
inventories as one component and misses everything it actually runs. Measured on
`jenkins/jenkins:lts`: **3 archives on disk, 123 packages inside them.**

Multi-release classes under `META-INF/versions/N/` count, because a new enough
JVM loads them in preference to the base copy.

**Coordinates come in tiers, and the tier travels with the data.** Unlike a
`dist-info` or a `package.json`, a jar frequently carries no statement of its
own groupId.

| Tier | Source | `CoordsKnown` |
|---|---|---|
| 1 | `META-INF/maven/<g>/<a>/pom.properties` — Maven's own record | yes |
| 2 | `META-INF/native-image/<g>/<a>/` — the Gradle/Spring/GraalVM convention, same two coordinates | yes |
| 3 | `MANIFEST.MF`: `Implementation-Vendor-Id`/`-Title`, else the OSGi `Bundle-SymbolicName` | **no** |
| 4 | the `<artifactId>-<version>.jar` file name plus the classes' shared package prefix | **no** |

Tiers 3 and 4 still produce a queryable name, and every other plausible reading
is offered alongside it as an alternate to query — one more entry in a batch
request costs nothing, and querying only the wrong name reports a vulnerable
artifact as clean. What they cannot do is support a claim of *absence*: saying
"this artifact ships no such class" about an artifact the scan only believes the
jar to be is two guesses stacked, and the second hides the first.

Tier 3 is load-bearing in practice. Tomcat's own jars carry nothing but an OSGi
manifest: `catalina.jar` states `Bundle-SymbolicName: org.apache.tomcat-catalina`
and no coordinate. A symbolic name cannot spell the groupId/artifactId boundary,
so the dot split lands one segment shallow at `org.apache:tomcat-catalina`;
`org.apache.tomcat:tomcat-catalina`, which is what OSV keys Tomcat's advisories
on, is reachable only because Maven artifactIds conventionally repeat the last
segment of their groupId, and is queried as an alternate. **The name printed for
a tier-3 or tier-4 artifact may therefore be a coordinate nobody publishes
under** — the finding carries evidence saying the coordinates were reconstructed.

| Situation | Status | Justification | Method |
|---|---|---|---|
| no archive in the image declares the artifact | `not_present` | `component_not_present` | `jar-inventory` |
| …but some archive could not be read or declares no coordinates | `undetermined` | — | reason `unidentified_archive` |
| the archive holds no `.class` entry at all (sources, javadoc, resources jar) | `not_present` | `vulnerable_code_not_present` | `jar-no-code` |
| a validated mined class is absent under every package spelling | `not_present` | `vulnerable_code_not_present` | `jar-class-absent` |
| the archive is present but its listing could not be read | `linked` + blocking evidence | — | `jar-inventory` |
| otherwise | `linked` | *(none — treat as affected)* | `jar-inventory` |

Repo mode is deliberately absent. Maven has no lock file, and resolving a
`pom.xml` means parent POMs and version ranges — that is running the build.
Gradle's `gradle.lockfile` is real but rare. Deferred, not refused on principle.

### Python and npm, repo mode

A checkout gets **lock file inventory and no import graph.** Resolving a
specifier needs an installed dependency tree, and materializing one means
running the target's build — arbitrary code from the thing being audited.
`vexscan` declines, and says so in the finding rather than letting the silence
read as a weaker form of a clean answer.

Read: `package-lock.json` and `npm-shrinkwrap.json` (v1 nested trees and v2/v3
`packages` maps, aliases and workspace links handled), `requirements*.txt`,
`poetry.lock`, and `Pipfile.lock`. `pyproject.toml` is deliberately not among
them — it declares constraints rather than resolutions.

| Situation | Status | Justification | Method |
|---|---|---|---|
| no lock file declares the named package | `not_present` | `component_not_present` | `pypi-lockfile` / `npm-lockfile` |
| declared as a development dependency only | `not_in_execute_path` | `vulnerable_code_not_in_execute_path` | `pypi-dev-only` / `npm-dev-only` |
| otherwise | `linked` | *(none — treat as affected)* | `pypi-lockfile` / `npm-lockfile` |

The dev-only row is a **deterministic test, not a heuristic**: `"dev": true` in a
lockfile, a non-`main` `poetry.lock` group, or `Pipfile.lock`'s `develop` section
each mean *reachable only through development dependencies*, so `npm ci
--omit=dev` and `poetry install --only main` will not install it. It is
`not_in_execute_path` rather than `not_present` because the code does run — in
CI, and on every machine that checks the repo out.

`requirements.txt` carries no such partition, and none is invented. A file named
`requirements-dev.txt` is a convention, not a declaration, and is never read as
one; a package a repo declares only there still comes back `linked`.

An unpinned requirement (`flask` with no `==`) proves the package is present but
pins no version, so the advisory matched on the *name alone*. That finding is
`linked` and carries blocking evidence saying the affected range was never
compared against anything — without it, one unpinned line would report every
advisory ever filed against that package as though the version had been checked.

## Known limits — read this before trusting a result

**The closure is a weaker signal than Go's pclntab test, and the gap matters.**

pclntab is ground truth about what the linker *removed from the shipped
artifact*: if the package name is not in the table, the code is not in the file.
The closure proves nothing about the file's contents. It is ground truth only
for an image that is fully dynamically linked, does not call `dlopen`, and has a
known entrypoint. Concretely:

- **Alpine and distroless images are the worst case.** Static binaries embed
  musl, OpenSSL and zlib while the corresponding `.so` sits unreferenced on
  disk. The `static-elf` taint catches this and the result is `linked` — correct
  but useless — on exactly the images people most want a clean answer for.
- **Distro base images are nearly as bad.** `debian:12` and `ubi9` ship with
  `bash` as Cmd, which triggers `shell-entrypoint`: every binary in `/usr/bin`
  becomes a root, and almost everything is reachable. On `ubi9:latest --all`,
  292 findings come back as 58 `not_present` (via `pkgdb-no-code`) and 234
  `linked`. That is the honest answer for a general-purpose base image — it
  really can run anything — but it is not a useful one. **The closure earns its
  keep on purpose-built application images with a real entrypoint**, not on base
  images.
- `glibc` is reachable from everything and always will be. Do not expect the
  closure to rule out a libc CVE.
- **`--rootfs` has no entrypoint to start from**, so it begins where a base
  image ends up: everything is a root. `--roots` is the way out, and naming the
  wrong thing does not help. See
  [`--rootfs`](#scanning-a-filesystem-instead-of-an-image---rootfs).

**Python and npm are weaker still, and the numbers below are the point.**

Neither language eliminates dead code. An installed distribution's code is on
disk whether or not it ever runs, so `not_present` can only mean "not installed"
or the mined-module case — the pclntab test has no analog here. Reachability is
the only remaining lever, and it is blocked more readily than the ELF closure
is. Computed imports, plugin discovery and startup hooks are Python's `dlopen`,
and unlike `dlopen` they are everywhere.

| Image | Components | `not_present` / `not_in_execute_path` / `linked` | What dominated |
|---|---|---|---|
| `node:22-slim --ecosystem npm` | 186 | 0 / 0 / 14 | `foreign-entrypoint` (`docker-entrypoint.sh`) plus `dynamic-import` |
| `python:3.12-slim --ecosystem pypi` | 1 | 0 / 0 / 5 | `no-entrypoint` — a bare interpreter can import anything installed |
| `apache/airflow:latest --ecosystem pypi` | 434 | 0 / 0 / 28 | `foreign-entrypoint` (`dumb-init`) escalated **37,892 roots**; a `.pth` file running startup code taints globally on top of that |

Read that table before deciding what these ecosystems buy you. On these images
the graph rules out nothing, and the tool reports `linked` with the reason
attached rather than a clean answer it cannot support. Expect the same for
anything built on pytest plugins, Airflow providers, Home Assistant
integrations, or Django's string-named `INSTALLED_APPS`.

**`--roots` fixes the graph and still may not change the verdict.** Pointing
Airflow at its real entrypoint — `--roots /home/airflow/.local/bin/airflow` —
drops 37,892 escalated roots to 2 and the reachable set from 38,598 modules to
12,668. All 28 findings stay `linked` anyway, because a `.pth` file in that
image runs code at startup, and that taints globally no matter how well the
roots are chosen. That is the honest result and it is the one reported: a much
better graph, and a taint that outranks it.

Two more failure modes worth naming:

- **Bundled JavaScript defeats the inventory.** A webpack or esbuild output ships
  no `node_modules`, so the inventory finds nothing and every package would
  answer `component_not_present` — right conclusion, wrong reason. The
  `bundled-entrypoint` taint exists to say so out loud rather than let it pass as
  a clean scan.
- **Frozen Python** (PyInstaller, zipapp) has no `site-packages`, so `DetectImage`
  returns false and the plugin does not apply at all. That is a silence rather
  than a false clean.

If a whole class of images comes back `linked`, the answer is vendor VEX feeds
rather than more heuristics. [`--vexhub`](#vex-hubs---vexhub) is the first of
those: it contributes `Evidence{Origin: "vendor-vex"}` alongside the local
evidence, under one policy — local deterministic evidence outranks a vendor
claim, and a vendor `not_affected` never downgrades a finding below `linked` on
its own. Direct distro feeds (Red Hat CSAF, Debian tracker, Alpine secdb) are
the same shape and would slot in beside it.

**Java's presence test is sharp and its inventory is the weak part.** The class
check is the strongest below-package test in this tool after pclntab, and it
fires only when an advisory names a class — which OSV's Maven records never do
in structured form, so it needs `--llm --mine-advisories`. Without that flag the
plugin is an inventory. With it, the numbers below are still dominated by
`linked`, because these images genuinely do ship the vulnerable classes.

| Image | Archives | Artifacts | Unidentified | `not_present` / `not_in_execute_path` / `linked` |
|---|---|---|---|---|
| `tomcat:10.1.30-jre21 --ecosystem maven` | 42 | 29 | 13 | 0 / 0 / 33 |
| `jenkins/jenkins:lts --ecosystem maven` | 3 (123 nested) | 111 | 4 | 0 / 0 / 8 |
| `ghcr.io/christophetd/log4shell-vulnerable-app --ecosystem maven` | 23 (+nested) | 27 | 24 | 0 / 0 / 79 |
| `eclipse-temurin:21-jre --ecosystem maven` | 0 | 0 | 0 | plugin does not apply |

Read the unidentified column, because it is the one that bites:

- **A JRE image's own jars dominate it, and they should.** On the Log4Shell demo
  image (JDK 8) 21 of the 24 are `rt.jar`, `charsets.jar`, `jre/lib/ext/*.jar`
  and the security policy jars. Those are not Maven artifacts and have no
  coordinates to find. But **an unidentified archive blocks `component_not_present`
  for anything the scan is asked about and does not find** — the archive that
  could not be named could be the one being asked about. So on a JDK 8 base
  image, "that artifact is not here" is an answer this tool will not give.
  Modern JREs are modular (`eclipse-temurin:21-jre` has no jars at all), which
  is why that row is empty rather than noisy.
- **`tomcat:10-jre21` leaves 13**, of which 10 are the `tomcat-i18n-*.jar`
  resource bundles: they ship no classes, so tier 4 has no package prefix to
  work from. The remainder are `jrt-fs.jar` and a sample war.
- **A jar whose classes span two unrelated package roots falls out of tier 4.**
  `spring-aop` bundles `org.aopalliance` alongside `org.springframework.aop`, so
  the shared prefix is `org` and no coordinate is offered. That is 4 of 127 on
  Jenkins and 1 of 27 on the demo image. Refusing beats guessing here, but it is
  a gap, not a design win.

**Shading is handled for the class test and not for the inventory.**
`maven-shade-plugin` relocates `org.apache.commons.X` to
`com.foo.shaded.org.apache.commons.X`; a relocated copy still ends in
`/X.class`, so searching every package spelling means a shaded jar comes back
`linked` with evidence naming the relocated entry rather than a false
`not_present`. Shading usually preserves the merged `META-INF/maven` entries, so
an uber-jar still declares every artifact it absorbed and each becomes its own
component. When a build strips them, it does not.

**A bare class name concludes about one artifact only.** Log4Shell's advisory
lists 5 affected Maven artifacts and writes the class as bare `JndiLookup`, so
finding no such class proves only that *this* artifact ships none. If an
advisory names a class belonging solely to a sibling artifact, the conclusion is
wrong. The coordinate and listing gates bound that; OSV has already asserted
this artifact is affected. It is not eliminated.

**Repo mode is narrower by design.** A lock file gives coordinates and a
development partition, nothing more, so the best case there is
`npm-dev-only` — and that only fires for lock formats that declare the
partition. Measured: `npm/cli --all --ecosystem npm` is 993 packages and
`0 not_present / 11 not_in_execute_path / 10 linked`, with the dev partition
carrying more than half the findings. `home-assistant/core --all --ecosystem
pypi` is 1,224 packages and `0 / 0 / 26`, because `requirements.txt` declares no
dev partition at all and 22 of the 26 additionally pin no version.

## LLM layer (optional, `--llm`)

The LLM is an overlay and never a source of truth. It runs only on findings the
deterministic tests could not clear, and it cannot change a status.

- **`--llm`** — for CVEs whose vulnerable code is genuinely linked or reachable,
  a chat model gives an advisory `likely` / `unlikely` / `unknown` exploitability
  verdict, recorded under `llm` on the finding. You choose which model — see
  [Choosing a provider](#choosing-a-provider).
- **`--mine-advisories`** — lets the model read an advisory's prose and extract
  symbols, sonames, filenames and **module paths** worth checking. Distro OSV
  records give a fixed version and nothing about what inside the package is
  vulnerable, so for OS packages this is often the only route to a
  below-package-level answer. For Python and npm the mined value is a dotted
  module path or a package subpath — `yaml.constructor`, `lodash/template` — and
  it is the only route to a `not_present` for a distribution that is installed
  and does ship code, since neither language eliminates dead code at build time.
  For Java the mined value is a **class name**, and this is the ecosystem that
  needs mining most while getting the least help with it: OSV's Maven records
  carry no `ecosystem_specific` function data at all, unlike RustSec, so a class
  name can only come from prose. When one arrives it is checkable against
  something exact — a class is an entry in a zip.

**Mined hints are contained, not trusted.** A hint may only support a
`not_affected`-flavored status *after validation*: it must appear literally in
the advisory text, and it must be found in something the package actually
installs — the **defined** `.dynsym` of one of its libraries for an OS package,
its own installed file list for a Python or npm module path, an entry in the
archive for a Java class. An unvalidatable mined hint is indistinguishable from
a hallucination and is recorded as inconclusive, so a hallucinated hint is inert
rather than dangerous.

The Python and npm validations additionally defer to any blocking taint, and to
a file list that had to be reconstructed rather than read. Both are cases where
"the module is not here" could equally mean "we did not look in the right
place".

The Java validation adds two gates of its own. A mined name must be **shaped
like a class** — a dotted name whose last segment is capitalised — because there
is no `doLookup.class` and concluding absence from a method name's absence would
be a plain lie. And the artifact's **coordinates must have been read** rather
than reconstructed (tiers 1–2 above), on the same principle: an absence claim
about an artifact whose identity is a guess is two guesses stacked.

The class is then looked for under **every** package spelling in the archive,
not only the one the advisory wrote. That is what makes a bare `JndiLookup`
usable at all — GHSA-jfh8-c2jp-5v3q never writes the package — and it is
simultaneously the shading guard described above.

`elf-import-absent`, `py-import-absent` and `npm-import-absent` — reachable, but
nothing imports the vulnerable symbol or module — stay evidence-only unless you
pass `--trust-import-absence`. Absence of a *direct* import does not prove
unreachability, because the vulnerable code is usually called from inside the
same library or package.

### Choosing a provider

There is **no default**. `vexscan` used to call [GitHub
Models](https://github.com/marketplace/models), which was free with a token most
users already had; it has been retired. `--llm` with nothing configured fails
and prints the three ways to configure it, rather than quietly not asking —
missing verdicts look exactly like findings nothing had an opinion about.

**An OpenAI-compatible endpoint.** Almost everything speaks this format:

```sh
export VEXSCAN_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions
export VEXSCAN_LLM_TOKEN=sk-...          # or just set OPENAI_API_KEY
vexscan --image myorg/app:latest --all --llm --llm-model gpt-4o
```

Anthropic serves the same shape at
`https://api.anthropic.com/v1/chat/completions` (with `ANTHROPIC_API_KEY`), as
do Azure AI Foundry, OpenRouter, Together, Groq and Fireworks. Set
`--llm-model` to whatever that provider calls the model; routers want the
`vendor/model` spelling.

**A model on your own machine.** Ollama, vLLM and `llama.cpp` all expose the
same endpoint, and none of them wants a token:

```sh
ollama pull llama3.1                     # with `ollama serve` running
vexscan --image myorg/app:latest --all --llm \
  --llm-endpoint http://localhost:11434/v1/chat/completions --llm-model llama3.1
```

This is the closest replacement for what GitHub Models provided — free, and
nothing about the image you are triaging leaves the machine. The work suits a
small model better than it looks: the prompts are short, the answer is one small
JSON object, and `--mine-advisories` is extraction from text that is supplied in
the prompt rather than recall. Expect thinner rationales; expect nothing else to
change.

**A CLI you already have logged in.** The prompt goes to its standard input and
the reply is read from its standard output:

```sh
vexscan --image myorg/app:latest --all --llm --llm-command 'claude -p'
```

Anything that takes a prompt on stdin and prints a reply works, including a
wrapper script around something in-house. This is the weakest transport and the
trade is worth knowing: there is no structured-output mode to ask for, so the
reply is whatever the CLI printed; there are no rate-limit headers, so a
provider that wants you to slow down can only say so by failing; and an
unauthenticated CLI fails once per finding rather than once at startup. Note
also that `--llm-model` does nothing here — put the model in the command itself.

| | Flag | Environment |
|---|---|---|
| Endpoint | `--llm-endpoint` | `VEXSCAN_LLM_ENDPOINT` |
| Model | `--llm-model` | `VEXSCAN_LLM_MODEL` (default `gpt-4o`) |
| Credential | *(none, deliberately)* | `VEXSCAN_LLM_TOKEN`, else `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` |
| Local CLI | `--llm-command` | `VEXSCAN_LLM_COMMAND` |

The credential has no flag on purpose: everything on a command line is readable
in the process table by every other user on the machine. The prompt is sent to a
command's stdin for the same reason, and because advisory prose is long enough
to approach the argument-length limit.

**Which provider you pick cannot change a conclusion.** A verdict is only ever
attached to a finding that already has a status, and a mined symbol has to be
found in the artifact before it supports one. A weaker model produces vaguer
rationales and finds fewer checkable symbols. It cannot manufacture a
`not_present`. That is why this is a configuration option and not an
architectural decision.

### Rate limits and failures

`vexscan` caches verdicts per CVE, so the same CVE linked into twenty binaries
costs one call. Requests are not spaced out by default — set
`VEXSCAN_LLM_MIN_INTERVAL` (a Go duration) for a provider that needs it.
`429`/`5xx` and connection failures are retried with backoff, honoring
`Retry-After` up to two minutes; a failing `--llm-command` is **not** retried,
because a CLI's transient failures were already retried inside its own client
and its other failures do not improve on the sixth attempt. A failed assessment
is non-fatal either way: the finding is still reported, just without a verdict.

## Output

`--format text` is for reading; `--format json` is for keeping; `--format
fixplan` is for acting.

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

### Severity

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
  unrated, not unimportant ([above](#severity)), so every filtered run prints
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
for the same reason [`--vexhub`](#vex-hubs---vexhub) does not: it leaves the rows
in the order they were already in, which over-reports rather than under-reports.
The report says so explicitly, because a table with an empty KEV column must
never be readable as "nothing here is being exploited".

### VEX hubs (`--vexhub`)

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
            matched loosely: statement names pkg:golang/github.com/opencontainers/selinux@v1.11.0; component is pkg:golang/github.com%2Fopencontainers%2Fselinux@v1.11.1
```

Only `not_affected` and `fixed` move a row. A vendor `affected` or
`under_investigation` stays in `AFFECTED` and is annotated there — a vendor
confirming a finding must not make it quieter. The flag is repeatable and the
earliest hub to speak wins, so an internal hub listed first overrides a
vendor's.

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

### Contributing ruled-out findings back (`--vexhub-pr`)

`--vexhub` *reads* a hub. `--vexhub-pr` *writes* to one: it opens a pull request
against the `--vexhub` repository adding an OpenVEX `not_affected` statement for
every finding this scan **ruled out** — the `RULED OUT` section, where the
vulnerable code is not present or cannot run — that the hub does not already
answer.

```sh
vexscan --image rancher/hardened-kubernetes:v1.34.10-rke2r1-build20260724 --all \
  --vexhub https://github.com/rancher/vexhub \
  --vexhub-pr
```

Each ruled-out finding becomes one statement, filed under the artifact it was
found in (`pkg:oci/…` or a Go binary's `pkg:golang/…`), scoped to the component
purl, and carrying the OpenVEX justification the plugin already recorded
(`component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`) plus a one-line `impact_statement` saying
how vexscan reached the verdict. Existing documents are **merged, not
overwritten**: a statement the hub already has for the same vulnerability and
component is left in place, and `index.json` gains an entry only for a product
the hub did not yet cover.

- **Preview first with `--vexhub-pr-dry-run`.** It prints the branch, the PR
  title, every statement grouped by product, and the files that would change,
  and exits without touching the network beyond reading the hub.
- **A finding the hub already speaks to is never touched.** If `--vexhub` matched
  a statement for it — even an `affected` one — the PR leaves it alone. This flow
  fills gaps; it does not overrule a vendor.
- **Only a complete scan contributes.** If any ecosystem failed to inventory, the
  PR is not opened: a `not_affected` claim from a partial scan is exactly the
  kind of wrong this tool must never publish.
- **The author is you.** By default the OpenVEX `author` is the authenticated
  GitHub user (`<login> (via vexscan)`); override it with `--vex-author`.
- **Push to a fork you maintain with `--vexhub-pr-repo owner/repo`** when your
  token cannot push a branch straight to the hub. Keep that fork's default branch
  in sync with the hub's.

It needs a `GITHUB_TOKEN` / `GH_TOKEN` with pull-request scope on the hub (the
same variables `--gist` uses; this uses GitHub's REST API directly, so no `gh`
CLI is required inside the image). Only a `github.com` hub URL can become a PR —
a raw base URL or a local directory cannot, and the flag says so.

### JSON

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
[`--vexhub`](#vex-hubs---vexhub) a finding also carries `product` (the artifact
it was found in) and, when one matched, `vex` — the statement's `status`,
`justification`, `impact_statement`, `action_statement`, `author`, the product
purl that matched and the hub it came from, so a consumer can audit the claim
without re-fetching. With [`--triage`](#prioritising-by-exploitation-evidence---triage)
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

## Flags

| Flag | Default | Description |
|---|---|---|
| `--image` | | Container image to inspect |
| `--rootfs` | | Filesystem tree already on disk to inspect — see [`--rootfs`](#scanning-a-filesystem-instead-of-an-image---rootfs) |
| `--repo` | | Git source repo to analyze: govulncheck source mode for Go, lock file inventory for Python and npm |
| `--sbom` | | CycloneDX JSON bill of materials to scan — a path, or `-` for stdin. Every finding is `undetermined`; see [`--sbom`](#scanning-a-bill-of-materials---sbom) |
| `--rpm` | | RPM package file to scan without installing it — a path, a directory of them, or a URL; repeatable. Reads only the header, so a URL costs kilobytes not megabytes — see [`--rpm`](#scanning-package-files---rpm) |
| `--package` | | Package to check: purl, `ecosystem:name`, or bare name; repeatable |
| `--cves` | | CVE / GHSA / GO / RHSA / DSA ids; alone, resolved against the whole target |
| `--all` | `false` | Check everything each ecosystem can enumerate |
| `--ecosystem` | *(all)* | Restrict to these ecosystems (`golang`, `os`, `pypi`, `npm`, `maven`, or a distro family); repeatable |
| `--module` | | **Deprecated** alias for `--package golang:MODULE` |
| `--cves-file` | | File with one id per line (merged with `--cves`; `#` comments allowed) |
| `--ref` | *(default branch)* | Branch, tag, or commit to check out for `--repo` |
| `--repo-path` | `.` | Subdirectory within `--repo` to scan — the Go module, or the directory holding the lock files |
| `--module-version` | *(auto)* | Override the module version (image mode) instead of reading build info |
| `--version` / `-V` | | Print vexscan's version and exit. `--version=VERSION` is a **deprecated** spelling of `--module-version` and warns |
| `--go-version` | *(auto)* | Pin the Go toolchain for `--repo`, e.g. `1.24.0` (useful with `golang:stdlib`) |
| `--osv-ecosystem` | *(auto)* | Override the OSV ecosystem derived from os-release, from the `VENDOR`/`DISTRIBUTION` headers under `--rpm`, or from the `distro=` purl qualifier under `--sbom`, e.g. `Debian:12` |
| `--roots` | | Extra entrypoints for the closures — shared libraries and language imports; repeatable |
| `--vexhub` | | VEX Repository to check findings against, e.g. `https://github.com/rancher/vexhub` (also a raw base URL or a local directory); repeatable, earliest wins — see [VEX hubs](#vex-hubs---vexhub) |
| `--vexhub-pr` | `false` | Open a PR against the `--vexhub` repo adding OpenVEX `not_affected` statements for the findings ruled out — see [Contributing ruled-out findings back](#contributing-ruled-out-findings-back---vexhub-pr) |
| `--vexhub-pr-repo` | | With `--vexhub-pr`, push the branch to this `owner/repo` fork instead of straight to the hub |
| `--vex-author` | *(GitHub user)* | With `--vexhub-pr`, the OpenVEX `author` to record on the statements |
| `--vexhub-pr-dry-run` | `false` | With `--vexhub-pr`, print the files the PR would change and exit without pushing or opening it |
| `--severity` | *(all)* | Only report findings at these severities: `CRITICAL`, `HIGH`, `UNKNOWN`, `MEDIUM`, `LOW`, `NONE`; comma-separated or repeatable. `UNKNOWN` must be named to be shown — see [Filtering by severity](#filtering-by-severity---severity) |
| `--triage` | `false` | Order findings by exploitation evidence — EPSS scores and CISA's known-exploited catalog. Adds two columns and re-sorts; hides nothing and changes no severity — see [Prioritising by exploitation evidence](#prioritising-by-exploitation-evidence---triage) |
| `--dlopen-policy` | `taint` | `taint` (block conclusions) or `assume-none` |
| `--dynamic-import-policy` | `taint` | The same knob for a language import graph's computed imports. These are far more common than `dlopen`, so `assume-none` discards much more |
| `--trust-import-absence` | `false` | Let a missing dynamic import conclude `not_in_execute_path` (weaker than it looks) |
| `--os` / `--arch` | `linux` / `amd64` | Image platform variant to pull (image mode only) |
| `--llm` | `false` | Consult a chat model on genuinely-affected CVEs; needs a provider below |
| `--llm-endpoint` | | OpenAI-compatible chat/completions URL — an API provider or a local Ollama |
| `--llm-model` | `gpt-4o` | Model id for `--llm-endpoint` |
| `--llm-command` | | Run this installed CLI instead of an endpoint, e.g. `'claude -p'` |
| `--mine-advisories` | `false` | With `--llm`, mine advisory prose for symbols and module paths to check |
| `--format` | `text` | `text`, `json`, `fixplan`, or `inventory` |
| `--details` | `false` | With `--format text`, print the full evidence block under each row instead of the table alone |
| `--out` | *(stdout)* | Write output to a file |
| `--gist` | `false` | Also upload the output to a public gist and print its URL (token needs `gist` scope) |
| `--gist-secret` | `false` | With `--gist`, create a secret (unlisted) gist |
| `--fail-on` | | Exit `3` if a counted finding is at or above this severity, or `any`. Off by default — see [Gating a pipeline](#gating-a-pipeline---fail-on) |
| `--fail-on-status` | `affected` | What `--fail-on` weighs: a comma-separated list of `affected`, `undetermined`, `vexed`, `cleared`, or `all` |
| `--color` | `auto` | `auto`, `always`, or `never`. `auto` colours only a terminal — never a pipe, a `--out` file, a `--gist`, JSON, or a run with `NO_COLOR` set — see [Colour](#colour---color) |
| `--no-pager` | `false` | Never page the output, even when stdout is a terminal — see [Reading a long report](#reading-a-long-report) |
| `--quiet` | `false` | Suppress progress logging on stderr |

`--gist` uploads whatever would otherwise be printed, respecting `--format`,
using `GITHUB_TOKEN` / `GH_TOKEN` with gist scope. It composes with `--out`
(written to the file *and* uploaded).

### Standard library

Go standard-library CVEs work in both modes via `--package golang:stdlib` (the
name OSV and govulncheck use; `std` is an alias):

```sh
vexscan --image myorg/app:latest --package golang:stdlib --cves CVE-2025-22870
vexscan --repo github.com/rancher/rancher --package golang:stdlib --go-version 1.24.0
```

In repo mode the stdlib version analyzed is that of the toolchain running
govulncheck. `GOTOOLCHAIN=auto` only ever *upgrades*, so without `--go-version` a
repo is scanned with the newest locally-available toolchain. A pinned older
toolchain may be too old to build the latest `govulncheck`; pair it with
`VEXSCAN_GOVULNCHECK_VERSION` (e.g. `v1.1.4`) if `go run` complains.

### Environment variables

Its own variables are prefixed `VEXSCAN_`; the `GOMODVEX_` names are still
honored as a fallback so existing CI keeps working.

| Variable | Legacy name | Purpose |
|---|---|---|
| `VEXSCAN_LLM_ENDPOINT` | | OpenAI-compatible chat/completions URL for `--llm` |
| `VEXSCAN_LLM_MODEL` | | Model id for that endpoint (default `gpt-4o`) |
| `VEXSCAN_LLM_TOKEN` | | Bearer credential for that endpoint; `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` are accepted as fallbacks |
| `VEXSCAN_LLM_COMMAND` | | A local CLI to run for `--llm` instead of calling an endpoint |
| `VEXSCAN_LLM_MIN_INTERVAL` | `GOMODVEX_LLM_MIN_INTERVAL` | Minimum spacing between `--llm` calls (Go duration; default none) |
| `VEXSCAN_GOVULNCHECK_VERSION` | `GOMODVEX_GOVULNCHECK_VERSION` | Pin the govulncheck version used by `--repo` |
| `VEXSCAN_TRIAGE_CACHE` | | Directory for the `--triage` feed cache (default `os.UserCacheDir()/vexscan/triage`, e.g. `~/Library/Caches` or `$XDG_CACHE_HOME`) |
| `VEXSCAN_PAGER` | `GOMODVEX_PAGER` | Pager for terminal output; `$PAGER` is the fallback, `less` the default. Set it **empty** to never page — unlike the variables above, an empty value here is a decision rather than an absence |

`GITHUB_TOKEN` / `GH_TOKEN` are for `--gist` (gist scope) and `--vexhub-pr`
(pull-request scope on the hub), and are unchanged.

## Requirements

- [`skopeo`](https://github.com/containers/skopeo) on `PATH` — image mode
- A Go toolchain on `PATH` — required at **runtime** for `--repo`, which builds
  and runs `govulncheck` itself via `go run` with `GOTOOLCHAIN=auto`
- `git` on `PATH` — repo mode, unless scanning a local path
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on
  `PATH` — optional, used only for Go binary mode
- Network access for OSV lookups, and for `--repo` cloning
- `GITHUB_TOKEN` / `GH_TOKEN` for `--gist`, and for `--vexhub-pr`
- An LLM provider for `--llm` — an endpoint and key, a local model, or an
  installed CLI. See [Choosing a provider](#choosing-a-provider); there is no
  default and nothing is required unless you pass `--llm`.

All three package databases are parsed in-process — no `dpkg`, `rpm` or `apk`
binary is needed. So are the Python and npm inventories and lock files, and the
Java archives: no `python`, `pip`, `node`, `npm`, `java` or `unzip` is required,
and nothing from the target is ever executed.

## Install

```sh
go install github.com/cwayne18/vexscan@latest
```

Or from source:

```sh
git clone https://github.com/cwayne18/vexscan
cd vexscan
go build -o vexscan .
```

Building with `-tags norpm` drops the rpm database reader and its dependencies;
rpm images then report as an unreadable ecosystem rather than being silently
skipped.

### Container image (GHCR)

A self-contained image bundling `skopeo`, `git`, `govulncheck` and a Go
toolchain is published to
[`ghcr.io/cwayne18/vexscan`](https://github.com/cwayne18/vexscan/pkgs/container/vexscan)
on every push to `main` and every `v*` tag:

```sh
docker run --rm ghcr.io/cwayne18/vexscan:latest \
  --image rancher/hardened-coredns:v1.8.6-build20231009 \
  --package golang:golang.org/x/net --cves CVE-2023-39325

docker run --rm -e VEXSCAN_LLM_ENDPOINT -e VEXSCAN_LLM_TOKEN \
  ghcr.io/cwayne18/vexscan:latest \
  --image myorg/myapp:latest --package golang:golang.org/x/crypto --llm
```

## Caveats

- **The LLM verdict is advisory only.** Never file a VEX statement on an LLM
  verdict alone; it supplements the deterministic checks and does not replace
  them.
- **The pclntab test is conservative, not exact.** A genuinely-linked package is
  never reported absent, but validate candidates before publishing.
- **The `DT_NEEDED` closure is weaker still, and the Python and npm import
  graphs are weaker than that.** See [Known
  limits](#known-limits--read-this-before-trusting-a-result) — this is the
  most important section in this README.
- **`--rootfs` cannot know what the tree runs, and a tree you cannot fully read
  is not a clean tree.** Both are reported rather than assumed away — the first
  as taints, the second as `unreadable` plus exit 1. See
  [`--rootfs`](#scanning-a-filesystem-instead-of-an-image---rootfs).
- **`--rpm` runs no reachability test at all, and it says so on every report.**
  A package file has no filesystem behind it, so nothing is ever `linked` and
  nothing is ever ruled out as unreachable — only a package that ships no ELF
  object can be ruled out. See [`--rpm`](#scanning-package-files---rpm) for what
  that costs, measured.
- **`--sbom` runs no test of any kind, and it says so on every report.** A
  CycloneDX component is a name, a version and a purl: there is no filesystem
  to trace and no file list to rule anything out on, so **every** finding is
  `undetermined`. It is a triage input, not an answer. See
  [`--sbom`](#scanning-a-bill-of-materials---sbom).
- **Repo mode for Python and npm resolves no import graph at all.** A lock file
  answers "is this declared" and, where the format says so, "is it
  development-only". Nothing there speaks to reachability, and a `linked`
  finding says as much in its own text.
- When OSV publishes no package-level import paths for a Go advisory (some
  GitHub-only GHSA records), presence is asserted at **module** granularity;
  those findings say `granularity: module` and are coarser.

## License

MIT — see [LICENSE](./LICENSE).
