---
sidebar_position: 12
title: "Known limits"
---


**The closure is a weaker signal than Go's pclntab test, and the gap matters.**

pclntab is ground truth about what the linker *removed from the shipped
artifact*: if the package name is not in the table, the code is not in the file.
The closure proves nothing about the file's contents. It is ground truth only
for an image that is fully dynamically linked, does not call `dlopen`, and has a
known entrypoint. Concretely:

- **Alpine and static musl builds are the worst case.** A static binary embeds
  musl, OpenSSL and zlib while the corresponding `.so` sits unreferenced on
  disk. The `static-elf` taint catches this and the result is `linked` — correct
  but useless — on exactly the images people most want a clean answer for. The
  [pure-Go discharge](./how-the-tests-work.md#taints) lifts it for a `CGO_ENABLED=0` entrypoint, which
  covers the common distroless Go image but nothing built with cgo. For an
  unstripped cgo entrypoint, the [symbol-absence discharge](./how-the-tests-work.md#taints) can still
  clear a specific advisory when the vulnerable function is absent from the
  binary's own symbol table while its namespace is present; a stripped binary,
  or one that never links the family at all, stays `linked`.
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
  [`--rootfs`](./guides/rootfs.md).

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
rather than more heuristics. [`--vexhub`](./output/vex-sources.md) is the first of
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

Read the unidentified column, because it used to be the one that bit. An
archive that declares no coordinates still cannot be named, but it no longer
blocks every absence answer wholesale: an unidentified archive stops a
`component_not_present` verdict only for an artifact it *could* be, and a jar
that is positively something else, or that ships no code at all, is no longer in
the way.

- **A JRE image's own jars are recognized as the runtime.** On the Log4Shell demo
  image (JDK 8) 21 of the 24 unnamed archives are `rt.jar`, `charsets.jar`,
  `jre/lib/ext/*.jar` and the like. Those are not Maven artifacts and never will
  be, so they are matched by name and set aside as platform jars rather than
  counted as blockers — they cannot be the third-party artifact a scan is asked
  about. On a JDK 8 base image, "that artifact is not here" is now an answer this
  tool will give. Modern JREs are modular (`eclipse-temurin:21-jre` has no jars
  at all), which is why that row is empty rather than noisy. The name list is
  deliberately narrow: a project's own `tools.jar` or `plugin.jar` is left alone
  so it is never mistaken for the platform and wrongly cleared.
- **`tomcat:10-jre21`'s resource bundles no longer block.** Of the 13 it leaves,
  10 are the `tomcat-i18n-*.jar` bundles: they ship no classes, so tier 4 has no
  package prefix to work from — but a codeless archive cannot hold anyone's
  vulnerable class, so it can no longer stand in the way of an absence answer.
- **A jar whose classes span two unrelated package roots still falls out of tier
  4**, and that is correct: `spring-aop` bundles `org.aopalliance` alongside
  `org.springframework.aop`, so the shared prefix is `org` and no coordinate is
  offered. It stays unidentified — but the partial identity that *can* be read,
  the artifactId from its file name and the packages its classes declare, is now
  kept, so it only blocks an artifact it could actually be. `spring-aop` no
  longer blocks a question about `log4j-core`. What still blocks is the case that
  should: an unidentified jar that ships classes under the asked-about group's
  own package, which could be a repackaged copy carrying it under another name.

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

### When the main module says `(devel)`

**A Go binary built from a checkout carries no version for its own module, and
that is not a small problem.** `go install` stamps a semver version into build
info; `go build` from a source tree does not, and reports `(devel)`. OSV cannot
range-match that, so it answers with *every* advisory ever filed against the
module, including the ones fixed long before the build. This is by far the
largest source of Go false positives, because it lands on the one module whose
code is unquestionably present.

vexscan tries three recoveries for the main module, strongest first, and a
fourth for the one shape of *dependency* that has the same defect.

**1. The binary's own linker flags.** A project that versions itself with
`-ldflags "-X .../version.Version=v1.36.2+k3s1"` never gets that into
`Main.Version`, but the flags themselves are recorded verbatim in build info.
This is not an inference: it is the number the build used, read back out of the
artifact.

The difficulty is that large binaries stamp many versions. `/usr/bin/k3s` in
`rancher/rancher:v2.15.0` carries 25 `-X` assignments, six of which look exactly
like a version — for cri-tools, containerd, flannel, kube-router, cri-dockerd
and k3s itself. Reading containerd's `v2.3.2` as k3s's version would range past
every k3s advisory there is.

So the test is the variable's **owning package**: the stamp counts only if it
writes into the main module's own tree, or into package `main`, which by
definition belongs to the binary being built. Exactly one of the six survives
that. If two surviving stamps disagree, both are discarded.

This is deliberately narrower than trivy, which selects on the *shape of the
variable name* (a `main`/`common`/`version`/`cmd` prefix). Five of k3s's six
stamps end in `/version.Version`, so that rule finds five candidates, cannot
choose between them, and gives up: trivy reports the k3s main module with no
version at all, and therefore no findings against it — true or false.

**2. The binary's own symbol table,** for the builds where recovery 1 has
nothing to read because Go threw the flags away.

`-trimpath` makes the toolchain record no `-ldflags` setting at all — that is
[go#63432](https://go.dev/issue/63432) — and a reproducible distro rebuild sets
both:

```
go build           -ldflags "-X main.version=v9.9.9"
  → build -ldflags="-X main.version=v9.9.9"
go build -trimpath -ldflags "-X main.version=v9.9.9"
  → build -trimpath=true
```

The stamp itself survives. The linker materializes the string an `-X`
assignment writes as a symbol named for the variable with `.str` appended, so
`main.version` is still in the artifact as `main.version.str`. Reading it back
is the same fact from a different place — not an inference — which is why it
outranks the tag. The authority test is the identical one: the owning package
must be the main module's own tree or package `main`, and two surviving stamps
that disagree are both discarded.

This needs an unstripped binary. `-ldflags "-s -w"` removes `.symtab` and with
it the evidence, and then there is nothing here to read either — which is the
case on `rancher/nginx-ingress-controller`, where the binary is stripped and
recovery 3 is what answers instead. The technique is borrowed from trivy, which
added it for the same `-trimpath` reason; the selection rule around it is
vexscan's stricter one.

**3. The image tag,** which is a guess about the artifact rather than a fact
from it, and so is fenced much harder. The tag must normalize to full
`MAJOR.MINOR.PATCH` semver, *and* one of three things must connect it to this
module:

- **The image runs this module's binary.** The OCI config's `Entrypoint` and
  `Cmd` say what the image exists to do, so an image whose command is
  `/nginx-ingress-controller` is that module's image whatever it has been
  named. This is evidence where the two tests below are inference, so it is
  tried first.
- **The tag carries a k3s/rke2 build suffix** (`+k3s1`, `+rke2r1`) — those
  projects' own release markers, valid whatever the image is called, including
  a private mirror or a retag.
- **The image is named after the module** (`prom/prometheus`,
  `rancher/hardened-kubernetes`), the weakest of the three.

Nothing connects `python:3.12.1` to a Go binary that happens to live inside it,
so no version is inferred there.

The entrypoint test is what `registry.rancher.com/rancher/nginx-ingress-controller`
needs. Its binary is stripped and built with `-trimpath`, so recoveries 1 and 2
both come up empty, and the name test cannot help either: the module is
`k8s.io/ingress-nginx` and no dash-separated token of `nginx-ingress-controller`
equals `ingress-nginx`. The image's `Cmd` names the binary outright, and
`--all` on `v1.15.1-prime11` goes from 61 findings to 10 — including
CVE-2025-1974, CVE-2025-1098, CVE-2025-1097 and CVE-2023-5044, all fixed long
before 1.15.1.

Authority is decided per *module*, not per file, which is the same shape the
name tests have. That image ships three binaries built from `k8s.io/ingress-nginx`
— the controller, `/dbg` and `/wait-shutdown` — and runs one; the tag states
that project's version in all three, since they are one build of one checkout.

Reading the command stops at the first option, because everything after one is
that program's arguments rather than another thing the image runs: `/coredns
-conf /etc/coredns/Corefile` runs `coredns` and reads a file. A bare `--` is
stepped over instead, since it is how the init shims that so often occupy
`argv[0]` hand off — the ingress-nginx image runs `catatonit -- /nginx-ingress-controller`,
and the binary that matters is on the far side of it. A shell entrypoint names
only the shell and so grants nothing: `rancher/klipper-helm` runs a script
called `entry`, and the Go binaries beside it get no authority from it.

**4. The main module's own release, for a vendored staging module.** A monorepo
that publishes some of its own subdirectories as separate modules wires them up
with a directory replace — `replace k8s.io/apimachinery =>
./staging/src/k8s.io/apimachinery` — and there is no tag on a directory, so the
*dependency* is stamped `(devel)` too. On
`rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821`, `go version -m
/usr/local/bin/kubectl` reports a real `k8s.io/kubernetes v1.36.4+dirty` and
nine staging modules at `(devel)`:

```
mod  k8s.io/kubernetes    v1.36.4+dirty
dep  k8s.io/api           (devel)
dep  k8s.io/apimachinery  (devel)
dep  k8s.io/client-go     (devel)
... six more
```

Kubernetes' convention here is exact and published: the staging module cut
alongside `k8s.io/kubernetes vX.Y.Z` is released as `v0.Y.Z`. So `v1.36.4`
gives `k8s.io/apimachinery v0.36.4`, a real tag on the module proxy and a
version OSV ranges against cleanly. This is fenced to `k8s.io/kubernetes` at
major 1 with a `k8s.io/*` dependency that is itself uncomparable — which is
precisely the staging set, since `k8s.io/klog`, `k8s.io/utils` and
`k8s.io/kube-openapi` live in their own repositories and so state real versions
already.

Without it, `GO-2022-0965` — unbounded recursion in JSON parsing, **fixed in
September 2019** — comes back HIGH against a 2026 build of Kubernetes, once per
binary, alongside every other advisory ever filed against those nine modules.

**When no recovery applies, the module is not silently believed either.** A
version that reads too *high* ranges past a real advisory and marks a vulnerable
binary clean, which is the one direction this tool must never go, so every gate
above fails closed. The component is kept under its uncomparable version —
dropping it would leave a module nothing could decide looking like a module
with nothing filed against it — and its **affected verdicts are demoted to
`undetermined`** with reason `version_not_range_matchable`. The report counts
them in a `NOTE` and names the modules.

Only the affected verdicts move. A `not_present` finding was decided by reading
the binary's symbol table: the vulnerable package is not linked, which is true
at every version, so an uncomparable version takes nothing away from it.

**Every recovered version is on the finding.** Findings decided against one
carry an evidence entry naming both the version and where it came from —
`ldflags-version` with the exact `-X` key, `elf-symbol-version` with the `.str`
symbol it was read from, `image-tag-version` with the tag and why the tag was
believed, or `staging-module-version` with the main-module release it was
derived from — so no reader has to take a version build info never stated on
trust.

On the k3s binary above, the two mechanisms compose: the ldflags stamp turns
`(devel)` into `v1.36.2+k3s1`, which is a version the correction below can then
actually reason about. Four advisories become none, and the two that OSV still
matched are named in `corrections` rather than dropped.

### Advisories that cannot say where the flaw was fixed

**Some Go advisories cannot state where the flaw was fixed, and are corrected
against their own data.** The Go vulnerability database imports records it does
not curate and marks them `review_status: UNREVIEWED`. When such a record's
versions are not expressible as Go module versions — the normal case for a v2+
project whose module path carries no `/v2` suffix, so its only publishable
versions are `+incompatible` ones — it publishes a range that is open at the
top:

```json
"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
```

and parks the versions it could not translate in
`affected[].ecosystem_specific.custom_ranges`. An open range matches every
version forever. On `rancher/rancher:v2.15.0` that is 27 advisories against the
image's own module, every one of them fixed years earlier.

vexscan reads the record's own `custom_ranges` and sets the match aside — but
only when the query was for Go, the record is `UNREVIEWED`, its standard ranges
carry no `fixed` or `last_affected`, every version in `custom_ranges` parses,
the installed version is outside all of them, and no *other* record in the same
OSV answer corroborates the match. That last gate is what makes it two sources
rather than one record reinterpreted: OSV returns every record matching the same
package and version together, so an aliased GHSA that agrees is right there in
the response. Records in the same degraded shape do not count as corroboration —
`rancher/rancher` really does have pairs like `GO-2024-2929`/`GO-2024-3220`,
aliases of each other and both open at the top, which is one importer twice.

**Nothing is set aside quietly.** Every drop is counted, named and printed
above the findings, and carried in `corrections` in the JSON, because a report
27 findings shorter than the database offered must never be mistakable for a
cleaner image. A record with an open range and *no* `custom_ranges` offers
nothing better and is reported as found — on `rancher:v2.15.0` that is
`GO-2024-2761`, which is why the count is 27 and not 28.

Trivy solves the same problem by discarding govulndb for everything except
`stdlib` and `golang.org/x/*` and taking third-party Go modules from GHSA
instead ([trivy-db#675](https://github.com/aquasecurity/trivy-db/issues/675)).
That is why trivy reports nothing here. It is also why it reports nothing for a
module GHSA has no record of.

