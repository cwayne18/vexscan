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

**Every ecosystem brings its own deterministic presence test.** An LLM never
decides a status; it only comments on what the deterministic tests could not
rule out.

| Ecosystem | Selector | Deterministic test |
|---|---|---|
| Go modules and stdlib | `--package golang:PATH` | pclntab dead-code-elimination evidence; govulncheck call-graph reachability |
| OS packages (deb, rpm, apk) | `--package deb:NAME` etc. | package-database inventory; the dynamic linker's `DT_NEEDED` closure from the entrypoint (or `--roots`) |
| Python (PyPI) | `--package pypi:NAME` | `dist-info`/`RECORD` inventory; a static import closure from the entrypoint (or `--roots`) |
| npm | `--package npm:NAME` | `node_modules` manifest inventory; a static require/import closure from the entrypoint (or `--roots`) |
| Java (Maven) | `--package maven:GROUP:ARTIFACT` | jar/war/ear coordinate inventory; class presence in the archive's central directory |

`vexscan` was previously released as `gomod-vex`, which did the Go half only.
Existing `--module` command lines and `GOMODVEX_*` environment variables keep
working.

## Documentation

Full documentation lives at **<https://cwayne18.github.io/vexscan/>** (source in
[`docs/`](./docs)):

- [Quick start](https://cwayne18.github.io/vexscan/quick-start)
- [Selecting what to check](https://cwayne18.github.io/vexscan/selecting-what-to-check)
- [Scanning targets](https://cwayne18.github.io/vexscan/guides/) — fleets, hauler hauls, filesystems, package files, SBOMs
- [How the tests work](https://cwayne18.github.io/vexscan/how-the-tests-work)
- [Known limits](https://cwayne18.github.io/vexscan/known-limits) — **read this before trusting a clean answer**
- [Output and reporting](https://cwayne18.github.io/vexscan/output/) — severity, triage, VEX, JSON, SARIF, pipeline gating
- [Flags reference](https://cwayne18.github.io/vexscan/flags)

## Quick start

```sh
# Where does this CVE land, anywhere in the image? (searches every ecosystem)
vexscan --image debian:12 --cves CVE-2024-5535

# One Go module in a container image
vexscan --image rancher/hardened-kubernetes:v1.30.1 \
  --package golang:golang.org/x/net --cves CVE-2023-39325,CVE-2023-44487

# One OS package, with the shared-library closure as the presence test
vexscan --image debian:12 --package deb:openssl

# Everything a selected ecosystem can enumerate
vexscan --image registry.access.redhat.com/ubi9/ubi:latest --all --ecosystem os

# A whole fleet in one run: one row per image, advisories fetched once
vexscan --images-from fleet.txt --format summary

# A hauler haul, scanned inside the airgap it was carried into — no registry
vexscan --haul rke2-airgap.tar.zst --all --format summary

# A filesystem tree rather than an image (no entrypoint, so pass --roots)
vexscan --rootfs /mnt/rootfs --all --roots /usr/bin/myapp

# An RPM nobody installed — a file, a directory of them, or a URL
vexscan --rpm ./openssl-libs-3.5.5-2.el9_8.x86_64.rpm --all

# A CycloneDX bill of materials, from a file or a pipe
vexscan --sbom sbom.cdx.json --all
```

See the [Quick start](https://cwayne18.github.io/vexscan/quick-start) for the
full set of examples, including source repos, inventory listing, and alternate
advisory sources.

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
```

See [Requirements](https://cwayne18.github.io/vexscan/requirements) and
[Install](https://cwayne18.github.io/vexscan/install) for details.

## License

MIT — see [LICENSE](./LICENSE).
