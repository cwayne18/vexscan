---
sidebar_position: 20
title: "Flags"
---


| Flag | Default | Description |
|---|---|---|
| `--image` | | Container image to inspect; repeatable |
| `--images-from` | | Scan every image named in this list — a file with one reference per line, a [hauler manifest](./guides/haul.md#hauler-manifests-as-a-list---images-from), a [Kubernetes manifest](./guides/fleet.md#kubernetes-manifests-as-a-list), a URL, or `-` for stdin. `#` comments allowed, repeats scanned once — see [Scanning a fleet](./guides/fleet.md) |
| `--haul` | | Scan every image inside a [hauler haul](./guides/haul.md) without a registry — a `.tar.zst`, a tar, or an unpacked store directory. Charts and files in the haul are counted and named on stderr, never dropped silently |
| `--rootfs` | | Filesystem tree already on disk to inspect — see [`--rootfs`](./guides/rootfs.md) |
| `--repo` | | Git source repo to analyze: govulncheck source mode for Go, lock file inventory for Python and npm |
| `--sbom` | | CycloneDX JSON bill of materials to scan — a path, or `-` for stdin. Every finding is `undetermined`; see [`--sbom`](./guides/sbom.md) |
| `--rpm` | | RPM package file to scan without installing it — a path, a directory of them, or a URL; repeatable. Reads only the header, so a URL costs kilobytes not megabytes — see [`--rpm`](./guides/package-files.md) |
| `--rpm-deep` | `false` | With `--rpm`, decompress the payload and extract its ELF objects so the `elf-dynsym-absent` test can run. Needs `--mine-advisories --llm`; downloads the whole package; never runs the reachability closure — see [`--rpm-deep`](./guides/package-files.md#looking-inside-the-package---rpm-deep) |
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
| `--vexhub` | | VEX Repository to check findings against, e.g. `https://github.com/rancher/vexhub` (also a raw base URL or a local directory); repeatable, earliest wins — see [VEX hubs](./output/vex-sources.md) |
| `--distro-feeds` | SUSE on | Clear OS-package false positives with the distribution's own security feed: a vendor not-affected or an already-shipped fix moves a row to `ALREADY VEXED`, and like `--vexhub` never changes a `status`. SUSE's CSAF-VEX runs by default for SUSE images (it declines every other image and touches no network for one); `--distro-feeds` additionally consults the opt-in feeds (Debian's tracker today), and `--distro-feeds=false` consults none. Network — see [Distribution security feeds](./output/vex-sources.md#distribution-security-feeds---distro-feeds) |
| `--vex-out` | | Write `not_affected` documents for the findings ruled out into this directory, laid out as a VEX hub; with `--vexhub` they are merged into what that hub publishes, so it can be a clone of it — see [Contributing ruled-out findings back](./output/vex-output.md) |
| `--vex-author` | | With `--vex-out`, the author to record on the statements — **required**, and an error without `--vex-out` |
| `--vex-format` | `openvex` | With `--vex-out`, the serialisation to write: `openvex` or `csaf`. A hub indexes one document per product, so a product the hub already publishes in the other format is left untouched with a `warning:` — see [Writing CSAF instead](./output/vex-output.md#writing-csaf-instead---vex-format) |
| `--vex-merge-into` | | With `--vex-out`, also add every statement to this merged "master" document in the hub, e.g. `reports/rancher.openvex.json`; repeatable, never added to `index.json`, OpenVEX only. A named aggregate that cannot be written fails the run — see [Merged "master" reports](./output/vex-output.md#merged-master-reports---vex-merge-into) |
| `--vex-publisher-namespace` | | With `--vex-format csaf`, the URI identifying the publisher, e.g. `https://acme.example` — **required** for CSAF, and an error without it |
| `--vex-publisher-category` | `other` | With `--vex-format csaf`, the CSAF publisher category: `coordinator`, `discoverer`, `other`, `translator`, `user`, `vendor` |
| `--severity` | *(all)* | Only report findings at these severities: `CRITICAL`, `HIGH`, `UNKNOWN`, `MEDIUM`, `LOW`, `NONE`; comma-separated or repeatable. `UNKNOWN` must be named to be shown — see [Filtering by severity](./output/severity-and-filtering.md#filtering-by-severity---severity) |
| `--fixed-only` | `false` | Only report findings a fix has been published for. Prints how many it hid and how many of those are AFFECTED — see [Filtering to what you can fix](./output/severity-and-filtering.md#filtering-to-what-you-can-fix---fixed-only) |
| `--triage` | `false` | Order findings by exploitation evidence — EPSS scores and CISA's known-exploited catalog. Adds two columns and re-sorts; hides nothing and changes no severity — see [Prioritising by exploitation evidence](./output/severity-and-filtering.md#prioritising-by-exploitation-evidence---triage) |
| `--dlopen-policy` | `taint` | `taint` (block conclusions) or `assume-none` |
| `--dlopen-assume-none` | | The narrow form of the above: assert that one named `dlopen` caller loads nothing that matters, by path or SONAME. Repeatable, and an error alongside `--dlopen-policy=assume-none`. A name matching no caller discharges nothing and is reported — see [Waving off one caller](./how-the-tests-work.md#waving-off-one-caller---dlopen-assume-none) |
| `--exec-policy` | `taint` | The same knob for a Go entrypoint that links a process-spawning call. `assume-none` asserts that what it runs is accounted for — name those with `--roots` — see [The exec probe](./how-the-tests-work.md#the-exec-probe---exec-policy) |
| `--dynamic-import-policy` | `taint` | The same knob for a language import graph's computed imports. These are far more common than `dlopen`, so `assume-none` discards much more |
| `--trust-import-absence` | `false` | Let a missing dynamic import conclude `not_in_execute_path` (weaker than it looks) |
| `--os` / `--arch` | `linux` / `amd64` | Image platform variant to pull (image mode only) |
| `--llm` | `false` | Consult a chat model on genuinely-affected CVEs; needs a provider below |
| `--llm-endpoint` | | OpenAI-compatible chat/completions URL — an API provider or a local Ollama |
| `--llm-model` | `gpt-4o` | Model id for `--llm-endpoint` |
| `--llm-command` | | Run this installed CLI instead of an endpoint, e.g. `'claude -p'` |
| `--mine-advisories` | `false` | With `--llm`, mine advisory prose for symbols and module paths to check |
| `--format` | `text` | `text`, `summary`, `json`, `sarif`, `fixplan`, or `inventory` |
| `--details` | `false` | With `--format text`, print the full evidence block under each row instead of the table alone |
| `--out` | *(stdout)* | Write output to a file |
| `--gist` | `false` | Also upload the output to a public gist and print its URL (token needs `gist` scope) |
| `--gist-secret` | `false` | With `--gist`, create a secret (unlisted) gist |
| `--fail-on` | | Exit `3` if a counted finding is at or above this severity, or `any`. Off by default — see [Gating a pipeline](./output/machine-formats.md#gating-a-pipeline---fail-on) |
| `--fail-on-status` | `affected` | What `--fail-on` weighs: a comma-separated list of `affected`, `undetermined`, `vexed`, `cleared`, or `all` |
| `--color` | `auto` | `auto`, `always`, or `never`. `auto` colours only a terminal — never a pipe, a `--out` file, a `--gist`, JSON, or a run with `NO_COLOR` set — see [Colour](./output/reports.md#colour---color) |
| `--no-pager` | `false` | Never page the output, even when stdout is a terminal — see [Reading a long report](./output/reports.md#reading-a-long-report) |
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

`GITHUB_TOKEN` / `GH_TOKEN` are for `--gist` (gist scope), and are unchanged.
`--vex-out` needs no credential: it writes to the filesystem, and reads the hub
over the same read-only path `--vexhub` uses.

