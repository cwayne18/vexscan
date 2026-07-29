# vexscan

`vexscan` checks whether a given CVE in a Go module is **actually present and
reachable**, rather than merely being listed as a dependency. Point it at either:

- a **container image** (`--image`) — inspects the shipped Go binaries, or
- a **source repository** (`--repo`) — clones it and runs govulncheck's
  call-graph reachability analysis.

It is a generic, Go rewrite of the `vex_candidates.py` triage script from
[`cwayne18/rke2-toolbox`](https://github.com/cwayne18/rke2-toolbox): instead of
parsing a Trivy scan report, you point it directly at a target, a module, and
(optionally) a list of CVEs.

Package/CVE scanners flag a module as vulnerable whenever the *module* is a
dependency, even if the linker dead-code-eliminated the vulnerable *package* or
the vulnerable functions are never reachable. `vexscan` distinguishes those
cases so you can produce accurate [VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
statements.

## How it works

### Image mode (`--image`)

For every Go binary in the image that links the target module, `vexscan`:

1. **Resolves the vulnerable packages** from the [OSV](https://osv.dev) Go
   database, keyed by module + the version embedded in the binary's build info.
2. **govulncheck (binary mode)** — for non-stripped binaries, a linked but
   unreachable package is reported `vulnerable_code_not_in_execute_path`.
3. **pclntab presence test** — a Go binary keeps its function-name table even
   when fully stripped (`-ldflags=-s -w`). If none of a CVE's vulnerable
   packages appear in it, the linker eliminated them:
   `vulnerable_code_not_present`.

Module versions are read straight from each binary's embedded build info
(`debug/buildinfo`), so no Trivy report or manual version input is required.

### Repo mode (`--repo`)

The repo is cloned (shallow) and analyzed with **govulncheck source mode**,
whose call-graph reachability is authoritative for a source tree — strictly
better than the pclntab heuristic (which only exists because shipped binaries
are stripped). Each advisory in the dependency graph is classified as
`reachable` (the vulnerable symbol is actually called),
`not_in_execute_path` (imported but unreachable) or `not_present` (unused).
A local checkout path or `file://` URL is scanned in place without cloning.

> **Large repos:** source-mode analysis builds a whole-program call graph and can
> need several GB of RAM. Very large repos (e.g. `rancher/rancher`) may exhaust
> memory — govulncheck gets OOM-killed (`signal: killed`). Give the process more
> memory (in a container, raise the memory limit, e.g. `docker run --memory=8g`),
> scope the scan with `--repo-path <subdir>`, or fall back to `--image` mode.

### Standard library (`--module stdlib`)

Go standard-library CVEs are supported in both modes — pass `--module stdlib`
(the name OSV and govulncheck use; `--module std` is accepted as an alias):

```sh
# Image mode: the Go version comes from each binary's build info, and pclntab
# tells you which vulnerable stdlib packages (net/http, crypto/x509, ...) are
# actually linked into each binary.
vexscan --image myorg/app:latest --module stdlib --cves CVE-2025-22870

# Repo mode: govulncheck reports stdlib reachability. Results depend on the Go
# toolchain used, so pin it with --go-version to target a specific release.
vexscan --repo github.com/rancher/rancher --module stdlib --go-version 1.24.0
```

In repo mode the stdlib version analyzed is the one of the Go toolchain that
runs govulncheck. `GOTOOLCHAIN=auto` only ever *upgrades*, so without
`--go-version` a repo is scanned with the newest locally-available toolchain
(inside the container image, the base Go version). Pin `--go-version` to assess
a particular release. Note that a pinned older toolchain may be too old to build
the latest `govulncheck`; pair it with `VEXSCAN_GOVULNCHECK_VERSION` (e.g.
`v1.1.4`) if `go run` reports a version requirement.

### LLM exploitability check (optional, `--llm`)

For CVEs whose vulnerable code is genuinely linked (image mode) or reachable
(repo mode), a [GitHub Models](https://github.com/marketplace/models) chat model
gives an advisory `likely` / `unlikely` / `unknown` exploitability verdict.

GitHub Models enforces a low per-minute burst limit, so a scan that assesses
many CVEs can hit `429 Too Many Requests` (sometimes phrased as a Terms of
Service / "scraping" notice — that is GitHub's secondary rate limit). `vexscan`
mitigates this by:

- **caching verdicts** per CVE — in image mode the same CVE linked into many
  binaries is assessed once and reused;
- **spacing out requests** (default 1s between calls); tune or disable this with
  `VEXSCAN_LLM_MIN_INTERVAL` (a Go duration, e.g. `2s`, or `0` to disable);
- **retrying** `429`/`5xx` with backoff, honoring the server's `Retry-After`
  (up to two minutes) so a rate-limit window is actually outlasted.

A failed assessment is non-fatal: the finding is still reported (e.g. `LINKED`),
just without an LLM verdict.

### Environment variables

`vexscan` was previously released as `gomod-vex`. Its own variables are now
prefixed `VEXSCAN_`, and the corresponding `GOMODVEX_` names are still honored
as a fallback so existing CI configuration keeps working:

| Variable | Legacy name | Purpose |
|---|---|---|
| `VEXSCAN_LLM_MIN_INTERVAL` | `GOMODVEX_LLM_MIN_INTERVAL` | Minimum spacing between `--llm` API calls (Go duration; `0` disables) |
| `VEXSCAN_GOVULNCHECK_VERSION` | `GOMODVEX_GOVULNCHECK_VERSION` | Pin the govulncheck module version used by `--repo` |

`GITHUB_TOKEN` / `GH_TOKEN` are unchanged.

## Requirements

- A Go toolchain on `PATH` (also required at **runtime** for `--repo` source
  analysis). Repo mode builds and runs `govulncheck` itself via `go run` with
  `GOTOOLCHAIN=auto`, so Go will fetch whatever toolchain the scanned module
  requires — no manual version matching needed.
- [`skopeo`](https://github.com/containers/skopeo) on `PATH` — image mode
- `git` on `PATH` — repo mode (unless scanning a local path)
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on `PATH`
  — used only in image (binary) mode; optional. Repo mode does not need it
  preinstalled.
- Network access for `--repo` (to clone, download the module graph, and fetch a
  toolchain if the module needs a newer Go than is installed)
- `GITHUB_TOKEN` (or `GH_TOKEN`) when using `--llm` (or `--gist`; that also needs
  `gist` scope)

## Install

```sh
go install github.com/cwayne18/vexscan@latest
```

Or build from source:

```sh
git clone https://github.com/cwayne18/vexscan
cd vexscan
go build -o vexscan .
```

### Container image (GHCR)

A self-contained image bundling `skopeo`, `git`, `govulncheck` and a Go
toolchain (so both image and repo modes work) is published to
[`ghcr.io/cwayne18/vexscan`](https://github.com/cwayne18/vexscan/pkgs/container/vexscan)
on every push to `main` and every `v*` tag:

```sh
docker run --rm ghcr.io/cwayne18/vexscan:latest \
  --image rancher/hardened-coredns:v1.14.6 \
  --module golang.org/x/net --cves CVE-2023-39325
```

Pass a token through the environment to enable `--llm`:

```sh
docker run --rm -e GITHUB_TOKEN ghcr.io/cwayne18/vexscan:latest \
  --image myorg/myapp:latest --module golang.org/x/crypto --llm
```

## Usage

```sh
vexscan --image REF  --module PATH [--cves LIST] [flags]   # image mode
vexscan --repo  REPO --module PATH [--cves LIST] [flags]   # repo mode
```

Check two specific `x/net` CVEs in an image:

```sh
vexscan \
  --image rancher/hardened-kubernetes:v1.30.1-rke2r1 \
  --module golang.org/x/net \
  --cves CVE-2023-39325,CVE-2023-44487
```

Check a CVE against a source repo via reachability analysis:

```sh
vexscan \
  --repo github.com/rancher/rancher \
  --module golang.org/x/net \
  --cves CVE-2023-45288
```

`--repo` accepts `github.com/owner/repo`, a full clone URL, a bare
`owner/repo` (assumed GitHub), or a local checkout path / `file://` URL. Use
`--ref` for a branch, tag or commit and `--repo-path` for a module in a
subdirectory.

Check every advisory known for `x/crypto`, as JSON, with the LLM layer:

```sh
export GITHUB_TOKEN=...    # a token with models:read
vexscan \
  --image myorg/myapp:latest \
  --module golang.org/x/crypto \
  --llm --format json
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--image` | | Container image to inspect (mutually exclusive with `--repo`) |
| `--repo` | | Git source repo to analyze via govulncheck source mode |
| `--ref` | *(default branch)* | Branch, tag, or commit to check out for `--repo` |
| `--repo-path` | `.` | Module subdirectory within `--repo` to scan |
| `--module` | *(required)* | Go module import path to evaluate (or `stdlib` for the standard library) |
| `--cves` | *(all)* | Comma-separated CVE / GHSA / GO ids; empty checks every advisory for the version |
| `--cves-file` | | File with one id per line (merged with `--cves`; `#` comments allowed) |
| `--version` | *(auto)* | Override the module version (image mode) instead of reading build info |
| `--go-version` | *(auto)* | Pin the Go toolchain for `--repo` analysis, e.g. `1.24.0` (useful with `--module stdlib`) |
| `--os` / `--arch` | `linux` / `amd64` | Image platform variant to pull (image mode) |
| `--llm` | `false` | Consult a GitHub Models LLM on genuinely-affected CVEs |
| `--llm-model` | `openai/gpt-4o` | GitHub Models model id for `--llm` |
| `--format` | `text` | `text` or `json` |
| `--out` | *(stdout)* | Write output to a file |
| `--gist` | `false` | Also upload the output to a public GitHub gist and print its URL (needs a token with `gist` scope) |
| `--gist-secret` | `false` | With `--gist`, create a secret (unlisted) gist instead of a public one |
| `--quiet` | `false` | Suppress progress logging on stderr |

Exactly one of `--image` or `--repo` is required.

`--gist` uploads whatever would otherwise be printed (respecting `--format`) to a
gist using the same `GITHUB_TOKEN` / `GH_TOKEN` as `--llm`; the token needs
`gist` scope. The gist URL is printed to stdout after the report. It composes
with `--out` (the report is written to the file *and* uploaded).

## Output statuses

| Status | Meaning | Suggested VEX justification |
|---|---|---|
| `not_present` | Vulnerable package absent (pclntab / govulncheck source) | `vulnerable_code_not_present` |
| `not_in_execute_path` | Linked/imported but govulncheck marks it unreachable | `vulnerable_code_not_in_execute_path` |
| `linked` | Vulnerable package genuinely linked, image mode (real finding) | *(none — treat as affected)* |
| `reachable` | Vulnerable symbol is called, repo mode (real finding) | *(none — treat as affected)* |
| `undetermined` | No mapping for the id at this version | *(manual review)* |

In image mode, when OSV publishes no package-level import paths for an advisory
(e.g. some GitHub-only GHSA records), presence is asserted at **module**
granularity instead; these are coarser, so validate before transferring.

## Caveats

- The LLM verdict is advisory only. Never auto-file a VEX statement solely on an
  LLM verdict; it supplements, and does not replace, the deterministic checks.
- pclntab matching (image mode) is a heuristic. It is deliberately conservative
  (a genuinely-linked package is never reported absent), but validate candidates
  before publishing VEX.
- Repo mode needs a Go toolchain, `git` and network access at runtime. It runs
  `govulncheck` via `go run` from inside the target module with
  `GOTOOLCHAIN=auto`, so Go automatically fetches a newer toolchain when the
  scanned module requires one. Override the govulncheck version with
  `VEXSCAN_GOVULNCHECK_VERSION` if needed.

## License

MIT — see [LICENSE](./LICENSE).
