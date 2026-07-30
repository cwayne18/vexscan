# vexscan

`vexscan` answers one question, for a container image or a source repo: **is
this CVE's vulnerable code actually present, and can it actually run?**

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
| OS packages (deb, rpm, apk) | `--package deb:NAME` etc. | package-database inventory; the dynamic linker's `DT_NEEDED` closure from the image entrypoint |
| Python (PyPI) | `--package pypi:NAME` | `dist-info`/`RECORD` inventory; a static import closure from the image entrypoint |
| npm | `--package npm:NAME` | `node_modules` manifest inventory; a static require/import closure from the image entrypoint |

Python and npm answer a **narrower** question than Go does, and the tool is
built to say so rather than to guess. Neither language removes dead code at
build time, so `not_present` can only mean "not installed"; reachability is the
one remaining lever, and it is blocked far more often than the `DT_NEEDED`
closure is. Read [Known limits](#known-limits--read-this-before-trusting-a-result)
before trusting a clean answer from either.

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

# Source repo (govulncheck source-mode reachability)
vexscan --repo github.com/rancher/rancher \
  --package golang:golang.org/x/net --cves CVE-2023-39325

# Source repo, lock file inventory (no import graph — see below)
vexscan --repo github.com/npm/cli --all --ecosystem npm

# Just list what is installed, with the names OSV will be queried by
vexscan --image debian:12 --format inventory
```

## Selecting what to check

A `--package SPEC` is a purl, an `ecosystem:name` shorthand, or a bare name
resolved against whatever inventory contains it:

```
golang:golang.org/x/net    deb:openssl    apk:musl    rpm:glibc    openssl
pypi:PyYAML    npm:@babel/core
pkg:golang/golang.org%2Fx%2Fnet@v0.17.0    pkg:pypi/pyyaml@6.0.3    pkg:npm/%40babel/core@7.24.0
```

`deb`, `dpkg`, `rpm` and `apk` are package *formats* rather than OSV ecosystem
names; they all select the OS plugin, which is the only thing that could answer
them. `go` is accepted for `golang`, `std` for `stdlib`, `python` and `pip` for
`pypi`, and `node` and `nodejs` for `npm`.

PyPI names are matched after PEP 503 normalization — lowercased, with runs of
`-`, `_` and `.` collapsed to a single `-` — so `PyYAML` and `pyyaml` select the
same distribution, as do `typing_extensions` and `typing-extensions`. npm names
are matched verbatim, scope included, because that is how the registry and OSV
key them.

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
| `no-entrypoint` | the image config has neither Entrypoint nor Cmd | same escalation |

`--roots /path/to/bin` adds entrypoints for an image whose real command comes
from outside its own config — a Kubernetes `command:`, a sidecar, an operator.
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
| `no-entrypoint` | no Entrypoint and no Cmd, or a bare interactive interpreter | same escalation |
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
(Red Hat CSAF, Debian tracker, Alpine secdb) rather than more heuristics. The
`evidence` array on every finding is the extension point for that: a future
vendor-feed source contributes `Evidence{Origin: "vendor-vex"}` alongside the
local evidence, under one policy — local deterministic evidence outranks a
vendor claim, and a vendor `not_affected` never downgrades a finding below
`linked` on its own.

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
  a [GitHub Models](https://github.com/marketplace/models) chat model gives an
  advisory `likely` / `unlikely` / `unknown` exploitability verdict, recorded
  under `llm` on the finding.
- **`--mine-advisories`** — lets the model read an advisory's prose and extract
  symbols, sonames, filenames and **module paths** worth checking. Distro OSV
  records give a fixed version and nothing about what inside the package is
  vulnerable, so for OS packages this is often the only route to a
  below-package-level answer. For Python and npm the mined value is a dotted
  module path or a package subpath — `yaml.constructor`, `lodash/template` — and
  it is the only route to a `not_present` for a distribution that is installed
  and does ship code, since neither language eliminates dead code at build time.

**Mined hints are contained, not trusted.** A hint may only support a
`not_affected`-flavored status *after validation*: it must appear literally in
the advisory text, and it must be found in something the package actually
installs — the **defined** `.dynsym` of one of its libraries for an OS package,
its own installed file list for a Python or npm module path. An unvalidatable
mined hint is indistinguishable from a hallucination and is recorded as
inconclusive, so a hallucinated hint is inert rather than dangerous.

The Python and npm validations additionally defer to any blocking taint, and to
a file list that had to be reconstructed rather than read. Both are cases where
"the module is not here" could equally mean "we did not look in the right
place".

`elf-import-absent`, `py-import-absent` and `npm-import-absent` — reachable, but
nothing imports the vulnerable symbol or module — stay evidence-only unless you
pass `--trust-import-absence`. Absence of a *direct* import does not prove
unreachability, because the vulnerable code is usually called from inside the
same library or package.

GitHub Models enforces a low per-minute burst limit, so a scan assessing many
CVEs can hit `429 Too Many Requests` (sometimes phrased as a Terms of Service or
"scraping" notice — that is GitHub's secondary rate limit). `vexscan` caches
verdicts per CVE, spaces requests out (default 1s), and retries `429`/`5xx` with
backoff honoring `Retry-After` up to two minutes. A failed assessment is
non-fatal: the finding is still reported, just without a verdict.

## Output

`--format text` is for reading; `--format json` is for keeping. The JSON is
`schema_version: 2`:

```jsonc
{
  "schema_version": 2,
  "target": "...", "mode": "image",
  "findings": [ /* flat, sorted — jq '.findings[]' still works */ ],
  "ecosystems": [ { "id": "os", "components": 65, "error": "" } ]
}
```

Each finding carries ecosystem-neutral identity (`ecosystem`, `id`, `package`,
`version`, `location`, `purl`) plus `status`, `method`, `justification` and
`evidence`. The v1 Go spellings (`cve`, `module`, `binary`, `go_id`, `packages`,
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
the text report prints an `INCOMPLETE:` line, and the process exits 1. A CVE id
that matched no component anywhere still appears once, as `undetermined` with
`no_component_matched`, so a missing id never reads as a clean one.

`--format inventory` is a third output: every OS database and language ecosystem
the target carries, each under the directory it was read from, with the file
count and the names OSV will be queried by. It is the fastest way to check that
a reader found what you expected before trusting a finding — or an absent one.

Exit status: `0` the scan completed, `1` the scan failed or an ecosystem could
not be read, `2` the command line was wrong.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--image` | | Container image to inspect (mutually exclusive with `--repo`) |
| `--repo` | | Git source repo to analyze: govulncheck source mode for Go, lock file inventory for Python and npm |
| `--package` | | Package to check: purl, `ecosystem:name`, or bare name; repeatable |
| `--cves` | | CVE / GHSA / GO / RHSA / DSA ids; alone, resolved against the whole target |
| `--all` | `false` | Check everything each ecosystem can enumerate |
| `--ecosystem` | *(all)* | Restrict to these ecosystems (`golang`, `os`, `pypi`, `npm`, or a distro family); repeatable |
| `--module` | | **Deprecated** alias for `--package golang:MODULE` |
| `--cves-file` | | File with one id per line (merged with `--cves`; `#` comments allowed) |
| `--ref` | *(default branch)* | Branch, tag, or commit to check out for `--repo` |
| `--repo-path` | `.` | Subdirectory within `--repo` to scan — the Go module, or the directory holding the lock files |
| `--version` | *(auto)* | Override the module version (image mode) instead of reading build info |
| `--go-version` | *(auto)* | Pin the Go toolchain for `--repo`, e.g. `1.24.0` (useful with `golang:stdlib`) |
| `--osv-ecosystem` | *(auto)* | Override the OSV ecosystem derived from os-release, e.g. `Debian:12` |
| `--roots` | | Extra entrypoints for the closures — shared libraries and language imports; repeatable |
| `--dlopen-policy` | `taint` | `taint` (block conclusions) or `assume-none` |
| `--dynamic-import-policy` | `taint` | The same knob for a language import graph's computed imports. These are far more common than `dlopen`, so `assume-none` discards much more |
| `--trust-import-absence` | `false` | Let a missing dynamic import conclude `not_in_execute_path` (weaker than it looks) |
| `--os` / `--arch` | `linux` / `amd64` | Image platform variant to pull |
| `--llm` | `false` | Consult a GitHub Models LLM on genuinely-affected CVEs |
| `--llm-model` | `openai/gpt-4o` | GitHub Models model id for `--llm` |
| `--mine-advisories` | `false` | With `--llm`, mine advisory prose for symbols and module paths to check |
| `--format` | `text` | `text`, `json`, or `inventory` |
| `--out` | *(stdout)* | Write output to a file |
| `--gist` | `false` | Also upload the output to a public gist and print its URL (token needs `gist` scope) |
| `--gist-secret` | `false` | With `--gist`, create a secret (unlisted) gist |
| `--quiet` | `false` | Suppress progress logging on stderr |

`--gist` uploads whatever would otherwise be printed, respecting `--format`,
using the same `GITHUB_TOKEN` / `GH_TOKEN` as `--llm`. It composes with `--out`
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
| `VEXSCAN_LLM_MIN_INTERVAL` | `GOMODVEX_LLM_MIN_INTERVAL` | Minimum spacing between `--llm` calls (Go duration; `0` disables) |
| `VEXSCAN_GOVULNCHECK_VERSION` | `GOMODVEX_GOVULNCHECK_VERSION` | Pin the govulncheck version used by `--repo` |

`GITHUB_TOKEN` / `GH_TOKEN` are unchanged.

## Requirements

- [`skopeo`](https://github.com/containers/skopeo) on `PATH` — image mode
- A Go toolchain on `PATH` — required at **runtime** for `--repo`, which builds
  and runs `govulncheck` itself via `go run` with `GOTOOLCHAIN=auto`
- `git` on `PATH` — repo mode, unless scanning a local path
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on
  `PATH` — optional, used only for Go binary mode
- Network access for OSV lookups, and for `--repo` cloning
- `GITHUB_TOKEN` / `GH_TOKEN` for `--llm` and `--gist`

All three package databases are parsed in-process — no `dpkg`, `rpm` or `apk`
binary is needed. So are the Python and npm inventories and lock files: no
`python`, `pip`, `node` or `npm` is required, and nothing from the target is
ever executed.

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

docker run --rm -e GITHUB_TOKEN ghcr.io/cwayne18/vexscan:latest \
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
- **Repo mode for Python and npm resolves no import graph at all.** A lock file
  answers "is this declared" and, where the format says so, "is it
  development-only". Nothing there speaks to reachability, and a `linked`
  finding says as much in its own text.
- When OSV publishes no package-level import paths for a Go advisory (some
  GitHub-only GHSA records), presence is asserted at **module** granularity;
  those findings say `granularity: module` and are coarser.

## License

MIT — see [LICENSE](./LICENSE).
