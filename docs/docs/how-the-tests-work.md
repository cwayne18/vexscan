---
sidebar_position: 11
title: "How the tests work"
---


### Go, image mode

For every Go binary that links the target module:

1. **Resolve the vulnerable packages** from the [OSV](https://osv.dev) Go
   database, keyed by module plus the version embedded in the binary's build
   info (`debug/buildinfo`) — no Trivy report or manual version input needed.
   A binary's *own* main module often has no version there; see
   [when the main module says `(devel)`](./known-limits.md#when-the-main-module-says-devel).
2. **govulncheck (binary mode)**, for non-stripped binaries: linked but
   unreachable is `vulnerable_code_not_in_execute_path`.
3. **pclntab presence test.** A Go binary keeps its function-name table even
   when fully stripped (`-ldflags=-s -w`). If none of a CVE's vulnerable
   packages appear in it, the linker eliminated them:
   `vulnerable_code_not_present`.

> **govulncheck must be on `PATH`** for step 2. When it is not, non-stripped
> binaries cannot be narrowed to `not_in_execute_path`, so those findings stay
> `linked` — sound, but less precise than the tool can be. Rather than silently
> return a coarser answer, the run tags every finding it would have refined and
> prints a `NOTE:` in the report caveats telling you how many were affected and
> how to install it (`go install golang.org/x/vuln/cmd/govulncheck@latest`). The
> stripped-binary pclntab test in step 3 does not need it.

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
transitively from the image's Entrypoint and Cmd. Objects the dynamic loader
opens by name rather than by `DT_NEEDED` — `libnss_*`, PAM modules, gconv
converters, OpenSSL engines and providers, `*.node`, `site-packages/**/*.so` —
are rooted too, because nothing in the image points at them and a `DT_NEEDED`
closure would call every one of them dead code.

**Rooted by name, but not unconditionally.** A plugin is opened by one specific
library — NSS modules and gconv converters by `libc`, PAM modules by `libpam`,
engines and providers by `libcrypto` — so if the closure reaches no `libpam`,
nothing in the image contains the call that would open a PAM module, and rooting
one anyway is not conservative but wrong. Those four families are admitted only
once their loader is reached, as a fixpoint: a loader can itself arrive through a
plugin, so admission and the `DT_NEEDED` walk run to convergence together. The
other two families are loaded by a *program* — a `.node` addon by whatever
JavaScript runtime calls `require`, a `site-packages` extension by whatever is or
embeds CPython — and the set of programs that qualify is open-ended enough that
naming them would be a guess, so they are still rooted unconditionally.

The narrowing only ever applies to an image that said what it runs. An image
whose entrypoint is a shell, or absent, roots every program (see
[Taints](#taints)), which reaches the loaders, which admits every plugin — so the
case the gating could be wrong about is exactly the case it does not apply to. A
plugin left out is named in the evidence of any finding it would have decided,
along with the library that was missing:

```
libpam0g installs 2 ELF objects (/usr/lib/libpam.so.0, /usr/lib/security/pam_unix.so),
  and the dynamic linker would load none of them starting from /app/server
/usr/lib/security/pam_unix.so is a PAM module, and the closure reaches no libpam.so
  that could open it
```

On a SLE BCI 15.5 image with a pure-Go entrypoint this is the difference between
78 reachable objects and 1: `libpam`, `libcrypto`, `libselinux` and
`libkrb5support` were in the closure only through plugin roots, all four call
`dlopen`, and a `dlopen` taint is global — so 95 of the image's 107 OS findings
came back `linked`, 79 of them packages the closure had already shown it reaches
no object of.

| Situation | Status | Justification | Method |
|---|---|---|---|
| not installed at all | `not_present` | `component_not_present` | `pkgdb-inventory` |
| installed, owns no ELF (docs, data, scripts) | `not_present` | `vulnerable_code_not_present` | `pkgdb-no-code` |
| owns ELFs, none reachable, nothing blocking | `not_in_execute_path` | `vulnerable_code_not_in_execute_path` | `elf-needed-closure` |
| a validated mined symbol is defined by nothing the package installs | `not_present` | `vulnerable_code_not_present` | `elf-dynsym-absent` |
| reachable, or anything blocking | `linked` | *(none — treat as affected)* | `elf-needed-closure` |

#### Transparent exec wrappers

Before the entrypoint is judged a shell, transparent exec wrappers are peeled:
`tini`, `dumb-init`, `catatonit` (and their `--` separators), `gosu` / `su-exec`,
and `env` with its assignments and known flags. Each execs a specific later argv
token and loads no application code of its own, so peeling reaches the real
program and roots that instead of escalating — most of what runs Java and Node in
production sits behind one of these. Peeling only advances past a layer whose
argument grammar is parsed with certainty: `env -S`, `tini` with a bare option
and no `--`, or `gosu` with no command are left in place and fall back to the
`shell-entrypoint` escalation below. That fail-closed default is what keeps the
narrowing from ever hiding live code.

#### Taints

A taint never sets a status. It *blocks* the closure from concluding
`not_affected`, and is always emitted as evidence, so the report says why it
could not answer rather than answering wrongly.

A taint that stops blocking is still emitted. `--dlopen-policy=assume-none` and
the pure-Go discharge below both turn a blocker into a note, and the note is
the point: a clean verdict that something was cleared to reach is a different
claim from a clean verdict nothing ever threatened, and the evidence has to let
you tell them apart.

| Taint | Trigger | Effect |
|---|---|---|
| `unresolved-needed` | a `DT_NEEDED` that resolved to nothing | scoped to that soname |
| `dlopen` | a reachable ELF references `dlopen`/`dlmopen` | global, unless the caller is a bounded loader, is named by `--dlopen-assume-none`, or `--dlopen-policy=assume-none` is set |
| `static-elf` | a reachable ELF has no `PT_INTERP`/`.dynamic` | blocks all C-library conclusions, unless the entrypoint is a pure-Go build or its symbol table clears the advisory |
| `shell-entrypoint` | argv[0] is a shell or init shim (`sh`, `busybox`, `s6-*`), or a transparent wrapper (`tini`, `gosu`, `env`) used in a form its parser cannot read | every ELF in the standard bin dirs becomes a root — unless you assert past it, see below |
| `no-entrypoint` | the image config has neither Entrypoint nor Cmd — or there is no config at all, as in `--rootfs` mode | same escalation |
| `exec` | the entrypoint is a Go binary that links a process-spawning call | global, unless `--exec-policy=assume-none`; recorded as a discharged note when the binary provably links none |
| `missing-root` | a `--roots` path that names no ELF object in the image | global, always — see below |
| `inert-assertion` | a `--dlopen-assume-none` name that matched no `dlopen` caller | never blocks; reported so a typo is not invisible — see below |

**`missing-root`.** The one taint raised by what you said rather than by what
the image holds, and the one that most needs raising. `--roots` is how you
answer an `exec` taint — *it runs this, now conclude* — so a root that silently
went missing would take the closure down with it while
`--exec-policy=assume-none` discharged the taint that had been withholding the
answer. Measured on `rancher/mirrored-kube-vip-kube-vip-iptables:v1.2.3`, one
transposed character in `--roots /usr/sbin/xtables-nft-multi` flipped seven
OpenSSL CVEs from `linked` to `not_in_execute_path`, and the report was
byte-identical in size to the correct one.

So it blocks, globally, and it blocks *everything* for that image — including
the findings the correct run could have answered. Once a root is missing the
closure does not know what it missed, so it does not get to keep the answers it
happened to reach. The evidence names the path and says whether it was absent
or present-but-not-an-ELF-object, since pointing at a shell script instead of
the program it runs is a different mistake from a typo.

**Asserting past escalation.** Escalation and a *non-blocking* taint go
together, and it is worth seeing why. Rooting every program in the image cannot
under-report — there is nothing left for the unknown entrypoint to reach — so
there is nothing to withhold, and the taint is a note rather than a block. That
bargain is also why escalation is so expensive: on
`rancher/hardened-calico:v3.28.1`, a `/bin/bash` entrypoint rooted **491 of 668
objects**, and 144 of 145 OS findings came back reachable no matter what you
knew about the image.

You can buy your way out, but only with both halves of the assertion:

```
--roots /usr/bin/calico-node --exec-policy=assume-none
```

`--roots` alone is not enough, and neither is `--exec-policy=assume-none` alone.
The first says where execution *starts*, not that nothing else does — a shell is
free to run things you did not name. The second supplies the missing half, and
it is the same assertion `exec` already accepts one program away: a Go
entrypoint that can spawn is allowed to have its targets assumed accounted for,
and there is no principled reason a shell that spawns should be refused the same
answer. Given both, the closure stands on what you named — 491 roots drop to 9,
the reachable set from 595 objects to 15, and 141 of 148 findings become
provably unreached instead of 1 of 145.

A `--roots` path that resolves to nothing does not count toward the assertion,
so a typo escalates *and* raises `missing-root`. The taint itself is never
dropped either way: escalating it is a note, and standing on your roots it
becomes a **discharged** taint naming the assertion it was spent on.

**What `--roots` cannot do.** It *adds* a root. The entrypoint the image config
declares is still rooted beside it, because naming a program that also runs is
not a claim that the declared one does not. On a hardened image that is the
remaining cost: `--roots /usr/bin/calico-node --exec-policy=assume-none` stands
down the escalation, but `/bin/bash` is still a root, and `bash`,
`libnss_systemd` and `libselinux` each call `dlopen`, so three blocking `dlopen`
taints survive and every OS finding stays `linked`.

In the cluster, bash is never executed — the DaemonSet says
`command: ["/usr/bin/calico-node"]`, and a Kubernetes `command:` *replaces* the
ENTRYPOINT rather than adding to it. Nothing in the image records that, which is
why [pointing `--images-from` at the
manifest](./guides/fleet.md#kubernetes-manifests-as-a-list) is a different
assertion from `--roots` and not a more convenient spelling of it. On
`rancher/hardened-calico:v3.32.0-build20260511` it is the difference between 45
findings `linked` and 38 `linked` with **7 `not_in_execute_path`** — the three
`dlopen` taints go with the shell that reached them.

The override is fed through the same wrapper peeling, shell detection and
escalation as a config entrypoint, so a `command: ["/bin/sh", "-c", ...]`
escalates exactly as a `/bin/sh` ENTRYPOINT would, and a command naming nothing
in the image raises the same blocking `no-entrypoint` taint. It licenses nothing
else: `--exec-policy=assume-none` is still yours to make, because a manifest
saying which program starts is not a manifest saying that program starts nothing.

**Saying it without a manifest.** Kubernetes is not the only thing that replaces
an entrypoint — `docker run --entrypoint`, a compose service's `entrypoint:`, a
Nomad task's `command`, a systemd unit's `ExecStart` — and none of those ship a
file vexscan can read. `--entrypoint` and `--cmd` are the same assertion typed
out, one argv token per use:

```sh
vexscan --image rancher/hardened-calico:v3.32.0-build20260511 \
  --all --ecosystem os --exec-policy assume-none \
  --entrypoint /usr/bin/calico-node --cmd=-felix
```

which produces the same 38 `linked` and **7 `not_in_execute_path`** the manifest
does, and records `--entrypoint and --cmd` as the source instead of a filename.
A fleet list line says it per image as `entrypoint=` and `cmd=`, which is the
form to reach for when a fleet's images are started differently from each other.

Two things to know about the spelling. `--cmd` given alone leaves the image's
declared ENTRYPOINT running and replaces only its arguments, exactly as
Kubernetes `args:` and `docker run IMAGE ...` do — and the report says so rather
than claiming the entrypoint was replaced. And `--cmd=` with nothing after it
means *started with no arguments*, which is a different claim from not passing
the flag at all; `--entrypoint=` is refused, because "started with no program"
is not a thing that runs. Since a Kubernetes manifest already answers this per
container, passing `--entrypoint` beside one is an error rather than a flag that
silently does nothing.

**The pure-Go discharge.** `static-elf` blocks because a statically linked
entrypoint may hold a copy of the vulnerable library inside it, where
`DT_NEEDED` cannot see it — so an unreferenced `.so` on disk proves nothing. A
binary built with `CGO_ENABLED=0` links no C library at all, which answers
exactly that question: there is no hidden copy to worry about, and the
unreferenced `.so` really is the answer. vexscan reads the setting out of the
Go build info, so it survives `-ldflags=-s -w`, and the taint is recorded as a
non-blocking note rather than dropped:

```
evidence: /app/server is statically linked, so the libraries it uses are inside it
          and not on disk, but it is a pure-Go binary built with CGO_ENABLED=0, so
          it links no C library and cannot carry a hidden copy of one
```

Only the entrypoint is probed, and only a Go binary whose build info records
`CGO_ENABLED=0`. A cgo build, a non-Go static binary, or a build info that
cannot be read leaves the taint blocking. What this discharges is *linked-in* C
code, and only that — whether the binary goes on to `exec` something else is a
separate question, asked separately below.

#### Waving off one caller (`--dlopen-assume-none`)

`--dlopen-policy=assume-none` is usually far more than you mean. On
`rancher/hardened-calico:v3.32.0-build20260511` exactly three reachable objects
call `dlopen` — `/usr/bin/bash`, `libnss_systemd.so.2` and `libselinux.so.1` —
but the flag does not say "those three". It says *nothing in this image loads
anything that matters*, including every library nobody has looked at and every
one added by a later rebuild.

`--dlopen-assume-none` makes the claim you actually have evidence for, one
caller at a time, by tree-absolute path or by SONAME:

```
vexscan --image rancher/hardened-calico:v3.32.0-build20260511 --all \
  --roots /usr/bin/calico-node --exec-policy assume-none \
  --dlopen-assume-none /usr/bin/bash \
  --dlopen-assume-none /usr/lib64/libnss_systemd.so.2 \
  --dlopen-assume-none /usr/lib64/libselinux.so.1
```

Naming all three clears exactly what the blanket flag clears — the same seven
`not_in_execute_path` rows — while the recorded assertion shrinks from one
unfalsifiable sentence to three a reviewer can check. Each discharged caller
says which name answered it, and the condition line on the report names them:

```
NOTE: ruled-out reachability rows are conditional - under the asserted runtime
      profile: execution starts at /usr/bin/calico-node; the entrypoint is
      asserted to run nothing else; /usr/bin/bash, /usr/lib64/libnss_systemd.so.2,
      /usr/lib64/libselinux.so.1 are asserted to dlopen nothing that matters
```

The match is against the path or the SONAME and nothing else. A bare filename is
refused deliberately: a multiarch image carries `/usr/lib/libfoo.so.1` and
`/usr/lib32/libfoo.so.1`, and an assertion about the one you opened must not
quietly cover the one you did not. Where the graph has already worked out that a
caller is bounded — an OpenSSL provider directory it roots and walks — that
finding is what gets reported rather than your assertion, so a clean row never
reads as resting on a promise when it rests on a proof. Setting the flag
alongside `--dlopen-policy=assume-none` is an error: the two assert
different-sized things and there is no way to tell which you meant.

**`inert-assertion`.** A name that matches no `dlopen` caller does not fail the
scan. It removes no taint, so the run is strictly *more* conservative than you
asked for and no conclusion in it can be wrong — the asymmetry with
`missing-root`, which shrinks the closure and therefore has to block.

It is still reported, because it is still a mistake, and one whose consequences
are invisible: you see rows blocked by a `dlopen` you believe you answered, with
nothing connecting the two. The condition line says so, and distinguishes the
two cases, because they send you to different places:

```
/usr/bin/bsah was named by --dlopen-assume-none and matches no dlopen caller
here, so the assertion discharged nothing
```

— for a name that is not in the image at all, versus *is in this image but calls
no dlopen the closure reached* for one that is there and silent. The first is a
typo; the second means your profile is aimed at the wrong image, or that the
caller you were worried about is not reachable in the first place.

#### The exec probe (`--exec-policy`)

The closure follows what the dynamic linker maps into **one process**. It does
not follow a process tree. An entrypoint that runs `/usr/bin/su` loads libpam in
a second process that nothing here looks at, and a `not_affected` on the `pam`
package would then be wrong for a reason the report never mentioned.

Escalation covers the case where the image does not say what it runs, and
`shell-entrypoint` covers the case where what it runs is a script. An image
whose entrypoint is one compiled binary used to get the benefit of the doubt,
and the doubt was never measured. For a Go binary it can be.

A Go binary keeps its function-name table even when fully stripped, so whether
it links `syscall.forkExec` or `syscall.Exec` — the two chokepoints every route
out of Go into a new process ends at, including `os/exec`, `os.StartProcess` and
`golang.org/x/sys/unix.Exec` — is a fact about the file rather than a guess.
That makes the answer three-valued, and the two decided values are both worth
saying:

- **It can.** A blocking, global `exec` taint. Program paths the binary mentions
  are rooted, so their libraries are in the closure rather than reported as dead
  code, and they are named in the evidence as a starting list for `--roots`.
  Finding them does *not* discharge anything: a target assembled at runtime or
  resolved through `PATH` leaves no name to find, so the list can never be known
  to be complete.
- **It provably cannot.** A discharged note. This is the one that matters for a
  distroless-style image, because it turns "we assume the entrypoint does not
  shell out" into something checked:

```
evidence: /app/server starts no other program: it is a pure-Go binary built with
          CGO_ENABLED=0 and its function-name table contains none of the standard
          library's process-spawning calls, so it links no C that could exec and
          no Go that would
```

- **Unknown.** A C entrypoint, a cgo build with no Go-side marker, an unreadable
  file. Nothing is recorded and the closure behaves exactly as it did before the
  probe existed. Blocking here would block every image with a compiled non-Go
  entrypoint, on a suspicion that applies to all of them equally.

The asymmetry between the first two is deliberate. Finding a marker settles the
positive claim however the binary was linked; the negative claim additionally
requires `CGO_ENABLED=0`, because the markers are Go symbol names and a cgo
build can reach `execve`, `system` or `posix_spawn` from C without leaving one.

The test is a substring search over the whole file, not a parse of
`.gopclntab`, and that is the conservative direction rather than the lazy one.
The claim is an absence, and an absence proved over every byte is stronger than
one proved over the bytes a parser managed to find — a parser that mislocated
the table would report an empty function list and turn a binary that *does*
exec into one that provably does not. The cost is precision the other way: a
marker sitting in an embedded file reads as a spawn, which costs a taint, which
is a conclusion withheld rather than a conclusion invented.

`--exec-policy=assume-none` is the escape hatch, mirroring `--dlopen-policy`:
name what the entrypoint runs with `--roots`, then assert that they are
accounted for. The observation stays in the record as a discharged note.

**Measured**, on `registry.suse.com/bci/bci-base:15.5` with a Go entrypoint at
`/app/server`. The two images differ only in whether the entrypoint calls
`exec.Command("/usr/bin/su", ...)`:

| entrypoint | closure | affected | ruled out |
|---|---|---|---|
| pure Go, no spawn | 1 of 560 objects, 1 root | 48 | 125 |
| same, plus one `exec.Command` | 81 of 560 objects, 56 roots | 143 | 30 |

Before this probe both reported 48 / 125. The second one was wrong: `su` was
found in the binary's string literals and rooted, which pulled in libpam, which
admitted the 47 PAM modules the plugin gating had left out, and the global taint
blocked the rest.

**The cgo symbol-absence discharge.** A cgo entrypoint is exactly the case the
pure-Go discharge cannot touch: it *might* have linked the C library in, so its
static-elf taint stays blocking by default. But if it is **unstripped**, its own
symbol table settles the question for a specific advisory. Under
`--mine-advisories`, once a vulnerable symbol has been validated against the
package it belongs to (the same namespace discipline the mined-symbol test
uses), vexscan reads the entrypoint's `.symtab` and clears the taint for
that finding only when:

- the entrypoint is a **cgo** build (its build info records `CGO_ENABLED=1`) and
  is **not stripped** — a stripped binary stays blocking, because absence from a
  symbol table that was discarded is not absence from the binary;
- the vulnerable function's **namespace is present** in the table (the binary
  demonstrably links that library family), **and** the vulnerable function
  itself is **absent** — so the linker included the library but not the
  vulnerable code.

```
evidence: /app/server is a cgo binary, but its static symbol table carries the SSL_
          namespace and not SSL_free_buffers, so the vulnerable code is not statically
          linked into it
```

The namespace gate does most of the safety here, and it is the same open-world
rule the mined-symbol layer uses: a function absent from a table that never
mentions its library family says nothing — the family may be there under
localised or stripped names — so a *wholly* absent namespace stays blocking, not
discharged. It is not sufficient on its own, though, and the
[shape gate](./llm-layer.md) that backs it up applies here too: this path
consumes the same validated symbols, so a name that is not a function never
reaches it. This continues the [pure-Go discharge](#taints) (#24) toward the
same end as [issue #23](https://github.com/cwayne18/vexscan/issues/23):
maximizing the removals a scan can make with certainty, and making no other
kind.

`--roots /path/to/bin` adds entrypoints for an image whose real command comes
from outside its own config — a sidecar, an operator — and for a `--rootfs`
tree, which has no config to read. For a Kubernetes `command:`, which replaces
the config entrypoint rather than adding to it, read the manifest instead.
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
| …but an archive that could be it was unreadable or unidentified | `undetermined` | — | reason `unidentified_archive` |
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

