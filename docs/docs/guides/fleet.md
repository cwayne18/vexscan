---
sidebar_position: 1
title: "Scanning a fleet (--images-from)"
---


`--image` is repeatable, and `--images-from` reads a list: a file with one
reference per line, a URL, or `-` for stdin — or a
[Kubernetes manifest](#kubernetes-manifests-as-a-list), which carries what each
image is started with as well as which images there are.

```sh
vexscan --images-from fleet.txt --format summary
vexscan --image myorg/api:v2 --image myorg/web:v2 --format summary
vexscan --images-from https://inventory.internal/images.txt --fail-on critical

kubectl get pods -A -o jsonpath='{..image}' | tr ' ' '\n' | \
  vexscan --images-from - --format summary
```

The list is the plainest thing that can carry a fleet — `#` starts a comment,
blank lines are skipped, and a reference named twice is scanned once:

```
# production, europe
myorg/api:v2.4.1
myorg/web:v2.4.1        # the one that ships PyYAML
ghcr.io/myorg/worker@sha256:9f2a...
```

`--images-from` fetches over plain HTTP(S) and sends no credentials. A list
behind authentication should be fetched by whatever holds the token and piped
in with `-`.

### Per-image assertions

`--roots`, `--exec-policy`, `--dlopen-policy`, `--dlopen-assume-none` and
`--dynamic-import-policy` are process-global. What they *assert* is not.
"This entrypoint execs `iptables`, and `iptables` is the whole list" is true of
one image in a fleet of sixty; applied to the other fifty-nine it is meaningless at best. And since an
unresolvable `--roots` path is a blocking `missing-root` taint (see
[Taints](../how-the-tests-work.md#taints)), a global `--roots` aimed at one image withholds every
conclusion about the rest.

So a list line may carry its own:

```
# the one that shells out to iptables
rancher/mirrored-kube-vip-kube-vip-iptables:v0.6.0 roots=/usr/sbin/xtables-nft-multi exec-policy=assume-none

# a sidecar whose entrypoint is the whole program
rancher/hardened-coredns:v1.11.1-build20240910

rancher/nginx-ingress-controller:v1.10.4-hardened3 roots=/nginx-ingress-controller,/usr/sbin/nginx exec-policy=assume-none
```

| key | value |
|---|---|
| `roots=` | comma-separated paths; repeatable on the line. **Replaces** the global `--roots` for this image rather than adding to it — a line that names its own roots is a complete statement about what that image runs |
| `entrypoint=` | one argv token; repeatable and ordered, so `entrypoint=/usr/bin/tini entrypoint=--` is a two-word command line. **Replaces** the ENTRYPOINT the image config declares rather than adding to it, which is what `roots=` does. No comma split — an argument may contain one. Empty is an error |
| `cmd=` | the same, for the CMD. Given without `entrypoint=` it leaves the image's declared entrypoint running and changes only its arguments, as Kubernetes `args:` does. `cmd=` with nothing after it says the image is started with **no** arguments, which is not what saying nothing says |
| `exec-policy=` | `taint` or `assume-none` |
| `dlopen-policy=` | `taint` or `assume-none` |
| `dlopen-assume-none=` | comma-separated caller paths or SONAMEs; repeatable on the line. The narrow form of `dlopen-policy=assume-none` — it waves off only the callers named. **Replaces** the inherited list rather than adding to it, on the same rule as `roots=` |
| `dynamic-import-policy=` | `taint` or `assume-none` |
| `profile=` | the name of a `[profile ...]` block to take these keys from; see [Named profiles](#named-profiles) |

A key the line does not mention inherits the global flag, so a list can loosen
one image and leave the rest alone — or tighten one back to `taint` under a
global `assume-none`.

Two rules, both about not guessing on your behalf. An unknown key or an invalid
value is an error, reported before anything is pulled, rather than a line
quietly skipped: skipping fails closed, but it leaves you believing you asked
for something you did not. And an image named twice where either line carries
assertions is an error too — that is not a repeat, it is the list saying the
image runs two different things, and there is no safe way to pick one.

### Kubernetes manifests as a list

A cluster already records what it runs, and it records the one thing the images
themselves cannot: a container's `command:` **replaces** the image's ENTRYPOINT,
so the declared entrypoint is never executed and neither is anything only it
would have loaded.

Point `--images-from` at the manifest and it is read as one — no new flag, the
same way a [hauler manifest](./haul.md#hauler-manifests-as-a-list---images-from)
is:

```sh
vexscan --images-from deploy.yaml --all --exec-policy assume-none
kubectl get daemonset,deployment -A -o yaml | \
  vexscan --images-from - --all --exec-policy assume-none
```

Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController,
Job, CronJob, PodTemplate and List documents are read, `initContainers`
included; Services, ConfigMaps and RBAC alongside them are skipped because they
hold no containers. A file is treated as a manifest only if an unindented
`kind:` names one of those, so a plain reference list keeps the meaning it has
always had.

Why it is worth reading rather than transcribing into `roots=`: `--roots`
*adds* a root and leaves the image's own entrypoint rooted beside it. On
`rancher/hardened-calico:v3.32.0-build20260511` the declared entrypoint is
`/bin/bash`, and bash, `libnss_systemd` and `libselinux` each call `dlopen`, so
even with `--roots /usr/bin/calico-node --exec-policy=assume-none` all 45 OS
findings come back `linked`. Reading the DaemonSet's
`command: ["/usr/bin/calico-node"]` drops bash from the closure entirely — 1
root instead of 14, and **7 findings become `not_in_execute_path`**.

That is an assertion and it is recorded as one, at the front of the condition
line, because everything else in the sentence depends on it:

```
NOTE: ruled-out reachability rows are conditional - under the asserted runtime
profile: the image runs /usr/bin/calico-node -felix per deploy.yaml, not the
entrypoint its config declares; the entrypoint is asserted to run nothing else
```

Three things it deliberately does not do:

- **It does not imply `--exec-policy=assume-none`.** A manifest saying which
  program starts is not a manifest saying that program starts nothing. Without
  it the exec taint still blocks, and the seven rows above stay `linked`.
- **It does not flatter a shell.** `command: ["/bin/sh", "-c", "..."]` goes
  through the same shell detection and escalation as a `/bin/sh` ENTRYPOINT,
  and a command naming nothing in the image raises the same blocking
  `no-entrypoint` taint.
- **It does not go quiet on the images it left alone.** A container that sets
  no `command:` still records that a manifest was read for it — `deploy.yaml
  says nothing about how this image is started, so the entrypoint its config
  declares is what runs`. A manifest aimed at the wrong images would otherwise
  produce a report identical to the one you meant.

One image started two different ways — two containers with different
`command:`, or one overriding and one not — is an error naming both, on the same
rule as a list that names an image twice: that is not a repeat, it is two
closures, and no single scan answers for both. Containers that agree collapse,
so the same image in a Deployment and a DaemonSet is scanned once.

A container that sets its own `PATH` **and** a relative `command:` is also an
error. Nothing here reads the container environment, so resolving that command
against the image's `PATH` could name a different program with nothing in the
report to show for it. Give it as an absolute path.

### When there is no manifest

Kubernetes is not the only thing that replaces an entrypoint. `docker run
--entrypoint`, a compose service's `entrypoint:`, a Nomad task's `command`, a
systemd unit's `ExecStart` — all of them do, and none of them ship a file
vexscan can read. `--entrypoint` and `--cmd` are the same assertion typed out:

```sh
vexscan --image rancher/hardened-calico:v3.32.0-build20260511 \
  --all --ecosystem os --exec-policy assume-none \
  --entrypoint /usr/bin/calico-node --cmd=-felix
```

That produces the same seven `not_in_execute_path` rows the DaemonSet does, and
records `--entrypoint and --cmd` as the source in place of a filename. Per image
in a fleet, the `entrypoint=` and `cmd=` keys above say it on the line, which is
what to reach for when a fleet's images are started differently from each other.

The same three refusals apply — a shell is still a shell, a command the image
does not contain still blocks, and `--exec-policy=assume-none` is still yours to
make separately. Two more belong to the flags. `--entrypoint=` with nothing after
it is an error, because "started with no program" does not run; say
`--cmd=` if you mean it starts with no *arguments*. And because a Kubernetes
manifest already answers this for every container in it, `--entrypoint` passed
beside one is an error rather than a flag that quietly does nothing.

### Named profiles

A real fleet is a hundred images whose deployment shapes repeat: a hardened Go
daemon with one entrypoint, a supervisor wrapped in a shell, a CLI that execs
nothing. Spelling the same `exec-policy=assume-none` out on sixty lines makes
the list unmaintainable, and — worse — makes it *drift*, as half the lines get
updated and the other half keep asserting something that stopped being true.

A profile is the same assertion said once:

```
[profile go-daemon] exec-policy=assume-none
[profile calico]    roots=/usr/bin/calico-node exec-policy=assume-none

docker.io/rancher/hardened-calico:v3.32.0-build20260511   profile=calico
docker.io/rancher/hardened-coredns:v1.11.1-build20240910  profile=go-daemon roots=/coredns
docker.io/rancher/hardened-etcd:v3.5.21-build20250612     profile=go-daemon
```

A `[profile NAME]` line takes exactly the keys an image line takes, minus
`profile=` itself. Definitions are collected before any image line is read, so a
list can keep its profiles at the bottom, or put one beside the odd image it
exists for, rather than being forced into define-before-use order.

A key stated on the image line wins over the same key in the profile it names,
so `profile=go-daemon roots=/coredns` is the daemon policy with this image's own
root. The `roots=` rule is unchanged: the first `roots=` on a line clears
whatever the profile supplied rather than adding to it, and later `roots=` on
that same line append. `dlopen-assume-none=` works the same way, so a line can
correct a profile's caller list rather than only extend it.

A name in `dlopen-assume-none=` that matches no `dlopen` caller in the image is
not an error — it discharges nothing, so the scan stays more conservative than
you asked for, not less. It is reported, though, in the same condition line the
assertion appears in: `/usr/bin/bsah was named by --dlopen-assume-none and
matches no dlopen caller here`. A profile aimed at the wrong image, or a typo,
otherwise produces a report identical to the one you meant.

The name is carried onto the scan, into the report, and into the emitted VEX, so
a conclusion that rests on a profile says which one — `under the asserted
runtime profile "calico"`. That is the point of naming a profile rather than
expanding it: a reviewer reading the document six months later can look the name
up and disagree with it. See
[Conditional conclusions](../output/vex-output.md#conditional-conclusions).

A profile that asserts nothing, a name defined twice, a name used but never
defined, and a profile that names another profile are all errors, reported with
their line number before anything is pulled. Profiles do not nest because they
are collected in one pass and expanded in the next, so a `profile=` inside a
definition would be accepted and then quietly dropped — and dropped towards
asserting *less*, which shows up as a scan that withheld conclusions rather than
as an error.

### Why one process and not a shell loop

Everything expensive is shared across the images: the OSV client, the `--triage`
feeds, and the `--distro-feeds` providers with their parsed-document caches.
Forty images on the same Debian release download the security tracker once
instead of forty times.

The scan is **serial**. Running the images concurrently would multiply that win,
but only once every shared component has been audited for concurrent use, and a
data race inside the thing that decides whether a CVE is present is not a trade
worth making for wall-clock.

### The results stay separate

Nothing is merged. Each image keeps its own `analyze.Result` — its own target,
its own `INCOMPLETE` banners, its own findings — because merging would break the
one promise this tool makes. A `not_present` for image A and an `affected` for
image B are the same CVE with two different answers, and a single findings list
has nowhere to put that. Worse, an image whose package database could not be
read would drag its uncertainty across every other image in the run, or be
averaged out by thirty-nine clean ones.

So: N results, rendered as N reports under one roll-up, and an image that could
not be scanned is a **row in the table** rather than an absence from it.

```
vexscan batch report: 3 image(s)
INCOMPLETE: 1 of 3 image(s) could not be scanned, so this batch is not a clean result:
  ghcr.io/myorg/worker:v9: manifest unknown

BATCH SUMMARY
IMAGE                                  COMPONENTS  AFFECTED  RULED OUT
alpine:3.20                            14          0         0
ghcr.io/myorg/worker:v9 (NOT SCANNED)  -           -         -
debian:12                              88          175       7
TOTAL                                  102         175       7

affected by severity: 10 critical, 26 high, 44 unknown, 86 medium, 9 low
```

A row marked `(INCOMPLETE)` was scanned but with holes in it; its counts are a
floor, never a total. The rows follow the list, so an image that failed stays
where you asked for it and you can read the table against your own file line by
line.

An image that fails does not stop the run. Aborting on image 7 of 40 would make
this worse than the shell loop it replaces.

### What each format does

| `--format` | Batch behaviour |
|---|---|
| `summary` | The roll-up alone: one row per image, then a total. This is the format a fleet is actually read in |
| `text` | The roll-up, then every image's full report in list order, each under its own `vexscan report (image) for ...` header |
| `json` | A wrapper — `{"schema_version": 1, "mode": "batch", "targets": N, "results": [...], "failures": [...]}` — with each element of `results` the same shape a single scan emits, still carrying its own `schema_version` |
| `sarif` | One SARIF `run` per image in one document, each naming its target in `properties`, so a code-scanning dashboard can tell the alerts apart |
| `fixplan` | One fix plan per image. There is no combined plan: the upgrade that clears a CVE in one image is not the upgrade that clears it in another |
| `inventory` | One listing per image, in list order |

The output shape is decided by the **flags**, not by how many lines the list
happened to have — a `fleet.txt` that drops to one image still emits a batch
document, so nothing parsing it changes underneath you.

A batch `json` document is what
[`contrib/vexscan-dashboard.py`](../output/machine-formats.md#an-html-dashboard-contribvexscan-dashboardpy)
turns into a browsable index of the fleet, worst image first, with a page per
target behind it.

### Exit status and `--vex-out`

| Situation | Exit |
|---|---|
| Every image scanned, nothing over the `--fail-on` threshold | `0` |
| Any image could not be scanned, or was scanned incompletely | `1` — and `--fail-on` is not evaluated at all |
| Every image scanned, and any one of them is over the threshold | `3` |

`--fail-on` sums the counts across the fleet and trips on any image, because a
pipeline that ships a fleet ships the worst image in it. It is not consulted
when an image is missing: a finding count with a hole in it is not a number
worth deciding a build on, and a clean gate over it would be the batch's own
hole reported as a pass.

`--vex-out` is decided **per image**. The single-image rule — a scan with holes
in it must not have `not_affected` statements written from it — is about one
target. An image that could not be pulled says nothing about the thirty-nine
read cleanly, so their statements are still written and the incomplete ones are
skipped with a line on stderr saying so.

The *write*, though, happens once for the whole run rather than once per image.
Each image is still its own product with its own document — nothing is pooled
that the hub keeps apart — but the hub is read once, the index resolved once and
any [merged report](../output/vex-output.md#merged-master-reports---vex-merge-into) rewritten once, so
the cost of contributing a fleet is one hub round-trip, not forty.

