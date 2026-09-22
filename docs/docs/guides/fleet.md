---
sidebar_position: 1
title: "Scanning a fleet (--images-from)"
---


`--image` is repeatable, and `--images-from` reads a list: a file with one
reference per line, a URL, or `-` for stdin.

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

`--roots`, `--exec-policy`, `--dlopen-policy` and `--dynamic-import-policy` are
process-global. What they *assert* is not. "This entrypoint execs `iptables`,
and `iptables` is the whole list" is true of one image in a fleet of sixty;
applied to the other fifty-nine it is meaningless at best. And since an
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
| `exec-policy=` | `taint` or `assume-none` |
| `dlopen-policy=` | `taint` or `assume-none` |
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
that same line append.

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

