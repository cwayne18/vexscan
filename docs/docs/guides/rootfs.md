---
sidebar_position: 3
title: "Scanning a filesystem (--rootfs)"
---


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

A `--roots` path that names no ELF object in the image is a **blocking**
`missing-root` taint, not a skipped argument. Misspell it and the closure would
otherwise carry on one root short, reporting code it never looked at as
unreachable — and since `--roots` is usually paired with
`--exec-policy=assume-none`, there would be nothing left to withhold the
conclusion. So a typo costs you every answer for that image rather than buying
you wrong ones. The taint names the path that failed, and says whether it was
absent or present-but-not-an-ELF-object.

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

