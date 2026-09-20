---
sidebar_position: 2
title: "Scanning a hauler haul (--haul)"
---


[hauler](https://docs.hauler.dev) bundles images, charts and files into one
portable archive — a *haul* — so a fleet can cross an airgap as a single file.
`--haul` scans one:

```sh
vexscan --haul rke2-airgap.tar.zst --all --format summary
vexscan --haul haul.tar.zst --cves CVE-2024-45337 --fail-on high
vexscan --haul ./store --all --format json --out haul.json
```

**Nothing is pulled.** Inside, a haul is an OCI image layout, which is a
transport skopeo already speaks, so every image in one is extracted and analysed
straight out of the archive. That is the point: the machine that needs the
answer is the machine on the far side of the airgap, and it has no route to a
registry. A haul is not read to recover a list of references and then pull them
— that would need exactly the network the haul exists to do without.

A `.tar.zst`, a plain tar, or an already-unpacked store directory all work; the
compression is sniffed from the bytes rather than the file name. An archive is
unpacked to a temporary directory first, because zstd is a stream and there is
no seeking into one for the four blobs a particular image needs — so **budget
disk for a second copy of the haul** for the length of the run, and point
`--haul` at an unpacked `store/` directory instead when you already have one and
would rather not. The unpack is removed as soon as the last image has been read,
before anything is rendered.

`--haul` always produces a [batch document](./fleet.md),
even for a haul that holds one image, on the same grounds `--images-from` does:
what is in a bundle is a property of the bundle, not of the command.

### What a haul holds that this does not scan

A haul carries charts and files next to its images, and vexscan scans neither.
Filtering the index down to images and printing a clean report would produce
something indistinguishable from a scan of a haul that had no charts in it, so
everything skipped is counted and named on stderr before the scan starts:

```
warning: 2 charts in this haul are not scanned; vexscan has no chart target.
         If they were added with add-images, their images are in the haul and are covered above.
         If they were not, their images are not in this haul and nothing here covers them.
         hauler/cert-manager:v1.14.4
         hauler/rancher:2.8.2
```

That distinction is the whole of it. `add-images: true` in a hauler manifest
makes hauler resolve a chart's images into the store when it builds the bundle,
so those images *are* in the haul and are already in the scan above. Without it,
the chart's images were never collected, and no scan of this file can reach
them.

An entry this reader cannot classify gets the loudest warning of the set, with
the reason, because on a haul written by a newer hauler it could be an image in
a shape vexscan has not seen.

### References, and when they come out short

hauler files a store entry under a name with the **registry stripped off** —
`rancher/hardened-kubernetes:v1.31.0`, not
`docker.io/rancher/hardened-kubernetes:v1.31.0`. vexscan recovers the full name
from hauler's own `hauler.dev/original-ref` annotation, falling back to
`io.containerd.image.name`, so a haul scan and a registry scan of the same image
agree about what they looked at.

Some hauls record neither — anything built by hauler v1, and a window of v2 that
lost the containerd name on the OCI import path. Those images are scanned under
the registryless name, and said so:

```
warning: 1 image in this haul has no fully qualified reference recorded, so it is scanned under the
         registryless name hauler stored. Findings for it will not line up with a --image scan,
         and --vex-out would file it under a different product purl:
         rancher/klipper-helm:v0.9.4
```

Nothing is invented: guessing `docker.io` for a registryless name is how an
image from a private registry ends up filed under the wrong product.

### Hauler manifests as a list (`--images-from`)

The manifest that *produces* a haul is checked in beside the pipeline, which
makes it the natural thing to scan before the bundle exists. `--images-from`
reads one wherever it finds one — recognised by its `content.hauler.cattle.io`
API group, so a plain reference list keeps the behaviour it had:

```sh
vexscan --images-from hauler-manifest.yaml --all --format summary
```

Every document in the file is read, not just the first. Charts and files are
counted and warned about the same way, and a chart with `add-images` is named
individually, because a manifest scan is a **strict subset** of a haul scan:
the bundle holds images the manifest never writes down.

