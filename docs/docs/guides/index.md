---
sidebar_position: 0
title: "Scanning targets"
---

# Scanning targets

`vexscan` can point its deterministic presence tests at more than a running
container image. Each page here covers one non-image target and the trade-offs
that come with it:

- **[A fleet](./fleet)** — many images in one run, advisories fetched once.
- **[A hauler haul](./haul)** — images scanned inside the airgap they were carried into.
- **[A filesystem tree](./rootfs)** — an unpacked image, a mounted volume, or a machine's own `/`.
- **[Package files](./package-files)** — an RPM that was never installed, from a file, directory, or URL.
- **[A bill of materials](./sbom)** — a CycloneDX SBOM, from a file or a pipe.

For scanning a plain container image or a source repo, see
[Quick start](../quick-start) and [Selecting what to check](../selecting-what-to-check).
