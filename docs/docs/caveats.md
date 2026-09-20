---
sidebar_position: 23
title: "Caveats"
---


- **The LLM verdict is advisory only.** Never file a VEX statement on an LLM
  verdict alone; it supplements the deterministic checks and does not replace
  them.
- **The pclntab test is conservative, not exact.** A genuinely-linked package is
  never reported absent, but validate candidates before publishing.
- **The `DT_NEEDED` closure is weaker still, and the Python and npm import
  graphs are weaker than that.** See [Known
  limits](./known-limits.md) — this is the
  most important section in this README.
- **`--rootfs` cannot know what the tree runs, and a tree you cannot fully read
  is not a clean tree.** Both are reported rather than assumed away — the first
  as taints, the second as `unreadable` plus exit 1. See
  [`--rootfs`](./guides/rootfs.md).
- **`--rpm` runs no reachability test at all, and it says so on every report.**
  A package file has no filesystem behind it, so nothing is ever `linked` and
  nothing is ever ruled out as unreachable — only a package that ships no ELF
  object can be ruled out. See [`--rpm`](./guides/package-files.md) for what
  that costs, measured.
- **`--sbom` runs no test of any kind, and it says so on every report.** A
  CycloneDX component is a name, a version and a purl: there is no filesystem
  to trace and no file list to rule anything out on, so **every** finding is
  `undetermined`. It is a triage input, not an answer. See
  [`--sbom`](./guides/sbom.md).
- **Repo mode for Python and npm resolves no import graph at all.** A lock file
  answers "is this declared" and, where the format says so, "is it
  development-only". Nothing there speaks to reachability, and a `linked`
  finding says as much in its own text.
- When OSV publishes no package-level import paths for a Go advisory (some
  GitHub-only GHSA records), presence is asserted at **module** granularity;
  those findings say `granularity: module` and are coarser.

