---
sidebar_position: 5
title: "Scanning a bill of materials (--sbom)"
---


`--sbom` scans the components named in a CycloneDX JSON document — the standard
hand-off between a build system and a scanner, and the one input every other
scanner accepts. It is for the case where the SBOM is what you have: a build
published one, a vendor sent one, a policy requires one.

```sh
vexscan --sbom sbom.cdx.json --all
syft debian:12 -o cyclonedx-json | vexscan --sbom - --all
vexscan --sbom sbom.cdx.json --all --ecosystem golang
vexscan --sbom sbom.cdx.json --format inventory
```

`-` reads standard input. The flag is mutually exclusive with `--image`,
`--rootfs`, `--repo` and `--rpm`, and the report says `"mode": "sbom"`.

Components are routed to the plugin that can query them, from the purl type:
`pkg:golang` → Go, `pkg:npm` → npm, `pkg:pypi` → PyPI, `pkg:maven` → Maven, and
`pkg:deb` / `pkg:rpm` / `pkg:apk` → the OS plugin. `--ecosystem` and the
per-ecosystem outcome list behave exactly as they do for an image.

### Read this part before trusting a result

**Every finding is `undetermined`.** Not some — every one. `--rpm` has no
filesystem either, but an rpm header still lists the files the package installs
and `file(1)`'s verdict on each, which is enough to rule out a package that
ships no executable code. A CycloneDX component carries a name, a version and a
purl. There is nothing in it to rule anything out with, so nothing is ruled out:

```
NOTE: this read a bill of materials, not an installed system. No ELF
      reachability test could run -- there is no filesystem to trace -- and a
      CycloneDX component does not list the files it installs, so unlike a
      package file it cannot rule a package out for shipping no code either.
      Every row below is a package the document says is installed, and
      nothing here can say whether its code would ever run.
      89 finding(s) below are undetermined for that reason. Scan the image
      or tree these components came from to get an answer.
```

That note prints at both ends of the report, and it prints on a clean one too:
"no findings" out of a bill of materials is a much weaker statement than the
same words out of an image, and the difference has to be on the page.

So this mode answers *which advisories apply to what this document says is
installed* — the same question a version-matching scanner answers, and nothing
more. Point `vexscan` at the image or the tree when you want the answer only it
can give.

### The source name is why this finds anything

Debian, Alpine and the RPM distributions all file advisories against the
**source** package, and the binary package in the document is usually named
something else. Both producers say so, in different places: syft writes
`upstream=openssl` as a purl qualifier, trivy writes an
`aquasecurity:trivy:SrcName` property. `vexscan` reads both and queries the
binary and source names together. Missing it queries a name OSV has no records
under, which reads exactly like a clean package.

The distribution comes from the `distro=` qualifier — `distro=debian-12`,
and Alpine's bare `distro=3.19.9` resolved through the purl namespace. A
document that states no distribution, or states two, is **an error naming
`--osv-ecosystem`**, on the same reasoning as `--rpm`: an OSV query with no
ecosystem finds nothing and reads like a clean scan.

### Nothing is dropped quietly

A document with 400 components of which 120 were unusable must not print as a
scan of 280. Two things can be wrong with an entry, and they are not the same:

- **Skipped** — it named no package to begin with. The `operating-system` row,
  trivy's `go.mod` marker, a purl type `vexscan` has no ecosystem for, or a
  component with no version to match a range against. Each is logged with its
  reason. These are ordinary, and not a loss.
- **Failed** — it had a package URL and the URL would not parse. That is a
  component that went unexamined, so it lands in `unreadable` alongside a
  directory that could not be read, is named with its reason, and the scan
  **exits 1**.

A document nobody could read at all is an error, never an empty result — and so
is one where every entry resolved and none of them was a package this tool can
query. Scanning clean is the one outcome an empty result may never produce.

Only CycloneDX JSON is read today. An SPDX document is told what it is rather
than scanned as a document with no components in it.

