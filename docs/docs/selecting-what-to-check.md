---
sidebar_position: 3
title: "Selecting what to check"
---


A `--package SPEC` is a purl, an `ecosystem:name` shorthand, or a bare name
resolved against whatever inventory contains it:

```
golang:golang.org/x/net    deb:openssl    apk:musl    rpm:glibc    openssl
pypi:PyYAML    npm:@babel/core    maven:org.apache.logging.log4j:log4j-core
org.apache.logging.log4j:log4j-core    log4j-core
pkg:golang/golang.org/x/net@v0.17.0    pkg:pypi/pyyaml@6.0.3    pkg:npm/%40babel/core@7.24.0
pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
```

`deb`, `dpkg`, `rpm` and `apk` are package *formats* rather than OSV ecosystem
names; they all select the OS plugin, which is the only thing that could answer
them. `go` is accepted for `golang`, `std` for `stdlib`, `python` and `pip` for
`pypi`, `node` and `nodejs` for `npm`, and `java` and `jar` for `maven`.

PyPI names are matched after PEP 503 normalization — lowercased, with runs of
`-`, `_` and `.` collapsed to a single `-` — so `PyYAML` and `pyyaml` select the
same distribution, as do `typing_extensions` and `typing-extensions`. npm names
are matched verbatim, scope included, because that is how the registry and OSV
key them.

A Maven coordinate is itself colon-separated, so
`org.apache.logging.log4j:log4j-core` needs no `maven:` prefix — a prefix with a
dot in it is read as a groupId rather than an ecosystem, since no ecosystem name
contains one. A bare artifactId (`log4j-core`) also selects, which is ambiguous
in principle because two groups can publish the same artifactId, and in practice
resolves into extra findings rather than missing ones.

`--package` is repeatable and accepts comma-separated values, so
`--package a --package b` and `--package a,b` are the same.

Three ways to say what to check, and you need exactly one of them:

| | Meaning |
|---|---|
| `--package SPEC...` | these components, every advisory that applies to them (or just `--cves`) |
| `--cves LIST` alone | resolve these ids against the whole target, wherever they land |
| `--all` | everything each selected ecosystem can enumerate (the default in `--image` mode when you name no `--package`/`--cves`) |

`--ecosystem` (repeatable) restricts which plugins run. Naming one that no
plugin provides is an error rather than a silent empty report — as is a
`--package` aimed at an ecosystem that is not selected.

`--cves` matches an id anywhere the advisory is known by it, including as one of
the CVEs a distro advisory says its patch fixes. This matters on SUSE and Red
Hat, where the published id names no CVE at all: `SUSE-SU-2026:0312-1` addresses
eight and `RHSA-2024:2447` seven, and neither carries an alias. Asking for one
of those CVEs finds the advisory that patches it, reported under the id you
asked about, with `--details` listing the rest of the bundle so you can see the
upgrade covers more than you asked for.

> Before v0.5.1 this matched nothing on those distros. `--cves` against a SUSE
> image returned an unmatched-id row for every CVE, which read as "not
> affected". If you scanned SUSE or RHEL by CVE with an earlier release, rerun
> it.

