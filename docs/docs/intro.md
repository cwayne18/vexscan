---
sidebar_position: 1
slug: /
title: "Introduction"
sidebar_label: "Introduction"
---

# vexscan


`vexscan` answers one question, for a container image, a filesystem tree, a
source repo, or an RPM that was never installed: **is this CVE's vulnerable code
actually present, and can it actually run?**

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
| OS packages (deb, rpm, apk) | `--package deb:NAME` etc. | package-database inventory; the dynamic linker's `DT_NEEDED` closure from the entrypoint (or `--roots`) |
| Python (PyPI) | `--package pypi:NAME` | `dist-info`/`RECORD` inventory; a static import closure from the entrypoint (or `--roots`) |
| npm | `--package npm:NAME` | `node_modules` manifest inventory; a static require/import closure from the entrypoint (or `--roots`) |
| Java (Maven) | `--package maven:GROUP:ARTIFACT` | jar/war/ear coordinate inventory; class presence in the archive's central directory |

Python and npm answer a **narrower** question than Go does, and the tool is
built to say so rather than to guess. Neither language removes dead code at
build time, so `not_present` can only mean "not installed"; reachability is the
one remaining lever, and it is blocked far more often than the `DT_NEEDED`
closure is. Read [Known limits](./known-limits.md)
before trusting a clean answer from either.

Java answers a narrower question again — there is no reference graph, so nothing
here comes from reachability — but its presence test is the only one in the
table that routinely **contradicts** a version scanner. The mitigation Apache
published for Log4Shell was

```sh
zip -d log4j-core.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

and the artifact is still `org.apache.logging.log4j:log4j-core@2.14.1`
afterwards. Listing a zip's central directory settles that; comparing versions
cannot.

`vexscan` was previously released as `gomod-vex`, which did the Go half only.
Existing `--module` command lines and `GOMODVEX_*` environment variables keep
working.

