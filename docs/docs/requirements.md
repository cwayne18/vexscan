---
sidebar_position: 21
title: "Requirements"
---


- [`skopeo`](https://github.com/containers/skopeo) on `PATH` — image mode
- A Go toolchain on `PATH` — required at **runtime** for `--repo`, which builds
  and runs `govulncheck` itself via `go run` with `GOTOOLCHAIN=auto`
- `git` on `PATH` — repo mode, unless scanning a local path
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on
  `PATH` — optional, used only for Go binary mode
- Network access for OSV lookups, and for `--repo` cloning
- `GITHUB_TOKEN` / `GH_TOKEN` for `--gist`
- `git` and an authenticated `gh` — only for `contrib/vexhub-pr.sh`, which turns
  a `--vex-out` directory into a pull request. `--vex-out` itself needs neither.
  Add [`git-lfs`](https://git-lfs.com) for `--merge-into` against a hub that
  stores its merged report in LFS, as rancher/vexhub does
- Python 3.8+ — only for [`contrib/vexscan-dashboard.py`](./output/machine-formats.md#an-html-dashboard-contribvexscan-dashboardpy),
  which turns a `--format json` report into an HTML page. Standard library only,
  and it never touches the network
- An LLM provider for `--llm` — an endpoint and key, a local model, or an
  installed CLI. See [Choosing a provider](./llm-layer.md#choosing-a-provider); there is no
  default and nothing is required unless you pass `--llm`.

All three package databases are parsed in-process — no `dpkg`, `rpm` or `apk`
binary is needed. So are the Python and npm inventories and lock files, and the
Java archives: no `python`, `pip`, `node`, `npm`, `java` or `unzip` is required,
and nothing from the target is ever executed.

