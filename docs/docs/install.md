---
sidebar_position: 22
title: "Install"
---


```sh
go install github.com/cwayne18/vexscan@latest
```

Or from source:

```sh
git clone https://github.com/cwayne18/vexscan
cd vexscan
go build -o vexscan .
```

Building with `-tags norpm` drops the rpm database reader and its dependencies;
rpm images then report as an unreadable ecosystem rather than being silently
skipped.

### Container image (GHCR)

A self-contained image bundling `skopeo`, `git`, `govulncheck` and a Go
toolchain is published to
[`ghcr.io/cwayne18/vexscan`](https://github.com/cwayne18/vexscan/pkgs/container/vexscan)
on every push to `main` and every `v*` tag:

```sh
docker run --rm ghcr.io/cwayne18/vexscan:latest \
  --image rancher/hardened-coredns:v1.8.6-build20231009 \
  --package golang:golang.org/x/net --cves CVE-2023-39325

docker run --rm -e VEXSCAN_LLM_ENDPOINT -e VEXSCAN_LLM_TOKEN \
  ghcr.io/cwayne18/vexscan:latest \
  --image myorg/myapp:latest --package golang:golang.org/x/crypto --llm
```

