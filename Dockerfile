# syntax=docker/dockerfile:1

# vexscan supports two modes with different runtime needs:
#   * image mode -> skopeo + a prebuilt govulncheck (binary scanning, no source)
#   * repo mode  -> git + a Go toolchain; govulncheck is built and run on demand
#     via `go run` from inside the target module so it always matches the Go
#     version that module requires (see internal/source). GOTOOLCHAIN=auto lets
#     Go fetch a newer toolchain when a scanned repo needs one.
# The runtime image ships all of them so both modes work out of the box.
#
# No dpkg/rpm/apk tooling is installed, and none is needed: the OS-package
# plugin parses all three databases in-process (see internal/pkgdb). The rpm
# reader uses a pure-Go sqlite driver specifically so this image can keep
# CGO_ENABLED=0 and cross-compile.

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0
WORKDIR /src

# Cache modules first: go-rpmdb and its sqlite driver are the only third-party
# dependencies, and they change far less often than the source does.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/vexscan .

# Prebuilt govulncheck for image (binary) mode. Repo mode does not use this; it
# builds govulncheck on demand with the toolchain the target module requires.
RUN mkdir /tmp/gv && cd /tmp/gv \
    && go mod init govulncheck-build >/dev/null \
    && go get golang.org/x/vuln/cmd/govulncheck@latest \
    && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" \
       -o /out/govulncheck golang.org/x/vuln/cmd/govulncheck

# Runtime: Go toolchain (repo mode) + git + skopeo (image mode) + the binaries.
FROM golang:${GO_VERSION}-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends skopeo git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/vexscan /usr/local/bin/vexscan
COPY --from=build /out/govulncheck /usr/local/bin/govulncheck

LABEL org.opencontainers.image.source="https://github.com/cwayne18/vexscan" \
      org.opencontainers.image.description="Check whether a CVE's vulnerable code is actually present and reachable in a container image or source repo (Go modules and OS packages)" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["vexscan"]
