---
sidebar_position: 2
title: "Quick start"
---


```sh
# Where does this CVE land, anywhere in the image? (searches every ecosystem)
vexscan --image debian:12 --cves CVE-2024-5535

# One Go module in a container image
vexscan --image rancher/hardened-kubernetes:v1.30.1 \
  --package golang:golang.org/x/net --cves CVE-2023-39325,CVE-2023-44487

# One OS package, with the shared-library closure as the presence test
vexscan --image debian:12 --package deb:openssl

# Everything the image installs, OS packages only
vexscan --image registry.access.redhat.com/ubi9/ubi:latest --all --ecosystem os

# One Python distribution, with the import graph as the reachability test
vexscan --image apache/airflow:latest --package pypi:requests

# Every npm package in the image
vexscan --image node:22-slim --all --ecosystem npm

# Every Java artifact in the image, jars nested inside a war or fat jar included
vexscan --image jenkins/jenkins:lts --all --ecosystem maven

# A whole fleet in one run: one row per image, advisories fetched once
vexscan --images-from fleet.txt --format summary
kubectl get pods -A -o jsonpath='{..image}' | tr ' ' '\n' | \
  vexscan --images-from - --format summary

# A hauler haul, scanned inside the airgap it was carried into — no registry
vexscan --haul rke2-airgap.tar.zst --all --format summary

# A filesystem tree rather than an image — an unpacked image, a mounted
# volume, a machine's own / (see below: no entrypoint, so pass --roots)
vexscan --rootfs /mnt/rootfs --all --roots /usr/bin/myapp

# An RPM nobody installed — a file, a directory of them, or a URL. Reads only
# the header, so the URL below costs 17 KB of a 2.3 MB package (see below)
vexscan --rpm ./openssl-libs-3.5.5-2.el9_8.x86_64.rpm --all
vexscan --rpm https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/o/openssl-libs-3.5.5-2.el9_8.x86_64.rpm --all

# A CycloneDX bill of materials, from a file or a pipe. Every finding is
# undetermined — a component names a package and nothing else (see below)
vexscan --sbom sbom.cdx.json --all
syft debian:12 -o cyclonedx-json | vexscan --sbom - --all

# Source repo (govulncheck source-mode reachability)
vexscan --repo github.com/rancher/rancher \
  --package golang:golang.org/x/net --cves CVE-2023-39325

# Source repo, lock file inventory (no import graph — see below)
vexscan --repo github.com/npm/cli --all --ecosystem npm

# Just list what is installed, with the names OSV will be queried by
vexscan --image debian:12 --format inventory
vexscan --rootfs /mnt/rootfs --format inventory
vexscan --rpm ./repo/x86_64/ --format inventory

# Advisories from somewhere other than api.osv.dev: a mirror or proxy that
# speaks the OSV API, or OSV's published data export on a host with no
# network at all (see below)
vexscan --image myorg/app:latest --all --osv-url http://osv-proxy.corp:8000
vexscan --image myorg/app:latest --all --osv-dir /srv/osv
```

