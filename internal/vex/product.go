package vex

import (
	"net/url"
	"strings"
)

// ImageProduct turns a container image reference into the product purl a VEX
// hub indexes it under.
//
//	rancher/hardened-kubernetes:v1.30.1
//	  -> pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes
//
// The normalization is Docker's, because that is what the hub's keys were
// written with: a bare name is under library/, a missing registry is
// index.docker.io, and docker.io is spelled index.docker.io. The tag and digest
// are dropped -- a hub keys a repository, not a release, and the statements
// inside carry their own timestamps.
//
// Returns "" for a reference it cannot make sense of, which the caller should
// treat as "no product to look up" rather than as an error.
func ImageProduct(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	// Digest first: a digest can contain ':' and would confuse tag stripping.
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// A tag is a ':' in the last path segment; a ':' earlier in the string is a
	// registry port.
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
		ref = ref[:i]
	}
	ref = strings.Trim(ref, "/")
	if ref == "" {
		return ""
	}

	registry := "index.docker.io"
	path := ref
	if i := strings.Index(ref, "/"); i >= 0 {
		if head := ref[:i]; isRegistry(head) {
			registry, path = head, ref[i+1:]
			if registry == "docker.io" {
				registry = "index.docker.io"
			}
		}
	}
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	if registry == "index.docker.io" && !strings.Contains(path, "/") {
		path = "library/" + path
	}

	name := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		name = path[i+1:]
	}
	return "pkg:oci/" + name + "?repository_url=" + registry + "/" + path
}

// isRegistry reports whether a leading reference segment is a registry host
// rather than the first part of a repository path. Docker's own rule: a dot, a
// port, or the literal localhost.
func isRegistry(s string) bool {
	return s == "localhost" || strings.Contains(s, ".") || strings.Contains(s, ":")
}

// GoProduct turns a Go main module path into its product purl.
//
// No escaping is applied: a hub's golang keys are written as the plain module
// path, upper-case letters and all (pkg:golang/github.com/Altinity/...), which
// is also exactly what build info reports.
func GoProduct(mainModule string) string {
	mainModule = strings.Trim(strings.TrimSpace(mainModule), "/")
	if mainModule == "" {
		return ""
	}
	return "pkg:golang/" + mainModule
}

// canonicalProduct puts a product purl into the one spelling used for
// comparison.
//
// The index writes keys percent-encoded
// (repository_url=index.docker.io%2Francher%2F...) while the @id inside the
// document it points at is not encoded at all, so the two only line up once
// both are decoded. PathUnescape rather than QueryUnescape: '+' is a legal
// character in a purl and must not become a space.
func canonicalProduct(purl string) string {
	purl = strings.TrimSpace(purl)
	if dec, err := url.PathUnescape(purl); err == nil {
		purl = dec
	}
	return purl
}
