package vexpr

import (
	"strings"
	"testing"
)

func TestProductLocation(t *testing.T) {
	cases := []struct {
		purl string
		want string
	}{
		{
			"pkg:golang/github.com/Altinity/clickhouse-backup/v2",
			"pkg/golang/github.com/Altinity/clickhouse-backup/v2/scan.openvex.json",
		},
		{
			"pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes",
			"pkg/oci/index.docker.io/rancher/hardened-kubernetes/scan.openvex.json",
		},
		{
			// An already-encoded repository_url decodes to the same path.
			"pkg:oci/hardened-kubernetes?repository_url=index.docker.io%2Francher%2Fhardened-kubernetes",
			"pkg/oci/index.docker.io/rancher/hardened-kubernetes/scan.openvex.json",
		},
	}
	for _, tc := range cases {
		got, err := productLocation(tc.purl)
		if err != nil {
			t.Errorf("productLocation(%q) error: %v", tc.purl, err)
			continue
		}
		if got != tc.want {
			t.Errorf("productLocation(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

func TestProductLocationRejectsUnsupported(t *testing.T) {
	for _, purl := range []string{
		"pkg:deb/debian/openssl@3.0.11-1",
		"not-a-purl",
		"pkg:oci/thing", // no repository_url
	} {
		if _, err := productLocation(purl); err == nil {
			t.Errorf("productLocation(%q) = nil error, want error", purl)
		}
	}
}

// TestProductLocationRejectsEscapes covers the reason productLocation validates
// at all.
//
// A golang product's name is the main module path, which vexscan reads out of
// the build info of a binary inside the image being scanned; an oci product's
// name comes from the image reference. On an untrusted target both are chosen
// by whoever built the thing, and both end up as a file path in someone else's
// repository. path.Join would clean "../.." into a working escape rather than
// object to it, so each of these must be an error and not a path.
func TestProductLocationRejectsEscapes(t *testing.T) {
	for _, purl := range []string{
		"pkg:golang/example.com/m/../../../../.github/workflows/release",
		"pkg:golang/../../../../README",
		"pkg:golang/./quiet",
		"pkg:golang/a//b",
		"pkg:golang/a/\\/b",
		"pkg:oci/x?repository_url=../../../.github/workflows",
		"pkg:oci/x?repository_url=%2E%2E%2F%2E%2E%2Fetc",
	} {
		got, err := productLocation(purl)
		if err == nil {
			t.Errorf("productLocation(%q) = %q, want an error", purl, got)
		}
	}
}

// TestProductLocationStaysUnderHubRoot is the property the individual cases are
// examples of: whatever comes back, it is a document inside pkg/.
func TestProductLocationStaysUnderHubRoot(t *testing.T) {
	for _, purl := range []string{
		"pkg:golang/github.com/Altinity/clickhouse-backup/v2",
		"pkg:golang/example.com/m/../../../../x",
		"pkg:oci/x?repository_url=index.docker.io/rancher/hardened-kubernetes",
		"pkg:oci/x?repository_url=../../../etc",
		"pkg:oci/x?repository_url=/etc/passwd",
	} {
		loc, err := productLocation(purl)
		if err != nil {
			continue // refused, which is the other acceptable outcome
		}
		if !strings.HasPrefix(loc, "pkg/") || strings.Contains(loc, "/../") {
			t.Errorf("productLocation(%q) = %q, which is not inside pkg/", purl, loc)
		}
	}
}

// TestCheckHubLocation pins the looser rule applied to a path the hub's own
// index.json supplied: a hub may file documents wherever it likes inside its
// repository, but not outside it.
func TestCheckHubLocation(t *testing.T) {
	for _, ok := range []string{
		"pkg/golang/example.com/m/scan.openvex.json",
		"documents/anything.json",
		"./nested/doc.json",
	} {
		if err := checkHubLocation(ok); err != nil {
			t.Errorf("checkHubLocation(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"/etc/passwd",
		"../../../.github/workflows/release.yml",
		"pkg/golang/../../.github/workflows/release.yml",
	} {
		if err := checkHubLocation(bad); err == nil {
			t.Errorf("checkHubLocation(%q) = nil, want an error", bad)
		}
	}
}

func TestIndexKey(t *testing.T) {
	cases := []struct {
		purl string
		want string
	}{
		{
			"pkg:golang/github.com/Altinity/clickhouse-backup/v2",
			"pkg:golang/github.com/Altinity/clickhouse-backup/v2",
		},
		{
			"pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes",
			"pkg:oci/hardened-kubernetes?repository_url=index.docker.io%2Francher%2Fhardened-kubernetes",
		},
	}
	for _, tc := range cases {
		got, err := indexKey(tc.purl)
		if err != nil {
			t.Errorf("indexKey(%q) error: %v", tc.purl, err)
			continue
		}
		if got != tc.want {
			t.Errorf("indexKey(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}
