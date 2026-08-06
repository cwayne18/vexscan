package vexpr

import "testing"

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
