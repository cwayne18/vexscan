package golang

import "testing"

func TestIsDevelVersion(t *testing.T) {
	devel := []string{"", "(devel)", "devel", " (devel) ", "v0.0.0", "0.0.0", "garbage"}
	for _, v := range devel {
		if !isDevelVersion(v) {
			t.Errorf("isDevelVersion(%q) = false, want true (not comparable by OSV)", v)
		}
	}
	comparable := []string{"v1.36.3", "v1.36.3+k3s1", "v0.17.0", "1.2.3", "v1.2.3-rc1"}
	for _, v := range comparable {
		if isDevelVersion(v) {
			t.Errorf("isDevelVersion(%q) = true, want false (real semver)", v)
		}
	}
}

func TestImageTag(t *testing.T) {
	tests := []struct {
		ref, want string
	}{
		{"docker.io/rancher/k3s:v1.36.3-k3s1", "v1.36.3-k3s1"},
		{"registry:5000/rancher/k3s:v1.36.3-k3s1", "v1.36.3-k3s1"},
		{"rancher/rke2:v1.31.5-rke2r1", "v1.31.5-rke2r1"},
		{"alpine", ""},
		{"alpine:latest", "latest"},
		{"repo/img@sha256:deadbeef", ""},
		{"repo/img:v1.0.0@sha256:deadbeef", "v1.0.0"},
	}
	for _, tt := range tests {
		if got := imageTag(tt.ref); got != tt.want {
			t.Errorf("imageTag(%q) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}

func TestModuleVersionFromImageTag(t *testing.T) {
	tests := []struct {
		ref, wantVer string
		wantOK       bool
	}{
		// k3s/rke2 Docker tags convert their '-k3sN'/'-rke2rN' suffix back to
		// the '+' form the module and its advisories use.
		{"docker.io/rancher/k3s:v1.36.3-k3s1", "v1.36.3+k3s1", true},
		{"rancher/rke2:v1.31.5-rke2r1", "v1.31.5+rke2r1", true},
		// A plain semver tag is used as-is (with a 'v' ensured).
		{"example.com/app:v1.2.3", "v1.2.3", true},
		{"example.com/app:1.2.3", "v1.2.3", true},
		// An ordinary prerelease is left alone, not treated as k3s/rke2.
		{"example.com/app:v1.2.3-rc1", "v1.2.3-rc1", true},
		// Non-semver, floating and digest tags yield no inference.
		{"example.com/app:latest", "", false},
		{"example.com/app:20240101", "", false},
		{"example.com/app", "", false},
		{"example.com/app@sha256:deadbeef", "", false},
	}
	for _, tt := range tests {
		gotVer, _, gotOK := moduleVersionFromImageTag(tt.ref)
		if gotVer != tt.wantVer || gotOK != tt.wantOK {
			t.Errorf("moduleVersionFromImageTag(%q) = (%q, %v), want (%q, %v)",
				tt.ref, gotVer, gotOK, tt.wantVer, tt.wantOK)
		}
	}
}
