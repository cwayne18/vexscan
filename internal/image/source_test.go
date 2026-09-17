package image

import "testing"

func TestSkopeoSource(t *testing.T) {
	tests := []struct {
		name string
		src  Source
		want string
	}{
		{
			"a registry reference",
			Source{Ref: "docker.io/library/alpine:3.20"},
			"docker://docker.io/library/alpine:3.20",
		},
		{
			"a digest reference",
			Source{Ref: "ghcr.io/org/app@sha256:abc123"},
			"docker://ghcr.io/org/app@sha256:abc123",
		},
		{
			// The haul case. The image is reported under its fully qualified
			// name and read out of the layout under the registryless one
			// hauler filed it as; collapsing the two would look for
			// "docker.io/rancher/pause:3.6" in a layout that has no such entry.
			"a layout entry whose store name differs from its reference",
			Source{
				Ref:       "docker.io/rancher/pause:3.6",
				Layout:    "/tmp/vexscan-haul-123",
				LayoutRef: "rancher/pause:3.6",
			},
			"oci:/tmp/vexscan-haul-123:rancher/pause:3.6",
		},
		{
			// No store name recorded, so the reference is the best there is.
			"a layout entry with no store name",
			Source{Ref: "rancher/pause:3.6", Layout: "/tmp/haul"},
			"oci:/tmp/haul:rancher/pause:3.6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.src.skopeoSource(); got != tt.want {
				t.Errorf("skopeoSource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSourceValidate(t *testing.T) {
	ok := []Source{
		{Ref: "alpine:3.20"},
		{Ref: "alpine:3.20", Layout: "/tmp/haul", LayoutRef: "library/alpine:3.20"},
		{Ref: "alpine:3.20", Layout: "/var/tmp/haul-2026-09-16"},
	}
	for _, s := range ok {
		if err := s.validate(); err != nil {
			t.Errorf("validate(%+v) = %v", s, err)
		}
	}

	// A layout path with a colon in it cannot be addressed: the oci: transport
	// cuts at the first colon, so the path and the reference would both come
	// out wrong, and skopeo would report a missing image rather than a name it
	// could not parse.
	bad := []Source{
		{Ref: ""},
		{Ref: "alpine:3.20", Layout: "/tmp/haul:1"},
		{Ref: "alpine:3.20", Layout: "C:/hauls/store"},
	}
	for _, s := range bad {
		if err := s.validate(); err == nil {
			t.Errorf("validate(%+v) = nil, want an error", s)
		}
	}
}
