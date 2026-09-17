package haul

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A layout built by hand, because the properties under test are about what an
// index says rather than about what is in the blobs, and a real haul is a
// gigabyte of things none of these assertions look at.

// layout accumulates manifests and blobs and writes an OCI layout.
type layout struct {
	t         *testing.T
	dir       string
	manifests []map[string]any
}

func newLayout(t *testing.T) *layout {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return &layout{t: t, dir: dir}
}

// blob writes content into the layout and returns its digest.
func (l *layout) blob(content string) string {
	l.t.Helper()
	sum := sha256.Sum256([]byte(content))
	hexsum := hex.EncodeToString(sum[:])
	dir := filepath.Join(l.dir, "blobs", "sha256")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hexsum), []byte(content), 0o644); err != nil {
		l.t.Fatal(err)
	}
	return "sha256:" + hexsum
}

// manifestBlob writes a manifest whose config has the given media type.
func (l *layout) manifestBlob(configType string) string {
	l.t.Helper()
	b, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIManifest,
		"config":        map[string]any{"mediaType": configType, "digest": "sha256:" + hex.EncodeToString(make([]byte, 32)), "size": 0},
		"layers":        []any{},
	})
	if err != nil {
		l.t.Fatal(err)
	}
	return l.blob(string(b))
}

func (l *layout) entry(mediaType, digest string, ann map[string]string) *layout {
	l.manifests = append(l.manifests, map[string]any{
		"mediaType":   mediaType,
		"digest":      digest,
		"size":        1,
		"annotations": ann,
	})
	return l
}

// write renders the index under the given file name and returns the layout dir.
func (l *layout) write(name string) string {
	l.t.Helper()
	b, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": l.manifests})
	if err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.dir, name), b, 0o644); err != nil {
		l.t.Fatal(err)
	}
	return l.dir
}

func open(t *testing.T, dir string) *Haul {
	t.Helper()
	h, err := Open(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func find(t *testing.T, h *Haul, storeRef string) Artifact {
	t.Helper()
	for _, a := range h.Artifacts {
		if a.StoreRef == storeRef {
			return a
		}
	}
	t.Fatalf("no artifact with store ref %q in %+v", storeRef, h.Artifacts)
	return Artifact{}
}

// The whole point of reading hauler's annotations rather than the OCI one:
// the store name has had its registry stripped, and scanning under it would
// file the findings under a product purl no --image scan would produce.
func TestQualifiedReferenceIsRecovered(t *testing.T) {
	l := newLayout(t)
	img := l.manifestBlob(mtOCIConfig)

	l.entry(mtOCIManifest, img, map[string]string{
		annRefName:     "rancher/hardened-kubernetes:v1.31.0",
		annOriginalRef: "docker.io/rancher/hardened-kubernetes:v1.31.0",
		annKind:        kindImage,
	})
	l.entry(mtOCIManifest, img, map[string]string{
		annRefName:        "rancher/mirrored-pause:3.6",
		annContainerdName: "docker.io/rancher/mirrored-pause:3.6",
		annKind:           kindImage,
	})
	// A hauler v1 store, or the v2 window where the containerd name was lost.
	l.entry(mtOCIManifest, img, map[string]string{
		annRefName: "rancher/klipper-helm:v0.9.4",
		annKind:    kindImage,
	})
	h := open(t, l.write(indexFile))

	tests := []struct {
		storeRef  string
		wantRef   string
		qualified bool
	}{
		{"rancher/hardened-kubernetes:v1.31.0", "docker.io/rancher/hardened-kubernetes:v1.31.0", true},
		{"rancher/mirrored-pause:3.6", "docker.io/rancher/mirrored-pause:3.6", true},
		{"rancher/klipper-helm:v0.9.4", "rancher/klipper-helm:v0.9.4", false},
	}
	for _, tt := range tests {
		a := find(t, h, tt.storeRef)
		if a.Ref != tt.wantRef {
			t.Errorf("%s: ref = %q, want %q", tt.storeRef, a.Ref, tt.wantRef)
		}
		if a.Qualified != tt.qualified {
			t.Errorf("%s: qualified = %v, want %v", tt.storeRef, a.Qualified, tt.qualified)
		}
		// Whatever the reported name, the addressing name is the store's.
		if a.StoreRef != tt.storeRef {
			t.Errorf("store ref = %q, want %q", a.StoreRef, tt.storeRef)
		}
	}
}

// original-ref for a chart is hauler's "repoURL|repo:tag" encoding, which is
// not a reference and must not be mistaken for one.
func TestChartOriginalRefIsNotTakenAsAReference(t *testing.T) {
	l := newLayout(t)
	l.entry(mtOCIManifest, l.manifestBlob(mtChartConfig), map[string]string{
		annRefName:     "hauler/rancher:2.8.2",
		annOriginalRef: "https://releases.rancher.com/server-charts/stable|rancher:2.8.2",
	})
	h := open(t, l.write(indexFile))

	a := find(t, h, "hauler/rancher:2.8.2")
	if a.Ref != "hauler/rancher:2.8.2" {
		t.Errorf("ref = %q, want the store name", a.Ref)
	}
	if a.Qualified {
		t.Error("a chart's encoded original-ref was reported as a qualified reference")
	}
	if a.Type != TypeChart {
		t.Errorf("type = %q, want chart", a.Type)
	}
}

func TestClassification(t *testing.T) {
	l := newLayout(t)
	add := func(name, mediaType, digest string, ann map[string]string) {
		if ann == nil {
			ann = map[string]string{}
		}
		ann[annRefName] = name
		l.entry(mediaType, digest, ann)
	}

	add("by-kind:1", mtOCIManifest, l.manifestBlob(mtChartConfig), map[string]string{annKind: kindImage})
	add("by-kind-index:1", mtOCIManifest, l.manifestBlob(mtChartConfig), map[string]string{annKind: kindImageIndex})
	add("sigs:1", mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{annKind: kindSigs})
	add("atts:1", mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{annKind: kindAtts})
	add("sboms:1", mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{annKind: kindSboms})
	add("referrers:1", mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{annKind: kindReferrers + "/abc123"})
	add("multiarch:1", mtOCIIndex, l.manifestBlob(mtOCIConfig), nil)
	add("dockerlist:1", mtDockerList, l.manifestBlob(mtOCIConfig), nil)
	add("dockermanifest:1", mtDockerManifest, l.manifestBlob(mtOCIConfig), nil)
	add("ociimage:1", mtOCIManifest, l.manifestBlob(mtOCIConfig), nil)
	add("dockerconfig:1", mtOCIManifest, l.manifestBlob(mtDockerConfig), nil)
	add("chart:1", mtOCIManifest, l.manifestBlob(mtChartConfig), nil)
	add("filelocal:1", mtOCIManifest, l.manifestBlob(mtFileConfigLocal), nil)
	add("filehttp:1", mtOCIManifest, l.manifestBlob(mtFileConfigHTTP), nil)
	add("filedir:1", mtOCIManifest, l.manifestBlob(mtFileConfigDir), nil)
	add("weirdconfig:1", mtOCIManifest, l.manifestBlob("application/vnd.example.something.v1+json"), nil)
	add("weirdmanifest:1", "application/vnd.example.manifest.v9+json", l.manifestBlob(mtOCIConfig), nil)
	add("missingblob:1", mtOCIManifest, "sha256:"+hex.EncodeToString(make([]byte, 32)), nil)

	h := open(t, l.write(indexFile))

	want := map[string]Type{
		// The kind annotation wins over the config media type, which is what
		// lets a hauler-written image be recognised without reading a blob.
		"by-kind:1":        TypeImage,
		"by-kind-index:1":  TypeImage,
		"sigs:1":           TypeAttached,
		"atts:1":           TypeAttached,
		"sboms:1":          TypeAttached,
		"referrers:1":      TypeAttached,
		"multiarch:1":      TypeImage,
		"dockerlist:1":     TypeImage,
		"dockermanifest:1": TypeImage,
		"ociimage:1":       TypeImage,
		"dockerconfig:1":   TypeImage,
		"chart:1":          TypeChart,
		"filelocal:1":      TypeFile,
		"filehttp:1":       TypeFile,
		"filedir:1":        TypeFile,
		// The three that must not be silently dropped.
		"weirdconfig:1":   TypeUnknown,
		"weirdmanifest:1": TypeUnknown,
		"missingblob:1":   TypeUnknown,
	}
	if len(h.Artifacts) != len(want) {
		t.Fatalf("got %d artifacts, want %d", len(h.Artifacts), len(want))
	}
	for name, typ := range want {
		if a := find(t, h, name); a.Type != typ {
			t.Errorf("%s: type = %q, want %q", name, a.Type, typ)
		}
	}
	// An unknown has to say why, so the warning the CLI prints can name the
	// reason rather than just the count.
	for _, name := range []string{"weirdconfig:1", "weirdmanifest:1", "missingblob:1"} {
		if a := find(t, h, name); a.Detail == "" {
			t.Errorf("%s: unknown artifact carries no explanation", name)
		}
	}
	if got := h.Count(TypeImage); got != 7 {
		t.Errorf("image count = %d, want 7", got)
	}
	if got := len(h.Images()); got != 7 {
		t.Errorf("Images() = %d, want 7", got)
	}
}

// An index entry with no ref name is the layout's own plumbing, not a missing
// image: hauler's own store walk skips exactly these.
func TestEntriesWithoutARefNameAreNotArtifacts(t *testing.T) {
	l := newLayout(t)
	l.entry(mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{annRefName: "app:1"})
	l.entry(mtOCIManifest, l.manifestBlob(mtOCIConfig), nil)
	h := open(t, l.write(indexFile))

	if len(h.Artifacts) != 1 {
		t.Fatalf("got %d artifacts, want 1: %+v", len(h.Artifacts), h.Artifacts)
	}
}

// `hauler store save --containerd` writes a filtered index.json and keeps the
// real one in a sidecar, which its own store load prefers. A reader that
// trusted index.json would see fewer artifacts than the haul holds, on exactly
// the hauls most likely to be in an airgap.
func TestSidecarIndexWinsOverAFilteredIndexJSON(t *testing.T) {
	l := newLayout(t)
	img := l.manifestBlob(mtOCIConfig)
	chart := l.manifestBlob(mtChartConfig)

	// The filtered index: images only.
	l.entry(mtOCIManifest, img, map[string]string{annRefName: "app:1", annKind: kindImage})
	dir := l.write(indexFile)

	// The sidecar: everything.
	l.entry(mtOCIManifest, chart, map[string]string{annRefName: "hauler/chart:1"})
	l.write(indexSidecar)

	h := open(t, dir)
	if len(h.Artifacts) != 2 {
		t.Fatalf("got %d artifacts, want 2 -- index.json was read instead of the sidecar", len(h.Artifacts))
	}
	if got := h.Count(TypeChart); got != 1 {
		t.Errorf("chart count = %d, want 1", got)
	}
}

// A layout one level down is found, because not every tree that reaches this
// was written by `hauler store save`.
func TestLayoutIsFoundOneLevelDown(t *testing.T) {
	parent := t.TempDir()
	l := newLayout(t)
	l.entry(mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{annRefName: "app:1"})
	inner := l.write(indexFile)

	nested := filepath.Join(parent, "store")
	if err := os.Rename(inner, nested); err != nil {
		t.Fatal(err)
	}
	h := open(t, parent)
	if h.Dir != nested {
		t.Errorf("Dir = %q, want %q", h.Dir, nested)
	}
	if len(h.Artifacts) != 1 {
		t.Errorf("got %d artifacts, want 1", len(h.Artifacts))
	}
}

// Two layouts in one tree is refused rather than guessed at: picking either
// would scan half a haul and report it as the whole one.
func TestTwoLayoutsInOneTreeIsAnError(t *testing.T) {
	parent := t.TempDir()
	for _, name := range []string{"store-a", "store-b"} {
		l := newLayout(t)
		l.entry(mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{annRefName: "app:1"})
		if err := os.Rename(l.write(indexFile), filepath.Join(parent, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(context.Background(), parent, nil); err == nil {
		t.Fatal("Open accepted a tree holding two layouts")
	}
}

func TestNotALayoutIsAnError(t *testing.T) {
	if _, err := Open(context.Background(), t.TempDir(), nil); err == nil {
		t.Fatal("Open accepted a directory with no index in it")
	}
}

// A descriptor is untrusted input, and a digest is a string that ends up in a
// path.
func TestBlobPathRejectsAMalformedDigest(t *testing.T) {
	for _, digest := range []string{
		"sha256:../../../../etc/passwd",
		"../evil:cafe",
		"sha256:CAFEBABE", // upper case is not a valid lowercase-hex digest
		"sha256:",
		"cafebabe",
		"",
		"sha256:cafe/babe",
	} {
		if p, err := blobPath("/root", digest); err == nil {
			t.Errorf("blobPath(%q) = %q, want an error", digest, p)
		}
	}
	got, err := blobPath("/root", "sha256:cafebabe")
	if err != nil {
		t.Fatalf("blobPath rejected a good digest: %v", err)
	}
	if want := filepath.Join("/root", "blobs", "sha256", "cafebabe"); got != want {
		t.Errorf("blobPath = %q, want %q", got, want)
	}
}

// A manifest read is capped, so a descriptor pointing at a multi-gigabyte
// layer blob cannot be read into memory as if it were a manifest.
func TestOversizeManifestIsNotRead(t *testing.T) {
	l := newLayout(t)
	big := l.blob(`{"config":{"mediaType":"` + mtOCIConfig + `"},"pad":"` +
		strings.Repeat("a", maxManifestBytes) + `"}`)
	l.entry(mtOCIManifest, big, map[string]string{annRefName: "fat:1"})
	h := open(t, l.write(indexFile))

	a := find(t, h, "fat:1")
	if a.Type != TypeUnknown {
		t.Errorf("type = %q, want unknown: an oversize manifest was read anyway", a.Type)
	}
}

// Close removes an unpacked haul and leaves a directory the caller owns alone.
func TestCloseOnlyRemovesWhatItUnpacked(t *testing.T) {
	l := newLayout(t)
	l.entry(mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{annRefName: "app:1"})
	dir := l.write(indexFile)

	h, err := Open(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.Extracted {
		t.Error("a store directory was reported as extracted")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("Close removed a directory it did not create: %v", err)
	}
}

func TestOpenReadsAnArchive(t *testing.T) {
	l := newLayout(t)
	l.entry(mtOCIManifest, l.manifestBlob(mtOCIConfig), map[string]string{
		annRefName:     "rancher/pause:3.6",
		annOriginalRef: "docker.io/rancher/pause:3.6",
		annKind:        kindImage,
	})
	dir := l.write(indexFile)

	for _, tt := range []struct {
		name     string
		compress bool
	}{{"tar.zst", true}, {"tar", false}} {
		t.Run(tt.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "haul."+tt.name)
			writeArchive(t, dir, archive, tt.compress)

			h, err := Open(context.Background(), archive, nil)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer h.Close()

			if !h.Extracted {
				t.Error("an archive was not reported as extracted")
			}
			if len(h.Images()) != 1 {
				t.Fatalf("got %d images, want 1", len(h.Images()))
			}
			if got := h.Images()[0].Ref; got != "docker.io/rancher/pause:3.6" {
				t.Errorf("ref = %q", got)
			}

			unpacked := h.Dir
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(unpacked); !os.IsNotExist(err) {
				t.Errorf("Close left the unpacked haul behind at %s", unpacked)
			}
		})
	}
}

func TestOpenRejectsAMissingPath(t *testing.T) {
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "nope.tar.zst"), nil); err == nil {
		t.Fatal("Open accepted a path that does not exist")
	}
}
