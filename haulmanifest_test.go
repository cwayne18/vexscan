package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stderrOf runs fn with os.Stderr redirected and returns what it wrote. The
// warnings in this file are the feature -- a manifest scan is a subset of a
// haul scan and has to say so -- so they are worth asserting on.
func stderrOf(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	os.Stderr = saved
	w.Close()
	out := <-done
	r.Close()
	return out
}

const manifestImagesOnly = `apiVersion: content.hauler.cattle.io/v1
kind: Images
metadata:
  name: fleet
spec:
  images:
    - name: docker.io/library/alpine:3.20
    - name: ghcr.io/org/app:v1.2.3
`

// The three-document shape a real manifest has.
const manifestFull = `apiVersion: content.hauler.cattle.io/v1
kind: Images
metadata:
  name: fleet
spec:
  images:
    - name: docker.io/library/alpine:3.20
---
apiVersion: content.hauler.cattle.io/v1
kind: Charts
metadata:
  name: charts
spec:
  charts:
    - name: rancher
      repoURL: https://releases.rancher.com/server-charts/stable
      version: 2.8.2
      add-images: true
    - name: cert-manager
      repoURL: https://charts.jetstack.io
      version: v1.14.4
---
apiVersion: content.hauler.cattle.io/v1
kind: Files
metadata:
  name: files
spec:
  files:
    - path: rke2-install.sh
    - path: https://example.invalid/checksums.txt
`

func TestLooksLikeHaulerManifest(t *testing.T) {
	yes := []string{
		manifestImagesOnly,
		manifestFull,
		"apiVersion: content.hauler.cattle.io/v1alpha1\nkind: Images\n",
		`apiVersion: "content.hauler.cattle.io/v1"` + "\nkind: Images\n",
		"  apiVersion: collection.hauler.cattle.io/v1\n  kind: ThickCharts\n",
	}
	for _, s := range yes {
		if !looksLikeHaulerManifest(s) {
			t.Errorf("looksLikeHaulerManifest = false for:\n%s", s)
		}
	}

	no := []string{
		// The case that matters: a plain reference list is also valid YAML, and
		// nothing about it may change shape now that manifests are recognised.
		"alpine:3.20\ndebian:12\n",
		"# the fleet\nghcr.io/org/app@sha256:abc\n",
		"",
		// Some other tool's YAML.
		"apiVersion: apps/v1\nkind: Deployment\n",
		"apiVersion: v1\nkind: ConfigMap\n",
		// A near miss: the words, but not the group.
		"apiVersion: hauler.cattle.io/v1\nkind: Images\n",
		// And the group named in a comment rather than declared.
		"# built from content.hauler.cattle.io/v1\nalpine:3.20\n",
	}
	for _, s := range no {
		if looksLikeHaulerManifest(s) {
			t.Errorf("looksLikeHaulerManifest = true for:\n%s", s)
		}
	}
}

func TestParseHaulerManifest(t *testing.T) {
	var got []string
	out := stderrOf(t, func() {
		var err error
		got, err = parseHaulerManifest(manifestImagesOnly)
		if err != nil {
			t.Fatal(err)
		}
	})
	want := []string{"docker.io/library/alpine:3.20", "ghcr.io/org/app:v1.2.3"}
	if !equalStrings(got, want) {
		t.Errorf("images = %v, want %v", got, want)
	}
	if out != "" {
		t.Errorf("a manifest with nothing but images warned anyway:\n%s", out)
	}
}

// Every document is read, not just the first: stopping at the top would scan
// whatever the file happened to declare first.
func TestParseHaulerManifestReadsEveryDocument(t *testing.T) {
	var got []string
	out := stderrOf(t, func() {
		var err error
		got, err = parseHaulerManifest(manifestFull)
		if err != nil {
			t.Fatal(err)
		}
	})
	if !equalStrings(got, []string{"docker.io/library/alpine:3.20"}) {
		t.Errorf("images = %v", got)
	}

	// add-images is the one that has to be called out by name: hauler resolved
	// that chart's images into the store, so the haul holds images this
	// manifest does not name and this scan cannot reach.
	if !strings.Contains(out, "add-images") || !strings.Contains(out, "rancher") {
		t.Errorf("no add-images warning naming the chart:\n%s", out)
	}
	if !strings.Contains(out, "--haul") {
		t.Errorf("the add-images warning does not point at --haul:\n%s", out)
	}
	// The chart without add-images is a different gap and gets its own line.
	if !strings.Contains(out, "1 chart in this manifest is not scanned") {
		t.Errorf("no warning for the chart without add-images:\n%s", out)
	}
	if !strings.Contains(out, "2 files in this manifest are not scanned") {
		t.Errorf("no warning for the files:\n%s", out)
	}
}

func TestParseHaulerManifestDeduplicatesAndTrims(t *testing.T) {
	var got []string
	stderrOf(t, func() {
		var err error
		got, err = parseHaulerManifest(`apiVersion: content.hauler.cattle.io/v1
kind: Images
spec:
  images:
    - name: "  alpine:3.20  "
    - name: debian:12
    - name: alpine:3.20
    - name: ""
---
apiVersion: content.hauler.cattle.io/v1
kind: Images
spec:
  images:
    - name: debian:12
    - name: busybox:1.36
`)
		if err != nil {
			t.Fatal(err)
		}
	})
	want := []string{"alpine:3.20", "debian:12", "busybox:1.36"}
	if !equalStrings(got, want) {
		t.Errorf("images = %v, want %v", got, want)
	}
}

// A document that will not parse is an error, not a skip: returning the images
// from the documents that did parse would be a shorter list with no sign that
// it was short.
func TestParseHaulerManifestRefusesABrokenDocument(t *testing.T) {
	_, err := parseHaulerManifest(`apiVersion: content.hauler.cattle.io/v1
kind: Images
spec:
  images:
    - name: alpine:3.20
---
apiVersion: content.hauler.cattle.io/v1
kind: Images
spec:
  images:
   - name: [unclosed
`)
	if err == nil {
		t.Fatal("parseHaulerManifest accepted a manifest with an unparseable document")
	}
	if !strings.Contains(err.Error(), "document 2") {
		t.Errorf("the error does not say which document failed: %v", err)
	}
}

// A kind this does not read is named rather than ignored, because the thing it
// declares may well be images.
func TestParseHaulerManifestWarnsOnAnUnreadKind(t *testing.T) {
	out := stderrOf(t, func() {
		if _, err := parseHaulerManifest(`apiVersion: collection.hauler.cattle.io/v1
kind: K3s
spec:
  version: v1.31.0+k3s1
`); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "K3s") {
		t.Errorf("the unread kind was not named:\n%s", out)
	}
}

// A trailing "---" produces an empty document, which is not a kind this cannot
// read.
func TestParseHaulerManifestIgnoresEmptyDocuments(t *testing.T) {
	out := stderrOf(t, func() {
		got, err := parseHaulerManifest(manifestImagesOnly + "---\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Errorf("images = %v", got)
		}
	})
	if out != "" {
		t.Errorf("a trailing separator produced a warning:\n%s", out)
	}
}

// --images-from recognises a manifest where it finds one, and goes on reading
// everything else exactly as it did.
func TestReadImageListAcceptsAHaulerManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hauler-manifest.yaml")
	if err := os.WriteFile(path, []byte(manifestImagesOnly), 0o644); err != nil {
		t.Fatal(err)
	}

	var (
		got []imageEntry
		err error
	)
	stderrOf(t, func() { got, err = readImageList(context.Background(), path) })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"docker.io/library/alpine:3.20", "ghcr.io/org/app:v1.2.3"}
	if !equalStrings(entryRefs(got), want) {
		t.Errorf("readImageList = %v, want %v", entryRefs(got), want)
	}
}

func TestTally(t *testing.T) {
	tests := []struct {
		n    int
		unit string
		want string
	}{
		{1, "chart", "1 chart"},
		{2, "chart", "2 charts"},
		{0, "file", "0 files"},
		{1, "entry", "1 entry"},
		{3, "entry", "3 entries"},
		{1, "image", "1 image"},
		{7, "artifact", "7 artifacts"},
	}
	for _, tt := range tests {
		if got := tally(tt.n, tt.unit); got != tt.want {
			t.Errorf("tally(%d, %q) = %q, want %q", tt.n, tt.unit, got, tt.want)
		}
	}
}
