package main

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/haul"
)

func img(ref, storeRef string, qualified bool) haul.Artifact {
	return haul.Artifact{Ref: ref, StoreRef: storeRef, Qualified: qualified, Type: haul.TypeImage}
}

func art(ref string, t haul.Type) haul.Artifact {
	return haul.Artifact{Ref: ref, StoreRef: ref, Qualified: true, Type: t}
}

// "no images" on its own reads as a broken file; the counts say it is a bundle
// built to carry something else.
func TestHaulContents(t *testing.T) {
	h := &haul.Haul{Artifacts: []haul.Artifact{
		art("hauler/rancher:2.8.2", haul.TypeChart),
		art("hauler/cert-manager:1.14", haul.TypeChart),
		art("hauler/install.sh:latest", haul.TypeFile),
		art("hauler/sig:1", haul.TypeAttached),
		art("hauler/mystery:1", haul.TypeUnknown),
	}}
	got := haulContents(h)
	for _, want := range []string{"2 charts", "1 file", "1 signature/attestation/SBOM", "1 unrecognised artifact"} {
		if !strings.Contains(got, want) {
			t.Errorf("haulContents = %q, missing %q", got, want)
		}
	}

	if got := haulContents(&haul.Haul{}); !strings.Contains(got, "nothing this reader recognised") {
		t.Errorf("an empty haul described as %q", got)
	}
}

// The governing rule in one test: a haul scan that covers eight of eleven
// artifacts must not print the same thing as one that covers all eight of
// eight.
func TestReportHaulSkipsNamesEveryGap(t *testing.T) {
	h := &haul.Haul{
		Artifacts: []haul.Artifact{
			img("docker.io/library/alpine:3.20", "library/alpine:3.20", true),
			img("rancher/klipper-helm:v0.9.4", "rancher/klipper-helm:v0.9.4", false),
			art("hauler/rancher:2.8.2", haul.TypeChart),
			art("hauler/install.sh:latest", haul.TypeFile),
			{Ref: "hauler/mystery:1", Type: haul.TypeUnknown, Detail: "unrecognised config media type application/vnd.example.v1+json"},
		},
		Skipped: 2,
	}
	out := stderrOf(t, func() { reportHaulSkips(h) })

	for _, want := range []string{
		// The chart, and both halves of what a chart in a haul means.
		"1 chart in this haul is not scanned",
		"hauler/rancher:2.8.2",
		"add-images",
		// The file.
		"1 file in this haul is not scanned",
		// The unclassified entry, loudest, with its reason.
		"1 artifact in this haul could not be classified",
		"hauler/mystery:1",
		"unrecognised config media type",
		// The registryless image and why it is not cosmetic.
		"1 image in this haul has no fully qualified reference",
		"rancher/klipper-helm:v0.9.4",
		"product purl",
		// The archive entries that were not unpacked.
		"2 entries in the haul archive were not",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("warning output is missing %q:\n%s", want, out)
		}
	}
}

// A haul with nothing but fully qualified images is the clean case and has to
// look like one, or the warnings stop meaning anything.
func TestReportHaulSkipsSaysNothingWhenThereIsNoGap(t *testing.T) {
	h := &haul.Haul{Artifacts: []haul.Artifact{
		img("docker.io/library/alpine:3.20", "library/alpine:3.20", true),
		img("ghcr.io/org/app:v1", "org/app:v1", true),
		// Signatures are not a gap: they are not scan targets and were never
		// going to be.
		art("hauler/app:sha256-abc.sig", haul.TypeAttached),
	}}
	if out := stderrOf(t, func() { reportHaulSkips(h) }); out != "" {
		t.Errorf("a complete haul scan warned anyway:\n%s", out)
	}
}

// The count in the warning is exact even when the sample under it is not.
func TestNameSomeCapsTheSample(t *testing.T) {
	h := &haul.Haul{}
	for _, name := range []string{"c8", "c7", "c6", "c5", "c4", "c3", "c2", "c1"} {
		h.Artifacts = append(h.Artifacts, art(name, haul.TypeChart))
	}
	out := stderrOf(t, func() { nameSome(h, haul.TypeChart) })

	if !strings.Contains(out, "... and 3 more") {
		t.Errorf("the sample was not capped:\n%s", out)
	}
	if n := strings.Count(out, "\n"); n != 6 {
		t.Errorf("printed %d lines, want 5 names and the elision", n)
	}
	// Sorted, so a haul's index order does not decide which five a reader sees.
	if !strings.HasPrefix(out, "         c1\n") {
		t.Errorf("the sample is not sorted:\n%s", out)
	}
}

func TestUnqualifiedListsOnlyImages(t *testing.T) {
	h := &haul.Haul{Artifacts: []haul.Artifact{
		img("docker.io/library/alpine:3.20", "library/alpine:3.20", true),
		img("rancher/b:1", "rancher/b:1", false),
		img("rancher/a:1", "rancher/a:1", false),
		// A chart's name is registryless too, and saying so would be noise:
		// nothing is going to scan it under any name.
		{Ref: "hauler/rancher:2.8.2", Type: haul.TypeChart},
	}}
	got := unqualified(h)
	if !equalStrings(got, []string{"rancher/a:1", "rancher/b:1"}) {
		t.Errorf("unqualified = %v", got)
	}
}

// The batch plumbing --haul added: every other target is its own address, and
// nothing about a registry scan may change because a haul scan needs two names.
func TestImageTargetsAndTargetRefs(t *testing.T) {
	refs := []string{"alpine:3.20", "ghcr.io/org/app:v1"}
	targets := imageTargets(refs)
	if len(targets) != 2 {
		t.Fatalf("imageTargets = %v", targets)
	}
	for i, tgt := range targets {
		if tgt.ref != refs[i] {
			t.Errorf("target %d ref = %q, want %q", i, tgt.ref, refs[i])
		}
		if tgt.storeRef != "" {
			t.Errorf("target %d has a store ref (%q); only a haul has one", i, tgt.storeRef)
		}
	}
	if !equalStrings(targetRefs(targets), refs) {
		t.Errorf("targetRefs = %v, want %v", targetRefs(targets), refs)
	}

	// Order is the input's, because it is the order the report prints in.
	haulish := []scanTarget{
		{ref: "docker.io/rancher/pause:3.6", storeRef: "rancher/pause:3.6"},
		{ref: "alpine:3.20", storeRef: "library/alpine:3.20"},
	}
	if !equalStrings(targetRefs(haulish), []string{"docker.io/rancher/pause:3.6", "alpine:3.20"}) {
		t.Errorf("targetRefs reordered its input: %v", targetRefs(haulish))
	}

	if got := imageTargets(nil); len(got) != 0 {
		t.Errorf("imageTargets(nil) = %v", got)
	}
}

func TestCountingHelpers(t *testing.T) {
	tests := []struct {
		name string
		fn   func(int) string
		one  string
		many string
	}{
		{"isAre", isAre, "is", "are"},
		{"waswere", waswere, "was", "were"},
		{"haveHas", haveHas, "has", "have"},
		{"theyIt", theyIt, "it is", "they are"},
		{"themIt", themIt, "it", "them"},
	}
	for _, tt := range tests {
		if got := tt.fn(1); got != tt.one {
			t.Errorf("%s(1) = %q, want %q", tt.name, got, tt.one)
		}
		for _, n := range []int{0, 2, 17} {
			if got := tt.fn(n); got != tt.many {
				t.Errorf("%s(%d) = %q, want %q", tt.name, n, got, tt.many)
			}
		}
	}
}
