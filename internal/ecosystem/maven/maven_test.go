package maven

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// jarBytes builds a zip in memory, so a jar in a test tree is just a file with
// unusual contents.
func jarBytes(t *testing.T, entries map[string]string) string {
	t.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entries[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// pom renders the META-INF/maven entry that makes an archive self-identifying.
func pom(group, artifact, version string) (string, string) {
	return fmt.Sprintf("META-INF/maven/%s/%s/pom.properties", group, artifact),
		fmt.Sprintf("groupId=%s\nartifactId=%s\nversion=%s\n", group, artifact, version)
}

// log4jJar is the flagship fixture, with or without the class the published
// mitigation says to delete.
func log4jJar(t *testing.T, withJndiLookup bool) string {
	t.Helper()
	name, body := pom("org.apache.logging.log4j", "log4j-core", "2.14.1")
	entries := map[string]string{
		name: body,
		"org/apache/logging/log4j/core/Logger.class": "",
	}
	if withJndiLookup {
		entries["org/apache/logging/log4j/core/lookup/JndiLookup.class"] = ""
	}
	return jarBytes(t, entries)
}

// javaImage writes a tree of files and wraps it as an image.
func javaImage(t *testing.T, files map[string]string) *target.Image {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &target.Image{Ref: "test", FS: target.NewDirFS(root)}
}

// findingsFor runs the whole plugin over one advisory.
func findingsFor(t *testing.T, img *target.Image, subjects []ecosystem.Subject, opts Options, adv *osv.Advisory) []ecosystem.Finding {
	t.Helper()
	ctx := context.Background()
	p := New(opts)

	ok, err := p.DetectImage(ctx, img)
	if err != nil {
		t.Fatalf("DetectImage: %v", err)
	}
	if !ok {
		t.Fatal("DetectImage said the plugin does not apply")
	}
	components, err := p.InventoryImage(ctx, img, subjects)
	if err != nil {
		t.Fatalf("InventoryImage: %v", err)
	}

	items := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		items = append(items, ecosystem.WorkItem{
			Component:  c,
			Advisories: map[string]*osv.Advisory{adv.ID: adv},
			Requested:  []string{adv.ID},
			Targeted:   len(subjects) > 0 && !subjects[0].MatchesAll(),
		})
	}

	findings, err := p.AnalyzeImage(ctx, img, items)
	if err != nil {
		t.Fatalf("AnalyzeImage: %v", err)
	}
	return findings
}

var anyAdvisory = &osv.Advisory{ID: "CVE-2024-0001", Summary: "a hole"}

// all is what the orchestrator hands a plugin for a --all run: one subject that
// names nothing and therefore selects everything.
var all = []ecosystem.Subject{{Raw: "--all"}}

// statuses runs the plugin over every artifact and keys the findings.
func statuses(t *testing.T, img *target.Image) map[string]ecosystem.Finding {
	t.Helper()
	out := map[string]ecosystem.Finding{}
	for _, f := range findingsFor(t, img, all, Options{}, anyAdvisory) {
		out[f.Module] = f
	}
	return out
}

// evidence renders a finding's evidence for an assertion message, and reports
// whether any of it is blocking.
func evidence(f ecosystem.Finding) (string, bool) {
	var b strings.Builder
	blocking := false
	for _, e := range f.Evidence {
		fmt.Fprintf(&b, "\n  [%s blocking=%v] %s", e.Origin, e.Blocking, e.Detail)
		blocking = blocking || e.Blocking
	}
	return b.String(), blocking
}

// The inventory rows of the status table, in one image.
func TestStatusTable(t *testing.T) {
	sourcesName, sourcesBody := pom("com.example", "thing", "1.0")
	img := javaImage(t, map[string]string{
		// Holds compiled code: present, and nothing here narrows it further.
		"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, true),
		// A sources jar is a real artifact at a real version that OSV will
		// match, and holds nothing a JVM can load.
		"/opt/lib/thing-1.0-sources.jar": jarBytes(t, map[string]string{
			sourcesName:                   sourcesBody,
			"com/example/thing/Main.java": "package com.example.thing;",
		}),
	})

	got := statuses(t, img)
	for _, tc := range []struct {
		name          string
		status        ecosystem.Status
		justification string
		method        string
	}{
		{"org.apache.logging.log4j:log4j-core", ecosystem.StatusLinked, "", MethodInventory},
		{"com.example:thing", ecosystem.StatusNotPresent, "vulnerable_code_not_present", MethodNoCode},
	} {
		f, ok := got[tc.name]
		if !ok {
			t.Errorf("%s: no finding", tc.name)
			continue
		}
		if f.Status != tc.status || f.Justification != tc.justification || f.Method != tc.method {
			ev, _ := evidence(f)
			t.Errorf("%s: status=%s justification=%q method=%q, want %s/%q/%s%s",
				tc.name, f.Status, f.Justification, f.Method,
				tc.status, tc.justification, tc.method, ev)
		}
	}
}

// An artifact the user named that no archive declares is a finding, not a
// silence.
func TestNamedArtifactThatIsNotInTheImage(t *testing.T) {
	img := javaImage(t, map[string]string{
		"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, true),
	})

	subject, err := ecosystem.ParseSubject("maven:com.fasterxml.jackson.core:jackson-databind")
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(t, img, []ecosystem.Subject{subject}, Options{}, anyAdvisory)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Status != ecosystem.StatusNotPresent || f.Justification != "component_not_present" {
		t.Errorf("status=%s justification=%q, want not_present/component_not_present",
			f.Status, f.Justification)
	}
}

// An archive nobody could open or name blocks the claim that an artifact is
// absent: the one that could not be identified could be the one being asked
// about.
func TestUnidentifiedArchiveBlocksAbsence(t *testing.T) {
	img := javaImage(t, map[string]string{
		"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, true),
		"/opt/lib/mystery.jar":           jarBytes(t, map[string]string{"a/B.class": ""}),
	})

	subject, err := ecosystem.ParseSubject("maven:com.example:thing")
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(t, img, []ecosystem.Subject{subject}, Options{}, anyAdvisory)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Status != ecosystem.StatusUndetermined || f.Reason != "unidentified_archive" {
		t.Errorf("status=%s reason=%q, want undetermined/unidentified_archive", f.Status, f.Reason)
	}
	if _, blocking := evidence(f); !blocking {
		ev, _ := evidence(f)
		t.Errorf("evidence is not blocking:%s", ev)
	}
}

// A jar that never said what it is still gets queried against OSV -- a name
// that matches nothing costs one entry in a batch -- but the finding has to say
// out loud that the name was reconstructed.
func TestReconstructedCoordinatesAreDeclared(t *testing.T) {
	img := javaImage(t, map[string]string{
		"/opt/lib/widget-1.0.0.jar": jarBytes(t, map[string]string{
			"net/corp/widget/Widget.class": "",
		}),
	})

	got := statuses(t, img)
	f, ok := got["net.corp.widget:widget"]
	if !ok {
		t.Fatalf("no finding for the reconstructed coordinate: %+v", got)
	}
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %s, want linked", f.Status)
	}
	ev, blocking := evidence(f)
	if !strings.Contains(ev, "reconstructed") {
		t.Errorf("evidence does not declare the guess:%s", ev)
	}
	// Not blocking. A guessed coordinate is a reason to doubt that OSV matched
	// the right artifact, which cuts both ways; it is not a reason to refuse
	// the status the analysis reached.
	if blocking {
		t.Errorf("coordinate taint should not block:%s", ev)
	}
}

// The same artifact in a container's lib directory and inside a war it deploys
// is one thing to say about the image.
func TestOneArtifactInTwoPlacesIsOneComponent(t *testing.T) {
	img := javaImage(t, map[string]string{
		"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, true),
		"/app/app.war": jarBytes(t, map[string]string{
			"WEB-INF/lib/log4j-core-2.14.1.jar":   log4jJar(t, true),
			"WEB-INF/classes/com/example/S.class": "",
		}),
	})

	var log4j []ecosystem.Finding
	for _, f := range findingsFor(t, img, all, Options{}, anyAdvisory) {
		if f.Module == "org.apache.logging.log4j:log4j-core" {
			log4j = append(log4j, f)
		}
	}
	if len(log4j) != 1 {
		t.Fatalf("got %d log4j findings, want 1", len(log4j))
	}
	ev, _ := evidence(log4j[0])
	for _, want := range []string{
		"/opt/lib/log4j-core-2.14.1.jar",
		"/app/app.war!/WEB-INF/lib/log4j-core-2.14.1.jar",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence does not name %s:%s", want, ev)
		}
	}
}

// A Maven coordinate is a bare name that contains a colon, and every Java tool
// in the world spells it that way. Parsing it as an ecosystem prefix would fail
// the scan with "unknown ecosystem org.apache.logging.log4j".
func TestBareMavenCoordinateIsANameNotAnEcosystem(t *testing.T) {
	for _, tc := range []struct{ raw, eco, name string }{
		{"org.apache.logging.log4j:log4j-core", "", "org.apache.logging.log4j:log4j-core"},
		{"maven:org.apache.logging.log4j:log4j-core", "maven", "org.apache.logging.log4j:log4j-core"},
		{"java:log4j-core", "maven", "log4j-core"},
		{"jar:log4j-core", "maven", "log4j-core"},
		// The existing spellings still work, and a Go module path -- the other
		// dotted thing here -- has no colon to be confused by.
		{"deb:openssl", "os", "openssl"},
		{"golang:golang.org/x/net", "golang", "golang.org/x/net"},
		{"golang.org/x/net", "", "golang.org/x/net"},
	} {
		s, err := ecosystem.ParseSubject(tc.raw)
		if err != nil {
			t.Errorf("ParseSubject(%q): %v", tc.raw, err)
			continue
		}
		if s.Ecosystem != tc.eco || s.Name != tc.name {
			t.Errorf("ParseSubject(%q) = ecosystem %q name %q, want %q, %q",
				tc.raw, s.Ecosystem, s.Name, tc.eco, tc.name)
		}
	}
}

// A user who says "log4j-core" has said something unambiguous enough to act on,
// and looking up the groupId afterwards is what they were going to do anyway.
func TestBareArtifactIdSelectsTheArtifact(t *testing.T) {
	img := javaImage(t, map[string]string{
		"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, true),
		"/opt/lib/guava-32.1.3-jre.jar": jarBytes(t, func() map[string]string {
			name, body := pom("com.google.guava", "guava", "32.1.3-jre")
			return map[string]string{name: body, "com/google/common/collect/Lists.class": ""}
		}()),
	})

	subject, err := ecosystem.ParseSubject("maven:log4j-core")
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(t, img, []ecosystem.Subject{subject}, Options{}, anyAdvisory)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want just log4j-core: %+v", len(got), got)
	}
	if got[0].Module != "org.apache.logging.log4j:log4j-core" {
		t.Errorf("module = %s, want org.apache.logging.log4j:log4j-core", got[0].Module)
	}
}

func TestPURLRoundTrip(t *testing.T) {
	img := javaImage(t, map[string]string{
		"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, true),
	})

	subject, err := ecosystem.ParseSubject("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(t, img, []ecosystem.Subject{subject}, Options{}, anyAdvisory)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if want := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"; got[0].PURL != want {
		t.Errorf("purl = %q, want %q", got[0].PURL, want)
	}
}

// An image with no Java in it must not produce a Maven section at all. An empty
// inventory renders as "nothing vulnerable", which is the one thing this tool
// must never manufacture.
func TestPluginDoesNotApplyWithoutArchives(t *testing.T) {
	img := javaImage(t, map[string]string{"/usr/bin/app": "ELF"})
	ok, err := New(Options{}).DetectImage(context.Background(), img)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("DetectImage said maven applies to an image with no archives")
	}
}
