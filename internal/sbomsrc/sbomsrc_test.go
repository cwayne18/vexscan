package sbomsrc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/pkgdb"
)

// read decodes a document written inline, so every fixture is readable beside
// the assertion it supports.
func read(t *testing.T, body string) *Result {
	t.Helper()
	res, err := Read(strings.NewReader(body), "a test", nil)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return res
}

func byName(res *Result, name string) (Component, bool) {
	for _, c := range res.Components {
		if c.Name == name {
			return c, true
		}
	}
	return Component{}, false
}

// The Debian shape, as trivy writes it: an operating-system component with no
// purl, packages whose distro qualifier carries the id, and the source name in
// a producer-namespaced property.
const debianBill = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "components": [
    {"bom-ref": "os", "type": "operating-system", "name": "debian", "version": "12.15"},
    {"type": "library", "name": "libssl3", "version": "3.0.16-1~deb12u1",
     "purl": "pkg:deb/debian/libssl3@3.0.16-1~deb12u1?arch=amd64&distro=debian-12.15",
     "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "openssl"}]},
    {"type": "library", "name": "base-files", "version": "12.4+deb12u15",
     "purl": "pkg:deb/debian/base-files@12.4%2Bdeb12u15?arch=amd64&distro=debian-12.15",
     "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "base-files"}]}
  ]
}`

func TestADebianBillResolvesToDebian(t *testing.T) {
	res := read(t, debianBill)

	c, ok := byName(res, "libssl3")
	if !ok {
		t.Fatalf("libssl3 is not in %+v", res.Components)
	}
	if c.PluginID != "os" || c.Format != pkgdb.FormatDeb {
		t.Errorf("plugin/format = %q/%q, want os/deb", c.PluginID, c.Format)
	}
	// The ecosystem is not resolved here -- ospkg owns that -- but the identity
	// handed to it has to be the one that produces the right answer.
	eco, err := c.Release.Ecosystem()
	if err != nil || eco != "Debian:12" {
		t.Errorf("ecosystem = %q, %v; want Debian:12", eco, err)
	}
	// Debian files every advisory against the source package. Missing this
	// queries OSV for "libssl3", which has no records, and reads as clean.
	if c.Source != "openssl" {
		t.Errorf("source = %q, want openssl -- Debian advisories are filed against it", c.Source)
	}
	if c.Version != "3.0.16-1~deb12u1" {
		t.Errorf("version = %q", c.Version)
	}
	if c.Arch != "amd64" {
		t.Errorf("arch = %q", c.Arch)
	}

	// A source name equal to the binary name is not a second name to query.
	base, _ := byName(res, "base-files")
	if base.Source != "" {
		t.Errorf("base-files source = %q, want empty", base.Source)
	}
	if base.Version != "12.4+deb12u15" {
		t.Errorf("base-files version = %q, want the '+' decoded as a plus", base.Version)
	}
}

// trivy writes Alpine's distro qualifier as a bare version -- "distro=3.19.9",
// not "distro=alpine-3.19.9" -- so the id has to come from the purl namespace.
// Reading it as an id would produce no ecosystem, and no ecosystem is a query
// that finds nothing.
func TestAnAlpineBillResolvesFromABareDistroVersion(t *testing.T) {
	res := read(t, `{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"type": "library", "name": "alpine-baselayout-data", "version": "3.4.3-r2",
	     "purl": "pkg:apk/alpine/alpine-baselayout-data@3.4.3-r2?arch=x86_64&distro=3.19.9",
	     "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "alpine-baselayout"}]}
	  ]
	}`)
	c := res.Components[0]
	eco, err := c.Release.Ecosystem()
	if err != nil || eco != "Alpine:v3.19" {
		t.Errorf("ecosystem = %q, %v; want Alpine:v3.19", eco, err)
	}
	// Alpine files advisories against the origin, and the origin is only in
	// the property: these purls carry no upstream qualifier at all.
	if c.Source != "alpine-baselayout" {
		t.Errorf("source = %q, want alpine-baselayout", c.Source)
	}
}

// syft's spelling of the same two facts: the id inside the qualifier, the
// source in an upstream qualifier rather than a property.
func TestTheSyftSpellingOfDistroAndUpstream(t *testing.T) {
	res := read(t, `{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"type": "library", "name": "libssl3", "version": "3.0.11-1~deb12u2",
	     "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl"}
	  ]
	}`)
	c := res.Components[0]
	if eco, err := c.Release.Ecosystem(); err != nil || eco != "Debian:12" {
		t.Errorf("ecosystem = %q, %v; want Debian:12", eco, err)
	}
	if c.Source != "openssl" {
		t.Errorf("source = %q, want openssl", c.Source)
	}
}

// An Ubuntu LTS release is a different OSV ecosystem from the interim release
// beside it, and only one of the two has records. An SBOM carries no
// PRETTY_NAME to read it off, so the version has to settle it.
func TestUbuntuLTSSurvivesTheTripThroughAPURL(t *testing.T) {
	for _, tt := range []struct{ distro, want string }{
		{"ubuntu-22.04", "Ubuntu:22.04:LTS"},
		{"ubuntu-24.04", "Ubuntu:24.04:LTS"},
		{"ubuntu-23.04", "Ubuntu:23.04"},
		{"ubuntu-24.10", "Ubuntu:24.10"},
	} {
		res := read(t, `{"bomFormat":"CycloneDX","components":[
		  {"type":"library","name":"libc6","version":"2.35-0ubuntu3",
		   "purl":"pkg:deb/ubuntu/libc6@2.35-0ubuntu3?distro=`+tt.distro+`"}]}`)
		got, err := res.Components[0].Release.Ecosystem()
		if err != nil || got != tt.want {
			t.Errorf("%s: ecosystem = %q, %v; want %q", tt.distro, got, err, tt.want)
		}
	}
}

// rpm records are written with an epoch and version comparison is literal, so a
// component that arrives without one has to be given the zero it means. The
// other direction -- comparing "3.0.7-24.el9" against "1:3.0.7-24.el9" -- makes
// a fully patched package look old, and no amount of patching clears it.
func TestRPMVersionsAlwaysCarryAnEpoch(t *testing.T) {
	for _, tt := range []struct {
		purl        string
		want        string
		wantedEpoch int
	}{
		{"pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?distro=rocky-9.3", "0:3.0.7-24.el9", 0},
		{"pkg:rpm/rocky/openssl-libs@1:3.0.7-24.el9?distro=rocky-9.3", "1:3.0.7-24.el9", 1},
		{"pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?epoch=2&distro=rocky-9.3", "2:3.0.7-24.el9", 2},
	} {
		res := read(t, `{"bomFormat":"CycloneDX","components":[
		  {"type":"library","name":"openssl-libs","purl":"`+tt.purl+`"}]}`)
		c := res.Components[0]
		if c.Version != tt.want || c.Epoch != tt.wantedEpoch {
			t.Errorf("%s: version/epoch = %q/%d, want %q/%d", tt.purl, c.Version, c.Epoch, tt.want, tt.wantedEpoch)
		}
		if eco, err := c.Release.Ecosystem(); err != nil || eco != "Rocky Linux:9" {
			t.Errorf("ecosystem = %q, %v", eco, err)
		}
	}
}

// The four language ecosystems, each keyed the way OSV keys it and not the way
// the purl spells it.
func TestLanguageComponentsAreNamedTheWayOSVKeysThem(t *testing.T) {
	res := read(t, `{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"type":"library","purl":"pkg:golang/github.com/Gorilla/mux@v1.8.0"},
	    {"type":"library","purl":"pkg:npm/%40babel/core@7.24.0"},
	    {"type":"library","purl":"pkg:pypi/ruamel.YAML.clib@0.2.8"},
	    {"type":"library","purl":"pkg:maven/org.apache.commons/commons-lang3@3.12.0"}
	  ]
	}`)
	want := map[string]string{
		"github.com/gorilla/mux":           "golang",
		"@babel/core":                      "npm",
		"ruamel-yaml-clib":                 "pypi",
		"org.apache.commons:commons-lang3": "maven",
	}
	for name, plugin := range want {
		c, ok := byName(res, name)
		if !ok {
			t.Errorf("%q is missing; got %+v", name, res.Components)
			continue
		}
		if c.PluginID != plugin {
			t.Errorf("%q went to plugin %q, want %q", name, c.PluginID, plugin)
		}
	}
	// The document's own spelling is kept as a second query, because not every
	// PyPI record was written normalized.
	py, _ := byName(res, "ruamel-yaml-clib")
	if len(py.AltNames) != 1 || py.AltNames[0] != "ruamel.YAML.clib" {
		t.Errorf("alt names = %v, want the document's spelling", py.AltNames)
	}
}

// Everything dropped is named. A bill of 400 components of which 120 were not
// scanned must not read as a scan of 400, and the only way a reader can check
// that is if the other 120 are identifiable.
func TestNothingIsDroppedSilently(t *testing.T) {
	res := read(t, `{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"bom-ref":"real","type":"library","purl":"pkg:npm/lodash@4.17.21"},
	    {"bom-ref":"container","type":"container","name":"debian:12"},
	    {"bom-ref":"nameless-lib","type":"library","name":"something"},
	    {"bom-ref":"exotic","type":"library","purl":"pkg:cargo/serde@1.0.0"},
	    {"bom-ref":"unversioned","type":"library","purl":"pkg:golang/github.com/foo/bar"},
	    {"bom-ref":"broken","type":"library","purl":"just-a-name"}
	  ]
	}`)
	if len(res.Components) != 1 || res.Components[0].Name != "lodash" {
		t.Fatalf("components = %+v, want only lodash", res.Components)
	}

	reasons := map[string]string{}
	for _, n := range res.Skipped {
		reasons[n.Ref] = n.Reason
	}
	for ref, want := range map[string]string{
		"container":    "no package URL",
		"nameless-lib": "no package URL",
		"exotic":       `no vexscan ecosystem for purl type "cargo"`,
		"unversioned":  "no version in the package URL",
	} {
		if got, ok := reasons[ref]; !ok || !strings.Contains(got, want) {
			t.Errorf("skipped[%q] = %q, want it to mention %q", ref, got, want)
		}
	}
	if len(res.Skipped) != 4 {
		t.Errorf("skipped = %+v, want four", res.Skipped)
	}

	// A purl that will not parse is a failure and not a skip: the document
	// claimed to identify a package and the claim is unusable, which is a
	// different thing from a package this tool has no plugin for.
	if len(res.Failed) != 1 || res.Failed[0].Ref != "broken" {
		t.Errorf("failed = %+v, want the malformed purl", res.Failed)
	}
}

// The schema lets components nest, and a component hidden inside another must
// not go unscanned for being one level down.
func TestNestedComponentsAreRead(t *testing.T) {
	res := read(t, `{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"type":"application","name":"app","components":[
	      {"type":"library","purl":"pkg:npm/lodash@4.17.21","components":[
	        {"type":"library","purl":"pkg:npm/minimist@1.2.5"}
	      ]}
	    ]}
	  ]
	}`)
	if len(res.Components) != 2 {
		t.Fatalf("components = %+v, want lodash and minimist", res.Components)
	}
}

// The three ways a document is not a bill of materials this can read. Each has
// to say which one it is: "no components" is what a wrong-format document and
// an empty one both look like from the inside, and only one of them is the
// user's mistake.
func TestADocumentThatIsNotACycloneDXBillSaysSo(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"not JSON at all", `<?xml version="1.0"?><bom/>`, "not JSON"},
		{"an SPDX document", `{"bomFormat":"SPDX","spdxVersion":"SPDX-2.3","packages":[]}`, "CycloneDX JSON"},
		{"JSON that is nothing in particular", `{"hello":"world"}`, "not a CycloneDX"},
		{"a bill with nothing scannable in it", `{"bomFormat":"CycloneDX","components":[
		  {"type":"operating-system","name":"debian","version":"12"}]}`, "no scannable components"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(tt.body), "a test", nil)
			if err == nil {
				t.Fatal("no error; an unreadable bill must never scan clean")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestOpenReadsAFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(p, []byte(debianBill), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Open(p, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(res.Components) != 2 {
		t.Errorf("components = %+v, want two", res.Components)
	}

	if _, err := Open(filepath.Join(t.TempDir(), "absent.json"), nil); err == nil {
		t.Error("a missing file scanned without complaint")
	}
}

// The order is the plugin then the name, so two runs over the same document
// query OSV in the same order and produce the same report.
func TestComponentsComeBackInAStableOrder(t *testing.T) {
	body := `{"bomFormat":"CycloneDX","components":[
	  {"type":"library","purl":"pkg:npm/zod@3.22.0"},
	  {"type":"library","purl":"pkg:golang/github.com/foo/bar@v1.0.0"},
	  {"type":"library","purl":"pkg:npm/axios@1.6.0"}]}`
	var want []string
	for i := 0; i < 3; i++ {
		var got []string
		for _, c := range read(t, body).Components {
			got = append(got, c.PluginID+" "+c.Name)
		}
		if want == nil {
			want = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("order changed between reads: %v then %v", want, got)
		}
	}
	if want[0] != "golang github.com/foo/bar" {
		t.Errorf("order = %v, want golang before npm", want)
	}
}
