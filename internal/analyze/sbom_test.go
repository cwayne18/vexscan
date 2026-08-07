package analyze

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem/ospkg"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/pkgdb"
)

// mixedBill has one component for every plugin, plus the two kinds of entry
// that are not components: a structural row with no purl, and a purl that will
// not parse. The point of the fixture is that all seven are accounted for.
const mixedBill = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "components": [
    {"bom-ref": "os", "type": "operating-system", "name": "debian", "version": "12.15"},
    {"type": "library", "name": "libssl3", "version": "3.0.16-1~deb12u1",
     "purl": "pkg:deb/debian/libssl3@3.0.16-1~deb12u1?arch=amd64&distro=debian-12.15",
     "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "openssl"}]},
    {"type": "library", "name": "golang.org/x/net", "version": "v0.17.0",
     "purl": "pkg:golang/golang.org/x/net@v0.17.0"},
    {"type": "library", "name": "lodash", "version": "4.17.20",
     "purl": "pkg:npm/lodash@4.17.20"},
    {"type": "library", "name": "Django", "version": "4.2.1",
     "purl": "pkg:pypi/django@4.2.1"},
    {"type": "library", "name": "log4j-core", "version": "2.14.1",
     "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
    {"bom-ref": "broken", "type": "library", "name": "mystery", "version": "1.0",
     "purl": "not-a-purl"}
  ]
}`

func writeBill(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Every component reaches the plugin that can evaluate it, and none of them
// reaches two. The split is what keeps --ecosystem and the per-ecosystem
// outcome list behaving as they do for an image.
func TestReadSBOMSplitsComponentsByPlugin(t *testing.T) {
	opts := Options{SBOM: writeBill(t, mixedBill), Logf: func(string, ...any) {}}

	bom, err := readSBOM(&opts)
	if err != nil {
		t.Fatalf("readSBOM: %v", err)
	}

	if len(opts.sbomOS) != 1 {
		t.Fatalf("os inventory = %+v, want one package", opts.sbomOS)
	}
	got := opts.sbomOS[0]
	if got.Package.Format != pkgdb.FormatDeb || got.Package.Name != "libssl3" {
		t.Errorf("os package = %+v, want the deb libssl3", got.Package)
	}
	// Debian files every advisory against the source package; without this the
	// query is for a name OSV has no records under, and reads as clean.
	if got.Package.Source != "openssl" {
		t.Errorf("source = %q, want openssl", got.Package.Source)
	}
	if got.Origin != ospkg.MethodSBOM {
		t.Errorf("origin = %q, want %q", got.Origin, ospkg.MethodSBOM)
	}
	// The identity is stated by the document rather than squeezed out of
	// headers there are none of. See ospkg.SuppliedIdentity.
	if got.Release.ID != "debian" {
		t.Errorf("release = %+v, want debian", got.Release)
	}
	// The zero Meta is the whole guarantee that nothing downstream clears a
	// package on a file list the document never carried.
	if got.Meta.FilesKnown {
		t.Error("an SBOM component claims to know its file list")
	}
	if got.Package.DB != opts.SBOM {
		t.Errorf("db = %q, want the document %q", got.Package.DB, opts.SBOM)
	}

	if len(opts.sbomGo) != 1 || opts.sbomGo[0].Path != "golang.org/x/net" || opts.sbomGo[0].Version != "v0.17.0" {
		t.Errorf("go inventory = %+v", opts.sbomGo)
	}
	for _, tc := range []struct {
		what string
		got  []langdb.Package
		name string
		form langdb.Format
	}{
		{"npm", opts.sbomNPM, "lodash", langdb.FormatNPM},
		{"pypi", opts.sbomPyPI, "django", langdb.FormatPyPI},
		{"maven", opts.sbomMaven, "org.apache.logging.log4j:log4j-core", langdb.FormatMaven},
	} {
		if len(tc.got) != 1 {
			t.Errorf("%s inventory = %+v, want one package", tc.what, tc.got)
			continue
		}
		p := tc.got[0]
		if p.Name != tc.name || p.Format != tc.form {
			t.Errorf("%s package = %s/%s, want %s/%s", tc.what, p.Format, p.Name, tc.form, tc.name)
		}
		if p.FilesKnown || p.ImportNamesKnown {
			t.Errorf("%s package claims to know what it installs: %+v", tc.what, p)
		}
		if p.Dir != opts.SBOM {
			t.Errorf("%s location = %q, want the document %q", tc.what, p.Dir, opts.SBOM)
		}
	}

	// The two entries that are not components are named, not dropped: one is a
	// structural row and one is a loss, and only the second is a gap.
	if len(bom.Skipped) != 1 || len(bom.Failed) != 1 {
		t.Errorf("skipped = %+v, failed = %+v; want one of each", bom.Skipped, bom.Failed)
	}
}

// A component that would not parse is a gap in the account of the document, so
// it lands where every other gap lands and drives the same footer and exit
// code.
func TestSBOMFailuresBecomeUnreadable(t *testing.T) {
	opts := Options{SBOM: writeBill(t, mixedBill), Logf: func(string, ...any) {}}
	bom, err := readSBOM(&opts)
	if err != nil {
		t.Fatalf("readSBOM: %v", err)
	}

	u := noteSBOMFailures(nil, bom, func(string, ...any) {})
	if u == nil || u.Count != 1 {
		t.Fatalf("unreadable = %+v, want one entry", u)
	}
	if len(u.Paths) != 1 || !strings.Contains(u.Paths[0], "broken") {
		t.Errorf("unreadable does not name what was lost: %+v", u.Paths)
	}

	// A skipped entry is not a loss, and folding it in here would make every
	// scan of a document with an operating-system row report as incomplete.
	if u.Count != len(bom.Failed) {
		t.Errorf("count = %d, want just the %d failures", u.Count, len(bom.Failed))
	}
}

// The mode names the target, and the report branches on it: the metadata
// caveat, the footer and the JSON all read it.
func TestSBOMHasItsOwnMode(t *testing.T) {
	if got := (Options{SBOM: "bom.json"}).mode(); got != "sbom" {
		t.Errorf("mode = %q, want sbom", got)
	}
}

// The tree --sbom scans against is real, empty, and cleaned up. Every plugin
// walks it and every walk gets the truthful answer, which is that nothing was
// installed anywhere.
func TestOpenSBOMTreeIsAnEmptyTree(t *testing.T) {
	opts := Options{SBOM: "bom.json"}
	img, cleanup, err := openSBOMTree(&opts)
	if err != nil {
		t.Fatalf("openSBOMTree: %v", err)
	}
	if img.Ref != "bom.json" {
		t.Errorf("ref = %q, want the document", img.Ref)
	}
	root := img.FS.Root()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("the tree is not a real directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the tree is not empty: %+v", entries)
	}
	cleanup()
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("cleanup left %s behind: %v", root, err)
	}
}

// The inventory is the output worth having before a scan of a document: the
// whole risk here is a component read under a name OSV has no records for, and
// this is where that is checkable.
func TestSBOMInventoryShowsTheQueriedNames(t *testing.T) {
	opts := Options{SBOM: writeBill(t, mixedBill), Logf: func(string, ...any) {}}

	invs, err := Inventory(context.Background(), opts)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	inv := invs[0]
	if inv.Mode != "sbom" || inv.Target != opts.SBOM {
		t.Errorf("inventory = %s/%s, want sbom/%s", inv.Mode, inv.Target, opts.SBOM)
	}
	if inv.OS == nil || inv.OS.Ecosystem != "Debian:12" {
		t.Fatalf("os = %+v, want Debian:12", inv.OS)
	}
	if inv.Packages() != 1 {
		t.Errorf("os packages = %d, want 1", inv.Packages())
	}
	// Debian files advisories against the source package. Seeing both names
	// here is the check this output exists for.
	names := inv.Databases[0].Packages[0].OSVNames()
	if len(names) != 2 || names[0] != "openssl" {
		t.Errorf("queried names = %v, want the source name first", names)
	}
	if inv.LanguagePackages() != 3 {
		t.Errorf("language packages = %d, want one each of pypi, npm and maven: %+v",
			inv.LanguagePackages(), inv.Languages)
	}
	// Go has no column in this output, and a module that simply vanished from
	// it would read as a document that had none.
	if len(inv.Notes) != 1 || !strings.Contains(inv.Notes[0], "Go module") {
		t.Errorf("notes = %+v, want the Go modules accounted for", inv.Notes)
	}
	// The unparseable purl is a gap in the account of the document, and drives
	// the same INCOMPLETE banner and exit code every other gap does.
	if inv.Unreadable == nil || inv.Unreadable.Count != 1 {
		t.Errorf("unreadable = %+v, want the broken component", inv.Unreadable)
	}
}

// A document naming no OS package has nothing to say about a distribution, and
// that is not the same as an os-release nobody could read.
func TestSBOMInventoryWithNoOSPackages(t *testing.T) {
	const langOnly = `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [
	    {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}
	  ]
	}`
	opts := Options{SBOM: writeBill(t, langOnly), Logf: func(string, ...any) {}}

	invs, err := Inventory(context.Background(), opts)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	inv := invs[0]
	if inv.OS != nil {
		t.Errorf("os = %+v, want nothing said about a distribution that was never named", inv.OS)
	}
	if inv.LanguagePackages() != 1 {
		t.Errorf("language packages = %d, want 1", inv.LanguagePackages())
	}
}
