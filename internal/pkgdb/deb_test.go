package pkgdb

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// testdata/debian12 is a real /var/lib/dpkg lifted verbatim out of the
// debian:12 image, with the info/ directory trimmed to eight .list files that
// between them cover every filename shape dpkg produces. The status file is
// untouched: parsing a database someone else wrote is the entire job, so the
// fixture is not one this code's author got to design.
//
// The fixture is materialised into a temp directory rather than read in place
// because of the one filename shape that matters most here. dpkg writes the
// multiarch lists as "libc6:amd64.list", and a module zip cannot contain a
// colon: the punctuation a module file path may use is "!#$%&()+,-.=@[]^_{}~"
// and nothing else, so one such file makes "go install" of this module fail
// for everyone, on every platform, before a line of it is compiled. The files
// are stored %3A-escaped and the colon is put back here, which keeps the name
// the parser sees byte-for-byte what dpkg wrote while keeping the repository
// installable. TestTrackedFilesCanGoInAModuleZip pins the rule.
func debianFS(t *testing.T) target.RootFS {
	t.Helper()
	return target.NewDirFS(unescapeTree(t, filepath.Join("testdata", "debian12")))
}

// unescapeTree copies a fixture tree into a temp directory, turning %3A in any
// path element back into a colon.
func unescapeTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, strings.ReplaceAll(rel, "%3A", ":"))
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestDebReadsARealDebianStatus(t *testing.T) {
	pkgs, err := (&Deb{}).Read(debianFS(t))
	if err != nil {
		t.Fatal(err)
	}
	// debian:12 ships 88 installed packages.
	if len(pkgs) != 88 {
		t.Errorf("got %d packages, want 88", len(pkgs))
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
		if p.Format != FormatDeb {
			t.Errorf("%s: format = %q", p.Name, p.Format)
		}
		if p.Version == "" {
			t.Errorf("%s: no version", p.Name)
		}
		if p.DB != dpkgStatus {
			t.Errorf("%s: DB = %q, want %q", p.Name, p.DB, dpkgStatus)
		}
	}

	tests := []struct {
		name, version, arch, source, sourceVersion string
	}{
		// The multiarch case, and the one that matters most: OSV files glibc
		// advisories against "glibc", and nothing at all against "libc6".
		{name: "libc6", version: "2.36-9+deb12u14", arch: "amd64", source: "glibc"},
		// "Source: bash (5.2.15-2)" -- the parenthesised form, used when the
		// source version differs from the binary version.
		{name: "bash", version: "5.2.15-2+b13", arch: "amd64", source: "bash", sourceVersion: "5.2.15-2"},
		// No Source field at all: the binary name is the source name.
		{name: "base-files", version: "12.4+deb12u15", arch: "amd64"},
		{name: "gcc-12-base", version: "12.2.0-14+deb12u1", arch: "amd64", source: "gcc-12"},
	}
	for _, tt := range tests {
		p, ok := byName[tt.name]
		if !ok {
			t.Errorf("%s not found", tt.name)
			continue
		}
		if p.Version != tt.version || p.Arch != tt.arch {
			t.Errorf("%s: got %s/%s, want %s/%s", tt.name, p.Version, p.Arch, tt.version, tt.arch)
		}
		if p.Source != tt.source || p.SourceVersion != tt.sourceVersion {
			t.Errorf("%s: source = %q/%q, want %q/%q", tt.name, p.Source, p.SourceVersion, tt.source, tt.sourceVersion)
		}
	}
}

// TestDebSourceNamesAreWhatOSVKeysOn guards the mapping the plan calls out as
// the one that produces both false negatives and false positives if wrong.
// Debian files advisories against source packages; the database lists binary
// packages; these four differ.
func TestDebSourceNamesAreWhatOSVKeysOn(t *testing.T) {
	pkgs, err := (&Deb{}).Read(debianFS(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"libc6":       {"glibc", "libc6"},
		"libgcc-s1":   {"gcc-12", "libgcc-s1"},
		"libcrypt1":   {"libxcrypt", "libcrypt1"},
		"libgnutls30": {"gnutls28", "libgnutls30"},
	}
	seen := 0
	for _, p := range pkgs {
		names, ok := want[p.Name]
		if !ok {
			continue
		}
		seen++
		got := p.OSVNames()
		if len(got) != len(names) || got[0] != names[0] || got[1] != names[1] {
			t.Errorf("%s: OSVNames() = %v, want %v", p.Name, got, names)
		}
	}
	if seen != len(want) {
		t.Errorf("matched %d of %d packages", seen, len(want))
	}
}

func TestDebReadsFileLists(t *testing.T) {
	pkgs, err := (&Deb{}).Read(debianFS(t))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// libc6 is Multi-Arch: same, so its list is info/libc6:amd64.list.
	//
	// The recorded path is /lib/..., not /usr/lib/..., even though debian:12
	// is usrmerged and the file's realpath is under /usr: dpkg stores the path
	// it installed to, and /lib is a symlink to usr/lib. Anything matching
	// file lists against a walked tree has to resolve through that symlink
	// rather than compare strings.
	libc := byName["libc6"]
	if !hasFile(libc, "/lib/x86_64-linux-gnu/libc.so.6") {
		t.Errorf("libc6 does not own libc.so.6; arch-qualified .list lookup failed (%d files)", len(libc.Files))
	}
	// bash is Multi-Arch: foreign, so its list is info/bash.list, unqualified.
	if !hasFile(byName["bash"], "/bin/bash") {
		t.Error("bash does not own /bin/bash; unqualified .list lookup failed")
	}
	// Architecture: all.
	if !hasFile(byName["adduser"], "/usr/sbin/adduser") {
		t.Error("adduser does not own /usr/sbin/adduser")
	}
	// A package with no .list in the trimmed fixture gets no files, and that
	// is not an error -- slimmed images delete info/ wholesale.
	if perl := byName["perl-base"]; len(perl.Files) != 0 {
		t.Errorf("perl-base has %d files but no fixture .list", len(perl.Files))
	}
	// dpkg lists "/." for the root; it must not survive into Files.
	for _, f := range libc.Files {
		if f == "/." || f == "/" {
			t.Errorf("file list contains the root entry %q", f)
		}
	}
}

func hasFile(p Package, want string) bool {
	for _, f := range p.Files {
		if f == want {
			return true
		}
	}
	return false
}

// TestDebSkipsRemovedPackages covers the Status states whose files are gone.
// A "config-files" package still has a paragraph and a version, and counting
// it would attribute vulnerable code to an image that does not contain it.
func TestDebSkipsRemovedPackages(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/var/lib/dpkg/status": strings.Join([]string{
			"Package: kept\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n",
			"Package: purged\nStatus: deinstall ok config-files\nVersion: 2\nArchitecture: amd64\n",
			"Package: never\nStatus: purge ok not-installed\nArchitecture: amd64\n",
			// Unpacked but unconfigured: the payload is on disk, so it counts.
			"Package: unpacked\nStatus: install ok unpacked\nVersion: 3\nArchitecture: amd64\n",
			"Package: triggered\nStatus: install ok triggers-pending\nVersion: 4\nArchitecture: amd64\n",
		}, "\n"),
	})

	pkgs, err := (&Deb{}).Read(fsys)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pkgs {
		got = append(got, p.Name)
	}
	want := "kept,triggered,unpacked"
	if strings.Join(got, ",") != want {
		t.Errorf("installed = %v, want %s", got, want)
	}
}

// TestDebReadsDistrolessStatusDir covers the other shape of dpkg database.
// Google's distroless images are assembled by Bazel, not dpkg, and ship
// /var/lib/dpkg/status.d/ with one paragraph per file and no info/ directory.
func TestDebReadsDistrolessStatusDir(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/var/lib/dpkg/status.d/libc6":         "Package: libc6\nSource: glibc\nVersion: 2.36-9+deb12u7\nArchitecture: amd64\nStatus: install ok installed\n",
		"/var/lib/dpkg/status.d/libssl3":       "Package: libssl3\nSource: openssl\nVersion: 3.0.11-1~deb12u2\nArchitecture: amd64\n",
		"/var/lib/dpkg/status.d/libc6.md5sums": "d41d8cd98f00b204e9800998ecf8427e  usr/lib/x86_64-linux-gnu/libc.so.6\n",
	})

	d := &Deb{}
	db, ok := d.Detect(fsys)
	if !ok || db != dpkgStatusD {
		t.Fatalf("Detect() = %q, %v; want %q, true", db, ok, dpkgStatusD)
	}
	pkgs, err := d.Read(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (the .md5sums sibling must not parse as one)", len(pkgs))
	}
	// The paragraph with no Status field counts: some image builders omit it,
	// and dropping the package would be a silent false negative.
	if pkgs[1].Name != "libssl3" || pkgs[1].Source != "openssl" {
		t.Errorf("got %+v", pkgs[1])
	}
}

// TestDebRejectsAnEmptyDatabase is the failure semantics the plan calls
// non-negotiable. A status file that parses to nothing is a bug, and reporting
// it as an inventory renders as "no packages installed, nothing vulnerable".
func TestDebRejectsAnEmptyDatabase(t *testing.T) {
	fsys := writeTree(t, map[string]string{"/var/lib/dpkg/status": "\n\n"})
	if _, err := (&Deb{}).Read(fsys); err == nil {
		t.Fatal("an empty dpkg status parsed as a valid empty inventory")
	}
}

func TestDebRejectsAParagraphWithNoPackageField(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/var/lib/dpkg/status": "Package: ok\nStatus: install ok installed\nVersion: 1\n\nVersion: 2\nArchitecture: amd64\n",
	})
	_, err := (&Deb{}).Read(fsys)
	if err == nil {
		t.Fatal("a malformed paragraph parsed cleanly")
	}
	if !strings.Contains(err.Error(), "no Package field") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestDebDoesNotMistakeContinuationLinesForFields: a Description body is
// indented, and dpkg descriptions routinely contain colon-separated text that
// looks exactly like a field.
func TestDebDoesNotMistakeContinuationLinesForFields(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/var/lib/dpkg/status": "Package: real\n" +
			"Status: install ok installed\n" +
			"Version: 1\n" +
			"Description: a package\n" +
			" Package: not-a-package\n" +
			" Version: 99\n" +
			" .\n" +
			" Source: not-a-source\n",
	})
	pkgs, err := (&Deb{}).Read(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Name != "real" || pkgs[0].Version != "1" || pkgs[0].Source != "" {
		t.Errorf("indented description leaked into fields: %+v", pkgs[0])
	}
}

func TestDebDetectReportsAbsence(t *testing.T) {
	fsys := writeTree(t, map[string]string{"/etc/os-release": "ID=alpine\n"})
	if db, ok := (&Deb{}).Detect(fsys); ok {
		t.Errorf("Detect() found %q in a tree with no dpkg database", db)
	}
}

func TestSplitSource(t *testing.T) {
	tests := []struct{ in, name, version string }{
		{"acl", "acl", ""},
		{"bash (5.2.15-2)", "bash", "5.2.15-2"},
		{"  util-linux  (2.38.1-5+deb12u3)  ", "util-linux", "2.38.1-5+deb12u3"},
		{"broken (", "broken", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		name, version := splitSource(tt.in)
		if name != tt.name || version != tt.version {
			t.Errorf("splitSource(%q) = %q, %q; want %q, %q", tt.in, name, version, tt.name, tt.version)
		}
	}
}

// writeTree builds a throwaway rootfs from tree-absolute path to content.
func writeTree(t *testing.T, files map[string]string) target.RootFS {
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
	return target.NewDirFS(root)
}
