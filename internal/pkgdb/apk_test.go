package pkgdb

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// testdata/alpine319 is /lib/apk/db/installed lifted verbatim out of the
// alpine:3.19 image -- all 15 packages, unmodified.
func alpineFS(t *testing.T) target.RootFS {
	t.Helper()
	return target.NewDirFS(filepath.Join("testdata", "alpine319"))
}

func TestAPKReadsARealAlpineDatabase(t *testing.T) {
	pkgs, err := (&APK{}).Read(alpineFS(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 15 {
		t.Fatalf("got %d packages, want 15", len(pkgs))
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
		if p.Format != FormatAPK || p.Version == "" || p.Arch != "x86_64" {
			t.Errorf("%+v", p)
		}
		if p.DB != "/lib/apk/db/installed" {
			t.Errorf("%s: DB = %q", p.Name, p.DB)
		}
	}

	// apk versions carry the "-r<N>" package revision. It is part of the
	// version string OSV compares against, so it must survive verbatim.
	if got := byName["libssl3"].Version; got != "3.1.8-r1" {
		t.Errorf("libssl3 version = %q, want 3.1.8-r1", got)
	}
	if got := byName["musl"].Version; got != "1.2.4_git20230717-r5" {
		t.Errorf("musl version = %q", got)
	}
}

// TestAPKOriginIsWhatOSVKeysOn: Alpine files advisories against the origin
// (aport) name. Querying Alpine:v3.19 for "libssl3" returns nothing at all,
// while "openssl" returns 55 advisories -- so losing the origin turns every
// OpenSSL CVE in an Alpine image into a silent clean result.
func TestAPKOriginIsWhatOSVKeysOn(t *testing.T) {
	pkgs, err := (&APK{}).Read(alpineFS(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"libssl3":                {"openssl", "libssl3"},
		"libcrypto3":             {"openssl", "libcrypto3"},
		"ssl_client":             {"busybox", "ssl_client"},
		"ca-certificates-bundle": {"ca-certificates", "ca-certificates-bundle"},
		"libc-utils":             {"libc-dev", "libc-utils"},
		// Origin equal to the name collapses to a single query.
		"musl": {"musl"},
		"zlib": {"zlib"},
	}
	seen := 0
	for _, p := range pkgs {
		names, ok := want[p.Name]
		if !ok {
			continue
		}
		seen++
		if got := p.OSVNames(); strings.Join(got, ",") != strings.Join(names, ",") {
			t.Errorf("%s: OSVNames() = %v, want %v", p.Name, got, names)
		}
	}
	if seen != len(want) {
		t.Errorf("matched %d of %d packages", seen, len(want))
	}
}

// TestAPKFileListsFollowTheDirectoryCursor: "F:" sets the current directory
// and every "R:" after it names a file inside that directory. Reading the
// paragraph into a map of key to value -- the obvious thing to do, and what
// works for dpkg -- loses the pairing and produces filenames with no path.
func TestAPKFileListsFollowTheDirectoryCursor(t *testing.T) {
	pkgs, err := (&APK{}).Read(alpineFS(t))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, tt := range []struct{ pkg, file string }{
		{"libssl3", "/lib/libssl.so.3"},
		{"libcrypto3", "/lib/libcrypto.so.3"},
		{"musl", "/lib/ld-musl-x86_64.so.1"},
		{"busybox", "/bin/busybox"},
		{"zlib", "/lib/libz.so.1.3.1"},
	} {
		if !hasFile(byName[tt.pkg], tt.file) {
			t.Errorf("%s does not own %s (has %d files)", tt.pkg, tt.file, len(byName[tt.pkg].Files))
		}
	}

	// Every recorded path is tree-absolute and normalized: apk stores "lib"
	// and "libssl.so.3" separately, with no leading slash on either.
	for _, p := range pkgs {
		for _, f := range p.Files {
			if !strings.HasPrefix(f, "/") || strings.Contains(f, "//") {
				t.Errorf("%s: unnormalized path %q", p.Name, f)
			}
		}
	}
}

func TestAPKParsesTheDirectoryCursorInIsolation(t *testing.T) {
	pkgs, err := parseAPK(strings.NewReader(strings.Join([]string{
		"P:one",
		"V:1.0-r0",
		"A:x86_64",
		"o:origin",
		"F:usr/lib",
		"R:liba.so.1",
		"R:libb.so.1",
		"F:usr/share/doc/one",
		"R:README",
		// A bare F: with no R: contributes no files.
		"F:usr/share/empty",
		"",
		// A second package must start from a clean cursor rather than
		// inheriting "usr/share/empty" from the one before it.
		"P:two",
		"V:2.0-r0",
		"R:orphan",
		"F:etc",
		"R:two.conf",
		"",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}

	if got := strings.Join(pkgs[0].Files, " "); got != "/usr/lib/liba.so.1 /usr/lib/libb.so.1 /usr/share/doc/one/README" {
		t.Errorf("one: files = %q", got)
	}
	// An "R:" before any "F:" is rooted at "/", which is what apk means by it.
	if got := strings.Join(pkgs[1].Files, " "); got != "/etc/two.conf /orphan" {
		t.Errorf("two: files = %q", got)
	}
}

func TestAPKRejectsAnEmptyDatabase(t *testing.T) {
	fsys := writeTree(t, map[string]string{"/lib/apk/db/installed": "\n"})
	if _, err := (&APK{}).Read(fsys); err == nil {
		t.Fatal("an empty apk database parsed as a valid empty inventory")
	}
}

func TestAPKRejectsAParagraphWithNoName(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/lib/apk/db/installed": "P:ok\nV:1\n\nV:2\nA:x86_64\n",
	})
	_, err := (&APK{}).Read(fsys)
	if err == nil {
		t.Fatal("a nameless apk paragraph parsed cleanly")
	}
	if !strings.Contains(err.Error(), "no P: field") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestAPKDetectFindsBothLocations(t *testing.T) {
	for _, db := range apkDBs {
		fsys := writeTree(t, map[string]string{db: "P:x\nV:1\n"})
		got, ok := (&APK{}).Detect(fsys)
		if !ok || got != db {
			t.Errorf("Detect() = %q, %v; want %q, true", got, ok, db)
		}
	}
	if db, ok := (&APK{}).Detect(writeTree(t, map[string]string{"/etc/os-release": "ID=debian\n"})); ok {
		t.Errorf("Detect() found %q in a tree with no apk database", db)
	}
}

// TestReadRunsEveryDetectedBackend covers the top-level entry point, including
// the case that makes the failure semantics matter: one database parses, the
// other is present and broken. The broken one must fail the whole call rather
// than let the good half render as a complete inventory.
func TestReadRunsEveryDetectedBackend(t *testing.T) {
	good := map[string]string{
		"/var/lib/dpkg/status":  "Package: kept\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n",
		"/lib/apk/db/installed": "P:musl\nV:1.2.4-r5\nA:x86_64\n",
	}
	results, err := Read(writeTree(t, good))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Format != FormatDeb || results[1].Format != FormatAPK {
		t.Fatalf("got %+v", results)
	}

	broken := map[string]string{
		"/var/lib/dpkg/status":  good["/var/lib/dpkg/status"],
		"/lib/apk/db/installed": "\n",
	}
	if got, err := Read(writeTree(t, broken)); err == nil {
		t.Fatalf("a broken apk database was reported as an inventory: %+v", got)
	}

	if results, err := Read(writeTree(t, map[string]string{"/etc/hostname": "x\n"})); err != nil || len(results) != 0 {
		t.Errorf("a tree with no package database: %+v, %v", results, err)
	}
}
