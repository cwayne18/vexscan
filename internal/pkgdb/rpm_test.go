//go:build !norpm

package pkgdb

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// testdata/ubi9 holds a real /var/lib/rpm/rpmdb.sqlite from
// registry.access.redhat.com/ubi9/ubi, cut down from 188 packages to five by
// copying the Packages rows out into a fresh database. The rows themselves are
// untouched rpm headers -- decoding those is the whole job, and they are not
// something this code's author could have written plausibly.
func ubi9FS(t *testing.T) target.RootFS {
	t.Helper()
	return target.NewDirFS(filepath.Join("testdata", "ubi9"))
}

func TestRPMReadsARealSQLiteDatabase(t *testing.T) {
	pkgs, err := (&RPM{}).Read(ubi9FS(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 5 {
		t.Fatalf("got %d packages, want 5", len(pkgs))
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
		if p.Format != FormatRPM {
			t.Errorf("%s: format = %q", p.Name, p.Format)
		}
		if p.DB != "/var/lib/rpm/rpmdb.sqlite" {
			t.Errorf("%s: DB = %q", p.Name, p.DB)
		}
	}

	tests := []struct {
		name, version, arch, source string
		epoch                       int
	}{
		// The non-zero-epoch case. OSV writes Red Hat fixed versions as
		// "1:3.0.7-27.el9", so dropping the epoch would compare the wrong
		// thing against every openssl advisory.
		{name: "openssl-libs", version: "1:3.5.5-6.el9_8", epoch: 1, arch: "x86_64", source: "openssl"},
		{name: "glibc-common", version: "0:2.34-274.el9_8", arch: "x86_64", source: "glibc"},
		{name: "libgcc", version: "0:11.5.0-14.el9", arch: "x86_64", source: "gcc"},
		// SOURCERPM naming the same package as the binary.
		{name: "redhat-release", version: "0:9.8-1.0.el9", arch: "x86_64", source: "redhat-release"},
		{name: "setup", version: "0:2.13.7-10.el9", arch: "noarch", source: "setup"},
	}
	for _, tt := range tests {
		p, ok := byName[tt.name]
		if !ok {
			t.Errorf("%s not found", tt.name)
			continue
		}
		if p.Version != tt.version || p.Epoch != tt.epoch || p.Arch != tt.arch || p.Source != tt.source {
			t.Errorf("%s: got %s epoch=%d %s source=%s; want %s epoch=%d %s source=%s",
				tt.name, p.Version, p.Epoch, p.Arch, p.Source,
				tt.version, tt.epoch, tt.arch, tt.source)
		}
	}
}

// TestRPMVersionsCarryTheEpochEvenWhenZero pins the encoding against what OSV
// actually publishes. Verified live:
//
//	RHSA-2024:2447  openssl  fixed 1:3.0.7-27.el9
//	RHSA-2023:6746  nghttp2  fixed 0:1.43.0-5.el9_3.1
//	Rocky Linux:9   openssl  fixed 1:3.0.1-43.el9_0
//	AlmaLinux:9     openssl  fixed 1:3.0.1-41.el9_0
//
// The explicit "0:" is not what "rpm -q" prints, so the obvious
// version-release composition is the wrong one.
func TestRPMVersionsCarryTheEpochEvenWhenZero(t *testing.T) {
	tests := []struct {
		epoch                  int
		version, release, want string
	}{
		{0, "1.43.0", "5.el9_3.1", "0:1.43.0-5.el9_3.1"},
		{1, "3.0.7", "27.el9", "1:3.0.7-27.el9"},
		{2, "1.2.3", "1", "2:1.2.3-1"},
		// No release recorded: emit the epoch and version alone rather than a
		// trailing hyphen, which no comparator would parse.
		{0, "1.0", "", "0:1.0"},
	}
	for _, tt := range tests {
		if got := rpmEVR(tt.epoch, tt.version, tt.release); got != tt.want {
			t.Errorf("rpmEVR(%d, %q, %q) = %q, want %q", tt.epoch, tt.version, tt.release, got, tt.want)
		}
	}
}

// TestRPMEpochIsRecoverable: Azure Linux is the one rpm ecosystem whose OSV
// records carry no epoch ("openssl fixed 3.3.0-1"). The OS plugin needs to
// strip the prefix for it, so Epoch has to survive as a separate field.
func TestRPMEpochIsRecoverable(t *testing.T) {
	pkgs, err := (&RPM{}).Read(ubi9FS(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		prefix := strings.SplitN(p.Version, ":", 2)
		if len(prefix) != 2 {
			t.Fatalf("%s: version %q has no epoch prefix to strip", p.Name, p.Version)
		}
		if got := prefix[0]; got != itoa(p.Epoch) {
			t.Errorf("%s: version prefix %q disagrees with Epoch %d", p.Name, got, p.Epoch)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestRPMReadsFileLists(t *testing.T) {
	pkgs, err := (&RPM{}).Read(ubi9FS(t))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// rpm stores file paths split across DIRNAMES and BASENAMES with an index
	// table joining them; a reader that ignores DIRINDEXES produces plausible
	// but wrong paths, so check a specific one rather than just a count.
	if !hasFile(byName["libgcc"], "/lib64/libgcc_s.so.1") {
		t.Errorf("libgcc does not own /lib64/libgcc_s.so.1 (has %d files)", len(byName["libgcc"].Files))
	}
	if !hasFile(byName["glibc-common"], "/usr/bin/gencat") {
		t.Error("glibc-common does not own /usr/bin/gencat")
	}
	for _, p := range pkgs {
		if len(p.Files) == 0 {
			t.Errorf("%s owns no files", p.Name)
		}
		for _, f := range p.Files {
			if !strings.HasPrefix(f, "/") {
				t.Errorf("%s: relative path %q", p.Name, f)
			}
		}
	}
}

// TestRPMSQLiteDriverIsRegistered is the regression test for a failure that
// does not show up at compile time. go-rpmdb calls sql.Open("sqlite", path)
// and registers no driver itself -- its own tests blank-import
// glebarez/go-sqlite to supply one. Without that import this package builds
// fine and then fails on every RHEL 9+ and Fedora 33+ image. sql.Open is lazy,
// so the error surfaces at the first query, not at open.
func TestRPMSQLiteDriverIsRegistered(t *testing.T) {
	pkgs, err := (&RPM{}).Read(ubi9FS(t))
	if err != nil {
		if strings.Contains(err.Error(), "unknown driver") {
			t.Fatalf(`the sqlite driver blank import is missing from rpm.go: %v`, err)
		}
		t.Fatal(err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no packages")
	}
}

func TestSourceRPMName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"openssl-3.2.2-16.el10.src.rpm", "openssl"},
		{"glibc-2.34-274.el9_8.src.rpm", "glibc"},
		{"gcc-11.5.0-14.el9.src.rpm", "gcc"},
		// Hyphens in the name itself: stripping from the left would give
		// "java", which is not a package in any rpm ecosystem.
		{"java-21-openjdk-21.0.5.0.11-3.el9.src.rpm", "java-21-openjdk"},
		{"redhat-release-9.8-1.0.el9.src.rpm", "redhat-release"},
		{"kernel-4.18.0-553.8.1.el8_10.nosrc.rpm", "kernel"},
		// gpg-pubkey pseudo-packages and anything else without the expected
		// shape yield nothing rather than a name OSV would silently not match.
		{"", ""},
		{"weird.rpm", ""},
		{"nodashes.src.rpm", ""},
	}
	for _, tt := range tests {
		if got := sourceRPMName(tt.in); got != tt.want {
			t.Errorf("sourceRPMName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestRPMBinaryNameIsFirst: unlike deb and apk, the Red Hat and AlmaLinux
// databases key on the binary package name -- "openssl-libs" returns 113
// advisories against Red Hat while "openssl" returns 168 different ones, and
// both are wanted. Rocky, confusingly, keys on the source name. Order is a
// preference only; both names are always queried.
func TestRPMBinaryNameIsFirst(t *testing.T) {
	p := Package{Format: FormatRPM, Name: "openssl-libs", Source: "openssl"}
	if got := p.OSVNames(); strings.Join(got, ",") != "openssl-libs,openssl" {
		t.Errorf("OSVNames() = %v", got)
	}
	deb := Package{Format: FormatDeb, Name: "libssl3", Source: "openssl"}
	if got := deb.OSVNames(); strings.Join(got, ",") != "openssl,libssl3" {
		t.Errorf("OSVNames() = %v", got)
	}
}

func TestRPMDetect(t *testing.T) {
	db, ok := (&RPM{}).Detect(ubi9FS(t))
	if !ok || db != "/var/lib/rpm/rpmdb.sqlite" {
		t.Errorf("Detect() = %q, %v", db, ok)
	}
	if db, ok := (&RPM{}).Detect(writeTree(t, map[string]string{"/etc/os-release": "ID=debian\n"})); ok {
		t.Errorf("Detect() found %q in a tree with no rpm database", db)
	}
}

// TestRPMRejectsAGarbageDatabase: a file at the right path that is not any of
// the three on-disk formats must be an error. go-rpmdb tries sqlite, then ndb,
// then Berkeley DB, and the last one's failure is what surfaces.
func TestRPMRejectsAGarbageDatabase(t *testing.T) {
	fsys := writeTree(t, map[string]string{"/var/lib/rpm/rpmdb.sqlite": "not a database"})
	if pkgs, err := (&RPM{}).Read(fsys); err == nil {
		t.Fatalf("a garbage rpm database parsed as an inventory: %+v", pkgs)
	}
}

// TestRPMParticipatesInRead checks the backend is wired into the top-level
// entry point, not just reachable directly.
func TestRPMParticipatesInRead(t *testing.T) {
	results, err := Read(ubi9FS(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Format != FormatRPM || len(results[0].Packages) != 5 {
		t.Fatalf("got %+v", results)
	}
}
