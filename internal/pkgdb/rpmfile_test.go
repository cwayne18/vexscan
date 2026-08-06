package pkgdb

import (
	"bytes"
	"encoding/binary"
	"errors"

	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The fixtures are the exact byte prefixes ReadFile consumed from three real
// packages, captured with io.TeeReader. Their sizes are the measurement that
// justifies streaming rather than downloading:
//
//	rocky9-openssl-libs        17,913 of 2,411,423 bytes    0.7%
//	rocky9-rocky-release       11,973 of    22,980 bytes   52.1%
//	sle15-libopenssl3          84,864 of 1,827,924 bytes    4.6%
//
// A fixture that is a prefix and not a whole file is also the point: it proves
// the parser stops where it says it does. If it ever reads one byte past the
// main header, every one of these tests fails with an unexpected EOF.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "rpmfile", name+".hdr"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readFixture(t *testing.T, name string) (Package, Meta) {
	t.Helper()
	pkg, meta, err := ReadFile(bytes.NewReader(fixture(t, name)))
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return pkg, meta
}

func TestReadFileParsesARealPackage(t *testing.T) {
	pkg, meta := readFixture(t, "rocky9-openssl-libs")

	if pkg.Format != FormatRPM {
		t.Errorf("Format = %q, want rpm", pkg.Format)
	}
	if pkg.Name != "openssl-libs" {
		t.Errorf("Name = %q", pkg.Name)
	}
	// The epoch is 1 here and is part of the string, because that is how the
	// Rocky OSV records are written. See rpmEVR.
	if pkg.Version != "1:3.5.5-2.el9_8" {
		t.Errorf("Version = %q, want the EVR with its epoch", pkg.Version)
	}
	if pkg.Epoch != 1 {
		t.Errorf("Epoch = %d, want 1", pkg.Epoch)
	}
	if pkg.Arch != "x86_64" {
		t.Errorf("Arch = %q", pkg.Arch)
	}
	// SOURCERPM is "openssl-3.5.5-2.el9_8.src.rpm". Recovering "openssl" from
	// it is what makes the package findable: Rocky files its advisories under
	// the source name and openssl-libs returns nothing.
	if pkg.Source != "openssl" {
		t.Errorf("Source = %q, want openssl", pkg.Source)
	}
	if want := []string{"openssl-libs", "openssl"}; !slices.Equal(pkg.OSVNames(), want) {
		t.Errorf("OSVNames() = %v, want %v", pkg.OSVNames(), want)
	}

	if len(pkg.Files) != 35 {
		t.Errorf("got %d files, want 35", len(pkg.Files))
	}
	if !slices.IsSorted(pkg.Files) {
		t.Error("Files are not sorted")
	}
	for _, f := range pkg.Files {
		if !strings.HasPrefix(f, "/") {
			t.Errorf("file %q is not tree-absolute", f)
		}
	}

	if meta.Vendor != "Rocky Enterprise Software Foundation" {
		t.Errorf("Vendor = %q", meta.Vendor)
	}
	if meta.Distribution != "Rocky Linux 9" {
		t.Errorf("Distribution = %q", meta.Distribution)
	}
	if meta.SourcePackage {
		t.Error("SourcePackage = true for a binary package")
	}
}

// TestReadFileFindsELFWithoutThePayload is the fact the whole metadata-only
// mode rests on. rpm stores file(1)'s verdict per file in the header, so a
// package's code can be found without decompressing its cpio payload -- no xz,
// no zstd, no cpio, and on a URL no download past the first 0.7%.
func TestReadFileFindsELFWithoutThePayload(t *testing.T) {
	_, meta := readFixture(t, "rocky9-openssl-libs")
	if !meta.HasELF() {
		t.Fatal("HasELF() = false for a shared-library package")
	}
	if len(meta.ELF) != 7 {
		t.Errorf("got %d ELF objects, want 7: %v", len(meta.ELF), meta.ELF)
	}
	if !slices.Contains(meta.ELF, "/usr/lib64/libcrypto.so.3.5.5") {
		t.Errorf("libcrypto is not among the ELF objects: %v", meta.ELF)
	}
	if !slices.IsSorted(meta.ELF) {
		t.Error("ELF paths are not sorted")
	}
	// Only the objects, not the directories and config files beside them.
	for _, f := range meta.ELF {
		if strings.HasSuffix(f, ".cnf") || strings.HasSuffix(f, "/") {
			t.Errorf("%q is not an ELF object", f)
		}
	}
}

// TestAPackageThatShipsNoCodeSaysSo is the other half. A package with no ELF
// anywhere is the one case a metadata-only scan can answer with certainty
// rather than undetermined, so getting an empty list right matters as much as
// getting a populated one right.
func TestAPackageThatShipsNoCodeSaysSo(t *testing.T) {
	pkg, meta := readFixture(t, "rocky9-rocky-release")
	if pkg.Arch != "noarch" {
		t.Errorf("Arch = %q, want noarch", pkg.Arch)
	}
	if meta.HasELF() {
		t.Errorf("HasELF() = true for a config-only package: %v", meta.ELF)
	}
	// Not an empty file list -- the package owns plenty, none of it code.
	if len(pkg.Files) == 0 {
		t.Error("got no files; no-ELF must not be reached by failing to read the list")
	}
}

// TestReadFileParsesASUSEPackage covers the distro the source name matters most
// on. Querying OSV for libopenssl3/SUSE returns nothing at all; openssl-3
// returns 32 vulnerabilities. A parser that dropped SOURCERPM would report this
// package clean.
func TestReadFileParsesASUSEPackage(t *testing.T) {
	pkg, meta := readFixture(t, "sle15-libopenssl3")
	if pkg.Name != "libopenssl3" || pkg.Source != "openssl-3" {
		t.Errorf("Name/Source = %q/%q, want libopenssl3/openssl-3", pkg.Name, pkg.Source)
	}
	// SUSE sets no epoch, and rpm's absent-EPOCH is zero by definition. The
	// zero is still written, matching how the records are published.
	if pkg.Version != "0:3.1.4-150600.2.19" {
		t.Errorf("Version = %q", pkg.Version)
	}
	if meta.Distribution != "SUSE Linux Enterprise 15" {
		t.Errorf("Distribution = %q", meta.Distribution)
	}
	// The vendor carries a URL in angle brackets, which the ecosystem lookup
	// has to cope with rather than expect a bare name.
	if !strings.HasPrefix(meta.Vendor, "SUSE LLC") {
		t.Errorf("Vendor = %q", meta.Vendor)
	}
	if !meta.HasELF() {
		t.Error("HasELF() = false for libopenssl3")
	}
}

func TestReadFileRejectsWhatIsNotAnRPM(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		// An HTTP error page saved as a .rpm is the likeliest way this happens:
		// a mirror answers 404 with HTML and 200 is never checked. It is 53
		// bytes, shorter than the 96-byte lead, so it has to be recognised as
		// the wrong kind of file and not as a cut-short right one.
		{"an html error page", []byte("<!DOCTYPE html><html><body>404 Not Found</body></html>"), ErrNotRPM},
		{"a deb", append([]byte("!<arch>\ndebian-binary"), make([]byte, 100)...), ErrNotRPM},
		{"empty", nil, ErrNotRPM},
		{"a lead and nothing else", validLead(), ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ReadFile(bytes.NewReader(tt.in))
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestATruncatedHeaderIsAnErrorNotAnEmptyPackage walks the truncation point
// through the whole of a real header. Every prefix must fail, because a
// partially-read package that reported the tags it managed to reach would be a
// package with fewer files than it has -- and a file list that is short is a
// package that looks like it ships no code.
func TestATruncatedHeaderIsAnErrorNotAnEmptyPackage(t *testing.T) {
	full := fixture(t, "rocky9-rocky-release")
	// From 4 bytes up: the magic is intact, so every one of these is a real rpm
	// that stopped early and must be reported as one.
	for _, n := range []int{4, 50, 95, 96, 100, 200, 1000, 5000, len(full) - 1} {
		pkg, _, err := ReadFile(bytes.NewReader(full[:n]))
		if err == nil {
			t.Errorf("truncated to %d bytes: no error, got package %q with %d files", n, pkg.Name, len(pkg.Files))
			continue
		}
		if !errors.Is(err, ErrTruncated) {
			t.Errorf("truncated to %d bytes: err = %v, want it to say the file was cut short", n, err)
		}
	}
	// Below four bytes there is not enough to tell a cut-short rpm from a file
	// that was never one, and the magic is what gets reported. Either answer
	// stops the scan; neither can be mistaken for a package that parsed.
	for _, n := range []int{1, 2, 3} {
		if _, _, err := ReadFile(bytes.NewReader(full[:n])); err == nil {
			t.Errorf("truncated to %d bytes: no error", n)
		}
	}
	// And the whole thing still parses, so the loop above is not passing for
	// the wrong reason.
	if _, _, err := ReadFile(bytes.NewReader(full)); err != nil {
		t.Fatalf("the untruncated fixture failed: %v", err)
	}
}

// TestAHeaderCannotClaimMoreThanItHas guards the allocation. nindex and hsize
// are read straight off an untrusted file and used as make() sizes; a header
// claiming four billion entries must be rejected before the allocation, not
// after it.
func TestAHeaderCannotClaimMoreThanItHas(t *testing.T) {
	tests := []struct {
		name           string
		nindex, hsize  uint32
		wantSubstrings string
	}{
		{"absurd index count", 1 << 30, 16, "index entries"},
		{"absurd data size", 1, 1 << 30, "bytes of data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			b.Write(validLead())
			b.Write(headerBytes(tt.nindex, tt.hsize))
			_, _, err := ReadFile(&b)
			if err == nil || !strings.Contains(err.Error(), tt.wantSubstrings) {
				t.Errorf("err = %v, want it to name the %s limit", err, tt.wantSubstrings)
			}
		})
	}
}

func validLead() []byte {
	lead := make([]byte, rpmLeadSize)
	copy(lead, rpmLeadMagic)
	return lead
}

// headerBytes is a header preamble that claims nindex entries and hsize bytes
// without supplying either.
func headerBytes(nindex, hsize uint32) []byte {
	h := make([]byte, rpmHeaderSize)
	copy(h, rpmHeaderMagic)
	binary.BigEndian.PutUint32(h[8:12], nindex)
	binary.BigEndian.PutUint32(h[12:16], hsize)
	return h
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
		if got := SourceRPMName(tt.in); got != tt.want {
			t.Errorf("SourceRPMName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
