package ospkg

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

// rocky and sle stand in for a header ReadFile parsed to the end, so both set
// FilesKnown -- without it their empty ELF lists would mean "nobody looked"
// rather than "this package ships no code", and the two lead to opposite
// verdicts. See TestAnUnreadFileListIsNotAClearance.
func rocky(name, version string) Supplied {
	return Supplied{
		Package: pkgdb.Package{Format: pkgdb.FormatRPM, Name: name, Version: version, Arch: "x86_64", DB: "/tmp/repo/" + name + ".rpm"},
		Meta:    pkgdb.Meta{Vendor: "Rocky Enterprise Software Foundation", Distribution: "Rocky Linux 9", FilesKnown: true},
	}
}

func sle(name, version string) Supplied {
	return Supplied{
		Package: pkgdb.Package{Format: pkgdb.FormatRPM, Name: name, Version: version, Arch: "x86_64", DB: "/tmp/sle/" + name + ".rpm"},
		Meta:    pkgdb.Meta{Vendor: "SUSE LLC <https://www.suse.com/>", Distribution: "SUSE Linux Enterprise 15", FilesKnown: true},
	}
}

// fromSBOM stands in for a component sbomsrc built out of a purl: coordinates,
// a distribution stated outright, and nothing else. No vendor, no distribution
// header, no file list -- it is deliberately the emptiest Supplied that still
// has to produce a usable scan.
func fromSBOM(name, version string, rel osv.Release) Supplied {
	return Supplied{
		Package: pkgdb.Package{Format: pkgdb.FormatDeb, Name: name, Version: version, Arch: "amd64", DB: "bom.json"},
		Release: rel,
		Origin:  MethodSBOM,
	}
}

// TestReleaseFromHeaderCoversTheVendorsThatShipRPMs pins the derivation against
// the two headers that were measured, and against the shapes the rest of the
// table exists for. The strings on the left are what the packages actually
// carry; the ecosystems on the right are what OSV actually answers to.
func TestReleaseFromHeaderCoversTheVendorsThatShipRPMs(t *testing.T) {
	tests := []struct {
		name              string
		vendor, dist, ver string
		wantEco           string
	}{
		{
			name:    "rocky, measured",
			vendor:  "Rocky Enterprise Software Foundation",
			dist:    "Rocky Linux 9",
			ver:     "1:3.5.5-2.el9_8",
			wantEco: "Rocky Linux:9",
		},
		{
			name:    "sle, measured",
			vendor:  "SUSE LLC <https://www.suse.com/>",
			dist:    "SUSE Linux Enterprise 15",
			ver:     "0:3.1.4-150600.2.19",
			wantEco: "SUSE",
		},
		{
			// Red Hat's own packages carry a vendor and no DISTRIBUTION, so
			// the version has to come out of the release tag.
			name:    "red hat, version from the .el9 in the release",
			vendor:  "Red Hat, Inc.",
			ver:     "1:3.0.7-27.el9",
			wantEco: "Red Hat",
		},
		{
			name:    "almalinux",
			vendor:  "AlmaLinux OS Foundation",
			dist:    "AlmaLinux 9",
			ver:     "1:3.0.7-27.el9",
			wantEco: "AlmaLinux:9",
		},
		{
			// Both openSUSE products share the SUSE vendor string, so only
			// DISTRIBUTION separates them -- and they are different
			// ecosystems, not different versions of one.
			name:    "opensuse leap",
			vendor:  "openSUSE",
			dist:    "openSUSE Leap 15.6",
			ver:     "0:3.1.4-150600.2.19",
			wantEco: "openSUSE:Leap 15.6",
		},
		{
			name:    "opensuse tumbleweed",
			vendor:  "openSUSE",
			dist:    "openSUSE Tumbleweed",
			ver:     "0:3.4.1-1.1",
			wantEco: "openSUSE:Tumbleweed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, ok := releaseFromHeader(
				pkgdb.Package{Version: tt.ver},
				pkgdb.Meta{Vendor: tt.vendor, Distribution: tt.dist},
			)
			if !ok {
				t.Fatalf("no distribution recognised from vendor %q / dist %q", tt.vendor, tt.dist)
			}
			eco, err := rel.Ecosystem()
			if err != nil {
				t.Fatalf("Ecosystem(): %v", err)
			}
			if eco != tt.wantEco {
				t.Errorf("ecosystem = %q, want %q", eco, tt.wantEco)
			}
		})
	}
}

// TestADistributionOSVDoesNotCarryIsNotGuessed is the same rule the os-release
// path follows. Fedora, Oracle Linux and CentOS Stream are all rpm and all
// absent from OSV; mapping them to a near neighbour would produce a query that
// answers with nothing, which renders as a clean package.
func TestADistributionOSVDoesNotCarryIsNotGuessed(t *testing.T) {
	for _, m := range []pkgdb.Meta{
		{Vendor: "Fedora Project", Distribution: "Fedora Project"},
		{Vendor: "Oracle America", Distribution: "Oracle Linux 9"},
		{Vendor: "CentOS", Distribution: "CentOS Stream 9"},
		{}, // no vendor, no distribution: a locally built rpm
	} {
		if rel, ok := releaseFromHeader(pkgdb.Package{Version: "1.0-1.el9"}, m); ok {
			t.Errorf("vendor %q mapped to ID %q, want no answer", m.Vendor, rel.ID)
		}
	}
}

func TestSuppliedIdentity(t *testing.T) {
	t.Run("derived from the headers", func(t *testing.T) {
		p := &Plugin{Packages: []Supplied{rocky("openssl-libs", "1:3.5.5-2.el9_8"), rocky("zlib", "0:1.2.11-40.el9")}}
		eco, distro, err := SuppliedIdentity(p.Packages, p.Ecosystem)
		if err != nil {
			t.Fatal(err)
		}
		if eco != "Rocky Linux:9" {
			t.Errorf("ecosystem = %q", eco)
		}
		if distro != "rocky" {
			t.Errorf("distro = %q, want rocky for the purl namespace", distro)
		}
	})

	t.Run("the override wins and still names the distro", func(t *testing.T) {
		p := &Plugin{
			Ecosystem: "SUSE:Linux Enterprise Module for Basesystem 15 SP6",
			Packages:  []Supplied{sle("libopenssl3", "0:3.1.4-150600.2.19")},
		}
		eco, distro, err := SuppliedIdentity(p.Packages, p.Ecosystem)
		if err != nil {
			t.Fatal(err)
		}
		if eco != "SUSE:Linux Enterprise Module for Basesystem 15 SP6" {
			t.Errorf("ecosystem = %q, want the override verbatim", eco)
		}
		if distro != "sles" {
			t.Errorf("distro = %q", distro)
		}
	})

	t.Run("the override rescues a distribution with no mapping", func(t *testing.T) {
		p := &Plugin{
			Ecosystem: "Red Hat",
			Packages: []Supplied{{
				Package: pkgdb.Package{Name: "x", Version: "1-1", DB: "/tmp/x.rpm"},
				Meta:    pkgdb.Meta{Vendor: "Fedora Project"},
			}},
		}
		eco, distro, err := SuppliedIdentity(p.Packages, p.Ecosystem)
		if err != nil {
			t.Fatal(err)
		}
		if eco != "Red Hat" || distro != "" {
			t.Errorf("eco = %q, distro = %q; distro should stay empty rather than be invented", eco, distro)
		}
	})

	t.Run("no mapping and no override is an error naming the flag", func(t *testing.T) {
		p := &Plugin{Packages: []Supplied{{
			Package: pkgdb.Package{Name: "x", Version: "1-1", DB: "/tmp/build/x.rpm"},
			Meta:    pkgdb.Meta{Vendor: "Fedora Project"},
		}}}
		_, _, err := SuppliedIdentity(p.Packages, p.Ecosystem)
		if err == nil {
			t.Fatal("a package of unknown provenance scanned anyway")
		}
		for _, want := range []string{"--osv-ecosystem", "x.rpm"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to mention %q", err, want)
			}
		}
	})

	// An SBOM component has no VENDOR and no DISTRIBUTION -- everything
	// releaseFromHeader works from is absent -- so without the stated release
	// this inventory would resolve to nothing at all and demand
	// --osv-ecosystem for a document that plainly says which distribution it
	// describes.
	t.Run("a stated release carries an inventory with no headers", func(t *testing.T) {
		pkgs := []Supplied{
			fromSBOM("libssl3", "3.0.11-1~deb12u2", osv.Release{ID: "debian", VersionID: "12"}),
			fromSBOM("zlib1g", "1:1.2.13.dfsg-1", osv.Release{ID: "debian", VersionID: "12"}),
		}
		eco, distro, err := SuppliedIdentity(pkgs, "")
		if err != nil {
			t.Fatal(err)
		}
		if eco != "Debian:12" {
			t.Errorf("ecosystem = %q, want Debian:12", eco)
		}
		if distro != "debian" {
			t.Errorf("distro = %q, want debian for the purl namespace", distro)
		}
	})

	// The LTS suffix is the reason the whole Release travels rather than an id
	// and a version: "Ubuntu:22.04" is a real ecosystem that answers HTTP 200
	// with no records, so getting it wrong renders as a clean image.
	t.Run("a stated release keeps its LTS suffix", func(t *testing.T) {
		pkgs := []Supplied{fromSBOM("libssl3", "3.0.2-0ubuntu1.15", osv.ReleaseFromDistro("ubuntu", "22.04"))}
		eco, _, err := SuppliedIdentity(pkgs, "")
		if err != nil {
			t.Fatal(err)
		}
		if eco != "Ubuntu:22.04:LTS" {
			t.Errorf("ecosystem = %q, want Ubuntu:22.04:LTS", eco)
		}
	})

	// A stated identity beats an inferred one. The headers here are a synthesis
	// from two free-text tags; the release was read off a field whose whole job
	// is to say this.
	t.Run("a stated release wins over the headers", func(t *testing.T) {
		s := rocky("openssl-libs", "1:3.5.5-2.el9_8")
		s.Release = osv.Release{ID: "almalinux", VersionID: "9"}
		eco, distro, err := SuppliedIdentity([]Supplied{s}, "")
		if err != nil {
			t.Fatal(err)
		}
		if eco != "AlmaLinux:9" || distro != "almalinux" {
			t.Errorf("eco = %q, distro = %q; want the stated release, not the header", eco, distro)
		}
	})

	// The error has to describe the document the user handed over. Telling
	// someone who ran --sbom that their VENDOR headers are unusable sends them
	// looking at rpm files they never had.
	t.Run("an SBOM with no distro says so in its own vocabulary", func(t *testing.T) {
		pkgs := []Supplied{fromSBOM("libssl3", "3.0.11-1~deb12u2", osv.Release{})}
		_, _, err := SuppliedIdentity(pkgs, "")
		if err == nil {
			t.Fatal("components of unknown provenance scanned anyway")
		}
		for _, want := range []string{"SBOM components", "distro qualifier", "--osv-ecosystem"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to mention %q", err, want)
			}
		}
		if strings.Contains(err.Error(), "VENDOR") {
			t.Errorf("err = %v, which names headers an SBOM does not have", err)
		}
	})

	// Two distributions in one directory have no single right ecosystem, and
	// filing half the inventory under the wrong one is a silent miss, not a
	// visible one.
	t.Run("mixed distributions are refused, not averaged", func(t *testing.T) {
		p := &Plugin{Packages: []Supplied{rocky("openssl-libs", "1:3.5.5-2.el9_8"), sle("libopenssl3", "0:3.1.4-150600.2.19")}}
		_, _, err := SuppliedIdentity(p.Packages, p.Ecosystem)
		if err == nil {
			t.Fatal("a mixed directory resolved to one ecosystem")
		}
		for _, want := range []string{"rocky", "sles", "--osv-ecosystem"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to mention %q", err, want)
			}
		}
	})
}

// TestTheReleaseIsNeverNarrowed guards the one thing SuppliedIdentity does not
// return and prepareSupplied therefore has to leave empty. A DISTRIBUTION
// header stops at "SUSE Linux Enterprise 15" while the affected entries say
// "15 SP6", so narrowing on what the header knows would filter with a token no
// record carries and clear findings that are real.
func TestTheReleaseIsNeverNarrowed(t *testing.T) {
	for _, pkgs := range [][]Supplied{
		{sle("libopenssl3", "0:3.1.4-150600.2.19")},
		{rocky("openssl-libs", "1:3.5.5-2.el9_8")},
	} {
		pr := &prepared{}
		if err := (&Plugin{Packages: pkgs}).prepareSupplied(pr); err != nil {
			t.Fatal(err)
		}
		if pr.release != "" {
			t.Errorf("release = %q for %s, want no narrowing", pr.release, pkgs[0].Package.Name)
		}
	}
}

func TestPrepareSuppliedBuildsTheInventory(t *testing.T) {
	p := &Plugin{Packages: []Supplied{
		rocky("openssl-libs", "1:3.5.5-2.el9_8"),
		{
			Package: pkgdb.Package{Format: pkgdb.FormatRPM, Name: "rocky-release", Version: "0:9.8-1.1.el9", Arch: "noarch", DB: "/tmp/repo/sub/rocky-release.rpm"},
			Meta:    pkgdb.Meta{Vendor: "Rocky Enterprise Software Foundation", Distribution: "Rocky Linux 9"},
		},
	}}
	p.Packages[0].Meta.ELF = []string{"/usr/lib64/libssl.so.3"}

	pr := &prepared{}
	if err := p.prepareSupplied(pr); err != nil {
		t.Fatal(err)
	}
	if !pr.metadataOnly {
		t.Error("metadataOnly = false; every verdict that needs a filesystem is gated on this")
	}
	if len(pr.dbs) != 1 || len(pr.dbs[0].Packages) != 2 {
		t.Fatalf("dbs = %+v, want one rpm result holding both packages", pr.dbs)
	}
	// The log line that names where an inventory came from should name the
	// directory, not one of the files inside it.
	if pr.dbs[0].DB != "/tmp/repo" {
		t.Errorf("Result.DB = %q, want the directory containing both", pr.dbs[0].DB)
	}

	// The metadata has to survive the trip into a component, because it is the
	// only evidence a metadata-only verdict has.
	c := pr.component(p.Packages[0].Package)
	st, ok := c.Extra.(*state)
	if !ok {
		t.Fatalf("Extra = %T", c.Extra)
	}
	if !st.meta.HasELF() {
		t.Error("the ELF list did not reach the component")
	}
	if bare := pr.component(p.Packages[1].Package); bare.Extra.(*state).meta.HasELF() {
		t.Error("a package that ships no ELF came back claiming it does")
	}
	if c.Ecosystem != "Rocky Linux:9" {
		t.Errorf("Ecosystem = %q", c.Ecosystem)
	}
	if !strings.HasPrefix(c.PURL, "pkg:rpm/rocky/openssl-libs@") {
		t.Errorf("PURL = %q", c.PURL)
	}
}

// TestMetadataOnlyStatusTable is the --rpm counterpart of TestStatusTable. Two
// of its four rows are reachable from a package file and the other two are
// not, which is the honest limit of the mode.
func TestMetadataOnlyStatusTable(t *testing.T) {
	ships := rocky("openssl-libs", "1:3.5.5-2.el9_8")
	ships.Package.Files = []string{"/usr/lib64/libssl.so.3", "/usr/lib64/libcrypto.so.3", "/usr/share/doc/openssl-libs"}
	ships.Meta.ELF = []string{"/usr/lib64/libssl.so.3", "/usr/lib64/libcrypto.so.3"}

	docs := rocky("rocky-release", "0:9.8-1.1.el9")
	docs.Package.Files = []string{"/etc/rocky-release", "/usr/share/doc/rocky-release/LICENSE"}

	p := New(Options{Packages: []Supplied{ships, docs}})
	// There is no filesystem. An empty directory is the truthful stand-in: it
	// is what an inventory of packages that were never installed has behind
	// it, and every walk and nil check downstream works over it unchanged.
	img := &target.Image{Ref: "--rpm /tmp/repo", FS: target.NewDirFS(t.TempDir())}

	got := statuses(t, p, img, []ecosystem.Subject{{Raw: "all", Name: ""}})

	// A package that would install no code cannot execute a vulnerable
	// function, and that is true whether the file list came from an installed
	// database or from the header that would install it. Same method, because
	// it is the same evidence.
	if f := got["rocky-release"]; f.Status != ecosystem.StatusNotPresent || f.Method != MethodNoCode {
		t.Errorf("rocky-release: status = %s, method = %s; want not_present via %s", f.Status, f.Method, MethodNoCode)
	} else if f.Justification != "vulnerable_code_not_present" {
		t.Errorf("rocky-release: justification = %q", f.Justification)
	}

	f := got["openssl-libs"]
	if f.Status != ecosystem.StatusUndetermined {
		t.Errorf("openssl-libs: status = %s, want undetermined", f.Status)
	}
	if f.Reason != "no_reachability_test_possible" {
		t.Errorf("openssl-libs: reason = %q", f.Reason)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Origin != MethodRPMFile {
		t.Fatalf("openssl-libs: evidence = %+v, want one %s note", f.Evidence, MethodRPMFile)
	}
	// The evidence has to name the objects, because "undetermined" on its own
	// tells a reader nothing about what was and was not looked at.
	if !strings.Contains(f.Evidence[0].Detail, "libssl.so.3") {
		t.Errorf("evidence = %q, want it to name the ELF objects", f.Evidence[0].Detail)
	}
}

// TestAnUnreadFileListIsNotAClearance is the guard on the zero Meta.
//
// An rpm header answers "does this package ship code"; a description that
// carries no file list -- an SBOM component is the case this exists for --
// does not. Both arrive here with an empty ELF slice, and only FilesKnown
// tells them apart. Getting this wrong does not produce a wrong-looking
// report: it produces a clean one, for a package nobody examined.
func TestAnUnreadFileListIsNotAClearance(t *testing.T) {
	unread := rocky("openssl-libs", "1:3.5.5-2.el9_8")
	unread.Meta.FilesKnown = false

	p := New(Options{Packages: []Supplied{unread}})
	img := &target.Image{Ref: "--rpm /tmp/repo", FS: target.NewDirFS(t.TempDir())}

	f := statuses(t, p, img, []ecosystem.Subject{{Raw: "all", Name: ""}})["openssl-libs"]
	if f.Status != ecosystem.StatusUndetermined {
		t.Fatalf("status = %s via %s, want undetermined -- an unexamined package was declared clean", f.Status, f.Method)
	}
	if f.Method == MethodNoCode {
		t.Errorf("method = %s, which claims evidence that was never read", f.Method)
	}
	if f.Reason != ReasonNoReachabilityTest {
		t.Errorf("reason = %q, want %q", f.Reason, ReasonNoReachabilityTest)
	}
	// The row has to say which question went unanswered, or "undetermined"
	// reads the same as it does for a package that was fully examined and
	// merely untraceable.
	if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0].Detail, "does not list its files") {
		t.Errorf("evidence = %+v, want it to say the file list was missing", f.Evidence)
	}
}

// TestSBOMFindingsSayWhereTheyCameFrom checks the two halves of an SBOM row a
// reader has to be able to tell apart from an --rpm one.
//
// The origin differs, because the evidence differs: an rpm header was read and
// a bill of materials was believed. The reason does not, because
// writeMetadataCaveat counts ReasonNoReachabilityTest to size the note that
// explains these rows, and a caveat that disagreed with the rows under it
// would be worse than no caveat.
func TestSBOMFindingsSayWhereTheyCameFrom(t *testing.T) {
	p := New(Options{Packages: []Supplied{
		fromSBOM("libssl3", "3.0.11-1~deb12u2", osv.Release{ID: "debian", VersionID: "12"}),
	}})
	img := &target.Image{Ref: "--sbom bom.json", FS: target.NewDirFS(t.TempDir())}

	f := statuses(t, p, img, []ecosystem.Subject{{Raw: "all"}})["libssl3"]
	if f.Status != ecosystem.StatusUndetermined {
		t.Fatalf("status = %s via %s; a bill of materials cannot settle anything", f.Status, f.Method)
	}
	if f.Reason != ReasonNoReachabilityTest {
		t.Errorf("reason = %q, want %q -- the report's caveat counts this", f.Reason, ReasonNoReachabilityTest)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Origin != MethodSBOM {
		t.Fatalf("evidence = %+v, want one %s note", f.Evidence, MethodSBOM)
	}
	if !strings.Contains(f.Evidence[0].Detail, "does not list its files") {
		t.Errorf("detail = %q, want it to say the file list was never available", f.Evidence[0].Detail)
	}
}

// An inventory that states no origin is an --rpm one: the field postdates that
// caller, and a zero value there must not silently relabel its evidence.
func TestAnUnstatedOriginIsTheRPMOne(t *testing.T) {
	ships := rocky("openssl-libs", "1:3.5.5-2.el9_8")
	ships.Package.Files = []string{"/usr/lib64/libssl.so.3"}
	ships.Meta.ELF = ships.Package.Files

	p := New(Options{Packages: []Supplied{ships}})
	img := &target.Image{Ref: "--rpm /tmp/repo", FS: target.NewDirFS(t.TempDir())}

	f := statuses(t, p, img, []ecosystem.Subject{{Raw: "all"}})["openssl-libs"]
	if len(f.Evidence) != 1 || f.Evidence[0].Origin != MethodRPMFile {
		t.Errorf("evidence = %+v, want one %s note", f.Evidence, MethodRPMFile)
	}
}

// TestMetadataOnlyNeverClaimsReachability is the guarantee the mode rests on.
// linked and not_in_path are both assertions about what the dynamic linker
// would load, and no closure ran.
func TestMetadataOnlyNeverClaimsReachability(t *testing.T) {
	var pkgs []Supplied
	for _, name := range []string{"openssl-libs", "glibc", "zlib", "rocky-release", "bash"} {
		s := rocky(name, "0:1-1.el9")
		s.Package.Files = []string{"/usr/lib64/lib" + name + ".so"}
		if name != "rocky-release" {
			s.Meta.ELF = s.Package.Files
		}
		pkgs = append(pkgs, s)
	}

	p := New(Options{Packages: pkgs, Roots: []string{"/usr/bin/bash"}})
	img := &target.Image{Ref: "--rpm /tmp/repo", FS: target.NewDirFS(t.TempDir())}

	for name, f := range statuses(t, p, img, []ecosystem.Subject{{Raw: "all"}}) {
		switch f.Status {
		case ecosystem.StatusLinked, ecosystem.StatusNotInPath:
			t.Errorf("%s: status = %s, which claims a reachability test that never ran", name, f.Status)
		}
		if f.Method == MethodClosure {
			t.Errorf("%s: method = %s with no filesystem to close over", name, f.Method)
		}
	}
}

// TestMetaKeySeparatesBuildsOfOneName matters for a repository directory,
// which routinely holds several builds of the same package. Keying on the name
// alone would let one build's file list answer for another's.
func TestMetaKeySeparatesBuildsOfOneName(t *testing.T) {
	a := pkgdb.Package{Name: "openssl-libs", Arch: "x86_64", Version: "1:3.5.5-2.el9_8"}
	b := pkgdb.Package{Name: "openssl-libs", Arch: "x86_64", Version: "1:3.0.7-27.el9"}
	c := pkgdb.Package{Name: "openssl-libs", Arch: "aarch64", Version: "1:3.5.5-2.el9_8"}
	if metaKey(a) == metaKey(b) || metaKey(a) == metaKey(c) {
		t.Error("two different builds share a key")
	}
	if metaKey(a) != metaKey(a) {
		t.Error("the key is not stable")
	}
}

func TestCommonSource(t *testing.T) {
	pkgs := func(dbs ...string) []pkgdb.Package {
		var out []pkgdb.Package
		for _, db := range dbs {
			out = append(out, pkgdb.Package{DB: db})
		}
		return out
	}
	tests := []struct {
		name string
		in   []pkgdb.Package
		want string
	}{
		{"one file names itself", pkgs("/tmp/x/openssl.rpm"), "/tmp/x/openssl.rpm"},
		{"a flat directory", pkgs("/tmp/x/a.rpm", "/tmp/x/b.rpm"), "/tmp/x"},
		{"a nested one", pkgs("/tmp/x/a.rpm", "/tmp/x/l/b.rpm"), "/tmp/x"},
		{"nothing in common", pkgs("/a/x.rpm", "/b/y.rpm"), "/"},
		// URLs are paths enough for this: the only use is one log line.
		{"urls", pkgs("https://m/pub/a.rpm", "https://m/pub/b.rpm"), "https://m/pub"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commonSource(tt.in); got != tt.want {
				t.Errorf("commonSource() = %q, want %q", got, tt.want)
			}
		})
	}
}
