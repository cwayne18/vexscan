package ospkg

import (
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

// fakeELF is an elfgraph.Reader over a map, so the status table can be
// exercised against a tree of empty files. What an ELF header looks like is
// internal/elfgraph's problem and is tested there against real objects.
type fakeELF map[string]*elfgraph.Info

func (f fakeELF) read(_ target.RootFS, name string) (*elfgraph.Info, error) {
	if info, ok := f[name]; ok {
		return info, nil
	}
	return nil, elfgraph.ErrNotELF
}

func lib(soname string, needed ...string) *elfgraph.Info {
	return &elfgraph.Info{
		Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_DYN,
		Dynamic: true, Soname: soname, Needed: needed,
	}
}

func exe(needed ...string) *elfgraph.Info {
	return &elfgraph.Info{
		Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC,
		Dynamic: true, Interp: "/lib64/ld-linux-x86-64.so.2", Needed: needed,
	}
}

// debPkg describes one row to write into the fixture's dpkg database.
type debPkg struct {
	name, version, source string
	files                 []string
}

// debianImage writes a dpkg database, an os-release, and the files the
// packages claim to own.
func debianImage(t *testing.T, cfg target.ImageConfig, pkgs []debPkg, extra map[string]string) *target.Image {
	t.Helper()
	root := t.TempDir()

	write := func(name, content string) {
		p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var status strings.Builder
	for _, p := range pkgs {
		status.WriteString("Package: " + p.name + "\n")
		status.WriteString("Status: install ok installed\n")
		status.WriteString("Architecture: amd64\n")
		if p.source != "" {
			status.WriteString("Source: " + p.source + "\n")
		}
		status.WriteString("Version: " + p.version + "\n\n")

		write("/var/lib/dpkg/info/"+p.name+":amd64.list", strings.Join(p.files, "\n")+"\n")
		for _, f := range p.files {
			write(f, "")
		}
	}
	write("/var/lib/dpkg/status", status.String())
	write("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")
	for name, content := range extra {
		write(name, content)
	}

	return &target.Image{Ref: "test", FS: target.NewDirFS(root), Config: cfg}
}

// statuses runs the whole plugin over one advisory and reports the status and
// method per package.
func statuses(t *testing.T, p *Plugin, img *target.Image, subjects []ecosystem.Subject) map[string]ecosystem.Finding {
	t.Helper()
	ctx := context.Background()

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

	adv := &osv.Advisory{ID: "CVE-2024-0001", Summary: "a hole"}
	items := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		items = append(items, ecosystem.WorkItem{
			Component:  c,
			Advisories: map[string]*osv.Advisory{"CVE-2024-0001": adv},
			Requested:  []string{"CVE-2024-0001"},
		})
	}

	findings, err := p.AnalyzeImage(ctx, img, items)
	if err != nil {
		t.Fatalf("AnalyzeImage: %v", err)
	}
	out := map[string]ecosystem.Finding{}
	for _, f := range findings {
		out[f.Module] = f
	}
	return out
}

// The four rows of the status table, in one image.
func TestStatusTable(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{
			// Reachable: the entrypoint links it.
			{name: "libssl3", version: "3.0.11-1", source: "openssl", files: []string{"/usr/lib/libssl.so.3"}},
			// Installed and loadable, but nothing loads it.
			{name: "libunused1", version: "1.0-1", files: []string{"/usr/lib/libunused.so.1"}},
			// Installed, no code at all.
			{name: "manpages", version: "6.03-2", files: []string{"/usr/share/man/man1/intro.1"}},
		},
		map[string]string{"/usr/bin/app": ""})

	p := New(Options{ReadELF: fakeELF{
		"/usr/bin/app":            exe("libssl.so.3"),
		"/usr/lib/libssl.so.3":    lib("libssl.so.3"),
		"/usr/lib/libunused.so.1": lib("libunused.so.1"),
	}.read})

	got := statuses(t, p, img, []ecosystem.Subject{
		{Ecosystem: "os", Name: "notinstalled", Raw: "os:notinstalled"},
		{Raw: ""}, // everything
	})

	want := []struct {
		pkg, status, justification, method string
	}{
		{"openssl", "linked", "", MethodClosure},
		{"libunused1", "not_in_execute_path", "vulnerable_code_not_in_execute_path", MethodClosure},
		{"manpages", "not_present", "vulnerable_code_not_present", MethodNoCode},
		{"notinstalled", "not_present", "component_not_present", MethodInventory},
	}
	for _, w := range want {
		f, ok := got[w.pkg]
		if !ok {
			t.Errorf("%s: no finding (got %v)", w.pkg, keys(got))
			continue
		}
		if string(f.Status) != w.status || f.Justification != w.justification || f.Method != w.method {
			t.Errorf("%s: got %s/%s/%s, want %s/%s/%s",
				w.pkg, f.Status, f.Justification, f.Method, w.status, w.justification, w.method)
		}
		if len(f.Evidence) == 0 {
			t.Errorf("%s: no evidence recorded", w.pkg)
		}
		// Nothing about this image is unaccountable, so every status here is a
		// conclusion the closure reached rather than one it fell back to.
		for _, e := range f.Evidence {
			if e.Blocking {
				t.Errorf("%s: unexpected blocking evidence %q", w.pkg, e.Detail)
			}
		}
	}
	if len(got) != 4 {
		t.Errorf("got %d findings, want 4: %v", len(got), keys(got))
	}
}

// Debian files advisories against the source package, so that is the name
// queried, with the installed name kept as an alternative.
func TestInventoryUsesTheNameOSVKeysOn(t *testing.T) {
	img := debianImage(t, target.ImageConfig{Cmd: []string{"/bin/sh"}},
		[]debPkg{{name: "libssl3", version: "3.0.11-1", source: "openssl", files: []string{"/usr/lib/libssl.so.3"}}}, nil)

	p := New(Options{ReadELF: fakeELF{}.read})
	components, err := p.InventoryImage(context.Background(), img, []ecosystem.Subject{{Raw: ""}})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 {
		t.Fatalf("got %d components, want 1", len(components))
	}
	c := components[0]
	if c.Ecosystem != "Debian:12" {
		t.Errorf("ecosystem = %q, want Debian:12", c.Ecosystem)
	}
	if c.Name != "openssl" || !reflect.DeepEqual(c.AltNames, []string{"libssl3"}) {
		t.Errorf("name/alts = %q/%v, want openssl/[libssl3]", c.Name, c.AltNames)
	}
	if c.PURL != "pkg:deb/debian/libssl3@3.0.11-1?arch=amd64" {
		t.Errorf("purl = %q", c.PURL)
	}
}

// A taint means the closure is not a complete account of what gets loaded, so
// "nothing reaches this package" stops being a conclusion and becomes an
// observation. The status must fall back to linked, with the reason recorded.
func TestABlockingTaintPreventsTheUnreachableConclusion(t *testing.T) {
	img := debianImage(t,
		// A statically linked entrypoint: its libraries are inside it, so an
		// untouched .so on disk proves nothing.
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "libunused1", version: "1.0-1", files: []string{"/usr/lib/libunused.so.1"}}},
		map[string]string{"/usr/bin/app": ""})

	p := New(Options{ReadELF: fakeELF{
		"/usr/bin/app":            {Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC},
		"/usr/lib/libunused.so.1": lib("libunused.so.1"),
	}.read})

	f := statuses(t, p, img, []ecosystem.Subject{{Raw: ""}})["libunused1"]
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %s, want linked", f.Status)
	}
	var blocking int
	for _, e := range f.Evidence {
		if e.Blocking {
			blocking++
			if !strings.Contains(e.Detail, "statically linked") {
				t.Errorf("blocking evidence does not say why: %q", e.Detail)
			}
		}
	}
	if blocking != 1 {
		t.Errorf("got %d blocking evidence entries, want 1", blocking)
	}
}

// A scoped taint belongs only to the package that provides the soname it names.
func TestAScopedTaintOnlyBlocksItsOwnPackage(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{
			// libmissing1's file was deleted from the image after install --
			// something still needs its soname, so the resolver came up empty
			// where it should not have.
			{name: "libmissing1", version: "1.0-1", files: []string{"/usr/lib/libmissing.so.1"}},
			{name: "libunused1", version: "1.0-1", files: []string{"/usr/lib/libunused.so.1"}},
		},
		map[string]string{"/usr/bin/app": ""})
	// Remove the file the database claims libmissing1 installed.
	host, err := img.FS.HostPath("/usr/lib/libmissing.so.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(host); err != nil {
		t.Fatal(err)
	}

	p := New(Options{ReadELF: fakeELF{
		"/usr/bin/app":            exe("libmissing.so.1"),
		"/usr/lib/libunused.so.1": lib("libunused.so.1"),
	}.read})

	got := statuses(t, p, img, []ecosystem.Subject{{Raw: ""}})
	// The package whose file is gone owns no ELF object in the image at all.
	if f := got["libmissing1"]; f.Method != MethodNoCode {
		t.Errorf("libmissing1: method = %s, want %s", f.Method, MethodNoCode)
	}
	// The unrelated package is unaffected by someone else's missing library.
	if f := got["libunused1"]; f.Status != ecosystem.StatusNotInPath {
		t.Errorf("libunused1: status = %s, want not_in_execute_path", f.Status)
	}
}

// dpkg records pre-usrmerge paths for files that now live under /usr. Comparing
// those strings against the walked tree finds nothing, and finding nothing
// reads as "this package ships no code".
func TestUsrMergePathsStillFindThePackagesCode(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "libc6", version: "2.36-9", source: "glibc", files: []string{"/lib/x86_64-linux-gnu/libc.so.6"}}},
		map[string]string{"/usr/bin/app": "", "/usr/lib/x86_64-linux-gnu/libc.so.6": ""})

	// /lib -> usr/lib, as every modern Debian image has it. The database's
	// path and the real path differ by that symlink.
	root := img.FS.Root()
	if err := os.RemoveAll(filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}

	p := New(Options{ReadELF: fakeELF{
		"/usr/bin/app":                        exe("libc.so.6"),
		"/usr/lib/x86_64-linux-gnu/libc.so.6": lib("libc.so.6"),
	}.read})

	f := statuses(t, p, img, []ecosystem.Subject{{Raw: ""}})["glibc"]
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %s, want linked -- the symlinked path lost the package's code", f.Status)
	}
}

// An image with no package manager is not this plugin's business, and saying so
// is not an error.
func TestDetectIsFalseWithoutAPackageDatabase(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	img := &target.Image{Ref: "scratch", FS: target.NewDirFS(root)}

	ok, err := New(Options{}).DetectImage(context.Background(), img)
	if err != nil {
		t.Fatalf("a scratch image is not a failure: %v", err)
	}
	if ok {
		t.Error("the plugin claims to apply to an image with no package manager")
	}
}

// A database that cannot be tied to an OSV ecosystem must stop the plugin. The
// alternative is an inventory that resolves to zero advisories, which is
// indistinguishable from an image with nothing wrong with it.
func TestAnUnidentifiableDistributionIsAnError(t *testing.T) {
	img := debianImage(t, target.ImageConfig{},
		[]debPkg{{name: "libssl3", version: "3.0.11-1", files: []string{"/usr/lib/libssl.so.3"}}}, nil)
	host, err := img.FS.HostPath("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host, []byte("ID=notadistro\nVERSION_ID=\"1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := New(Options{}).DetectImage(context.Background(), img); err == nil {
		t.Fatal("an unmappable distribution was accepted")
	}

	// ...and --ecosystem is the way out.
	ok, err := New(Options{Ecosystem: "Debian:12"}).DetectImage(context.Background(), img)
	if err != nil || !ok {
		t.Fatalf("--ecosystem override: ok=%v err=%v", ok, err)
	}
}

// A bare name is how --module names a Go module. Answering
// "component_not_present" for every Go module path on every image would be
// noise no reader could distinguish from a real result.
func TestAnAbsentPackageIsOnlyReportedWhenItWasAimedHere(t *testing.T) {
	img := debianImage(t, target.ImageConfig{Cmd: []string{"/bin/sh"}},
		[]debPkg{{name: "libssl3", version: "3.0.11-1", source: "openssl", files: []string{"/usr/lib/libssl.so.3"}}}, nil)
	p := New(Options{ReadELF: fakeELF{}.read})

	for _, tt := range []struct {
		name    string
		subject ecosystem.Subject
		want    int
	}{
		{"bare go module path", ecosystem.Subject{Name: "golang.org/x/net", Raw: "golang.org/x/net"}, 0},
		{"named ecosystem", ecosystem.Subject{Ecosystem: "os", Name: "curl", Raw: "os:curl"}, 1},
		{"named distribution", ecosystem.Subject{Ecosystem: "debian", Name: "curl", Raw: "debian:curl"}, 1},
		{"deb purl", ecosystem.Subject{PURL: "pkg:deb/debian/curl@8.0", Raw: "pkg:deb/debian/curl@8.0"}, 1},
		{"golang purl", ecosystem.Subject{PURL: "pkg:golang/golang.org%2Fx%2Fnet@v0.17.0", Raw: "p"}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			components, err := p.InventoryImage(context.Background(), img, []ecosystem.Subject{tt.subject})
			if err != nil {
				t.Fatal(err)
			}
			if len(components) != tt.want {
				t.Errorf("got %d components, want %d", len(components), tt.want)
			}
		})
	}
}

// --package openssl must find the libssl3 that was built from it.
func TestASubjectMatchesTheSourceNameToo(t *testing.T) {
	img := debianImage(t, target.ImageConfig{Cmd: []string{"/bin/sh"}},
		[]debPkg{
			{name: "libssl3", version: "3.0.11-1", source: "openssl", files: []string{"/usr/lib/libssl.so.3"}},
			{name: "zlib1g", version: "1.2.13", source: "zlib", files: []string{"/usr/lib/libz.so.1"}},
		}, nil)

	p := New(Options{ReadELF: fakeELF{}.read})
	components, err := p.InventoryImage(context.Background(), img,
		[]ecosystem.Subject{{Ecosystem: "os", Name: "openssl", Raw: "os:openssl"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || components[0].Name != "openssl" {
		t.Fatalf("got %d components (%+v), want just openssl", len(components), components)
	}
}

// Red Hat's OSV records carry the rpm epoch; Azure Linux's do not, and an
// epoch-prefixed query against them matches nothing -- which reads exactly like
// a clean image.
func TestOSVVersionStripsTheEpochOnlyWhereItMustBe(t *testing.T) {
	pkg := pkgdb.Package{Format: pkgdb.FormatRPM, Name: "glibc", Version: "0:2.38-6", Epoch: 0}
	rh := pkgdb.Package{Format: pkgdb.FormatRPM, Name: "openssl", Version: "1:3.0.7-24.el9", Epoch: 1}
	deb := pkgdb.Package{Format: pkgdb.FormatDeb, Name: "openssl", Version: "1:3.0.11-1"}

	for _, tt := range []struct {
		eco  string
		pkg  pkgdb.Package
		want string
	}{
		{"Azure Linux:3", pkg, "2.38-6"},
		{"Red Hat", rh, "1:3.0.7-24.el9"},
		{"Rocky Linux:9", rh, "1:3.0.7-24.el9"},
		// A deb epoch is part of the version everywhere, including on the
		// one distribution that strips rpm epochs.
		{"Azure Linux:3", deb, "1:3.0.11-1"},
	} {
		if got := osvVersion(tt.eco, tt.pkg); got != tt.want {
			t.Errorf("osvVersion(%q, %s) = %q, want %q", tt.eco, tt.pkg.Version, got, tt.want)
		}
	}
}

func TestParsePURL(t *testing.T) {
	for _, tt := range []struct {
		in, name, typ string
		ok            bool
	}{
		{"pkg:deb/debian/libssl3@3.0.11-1?arch=amd64", "libssl3", "deb", true},
		{"pkg:rpm/redhat/openssl-libs@1:3.0.7-24.el9", "openssl-libs", "rpm", true},
		{"pkg:apk/alpine/openssl@3.1.4-r5", "openssl", "apk", true},
		{"pkg:golang/golang.org%2Fx%2Fnet@v0.17.0", "golang.org%2Fx%2Fnet", "golang", true},
		{"openssl", "", "", false},
	} {
		name, typ, ok := parsePURL(tt.in)
		if name != tt.name || typ != tt.typ || ok != tt.ok {
			t.Errorf("parsePURL(%q) = %q/%q/%v, want %q/%q/%v", tt.in, name, typ, ok, tt.name, tt.typ, tt.ok)
		}
	}
}

func TestFamiliesAreSelectable(t *testing.T) {
	p := New(Options{})
	for _, sel := range []string{"os", "debian", "Debian:12", "red hat", "alpine"} {
		if !ecosystem.MatchEcosystem(p, sel) {
			t.Errorf("--ecosystem %q does not select the OS plugin", sel)
		}
	}
	if ecosystem.MatchEcosystem(p, "golang") {
		t.Error("--ecosystem golang selects the OS plugin")
	}
}

func keys(m map[string]ecosystem.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
