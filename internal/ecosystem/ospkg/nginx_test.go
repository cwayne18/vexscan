package ospkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

func TestDiscoverNginx(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "usr/local/nginx/sbin/nginx")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	data := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("nginx/1.27.1 built for ingress-nginx")...)
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}

	pkgs := discoverNginx(target.NewDirFS(root), pkgdb.FormatAPK)
	if len(pkgs) != 1 {
		t.Fatalf("discovered %d nginx packages, want 1", len(pkgs))
	}
	if got, want := pkgs[0].Name, "nginx"; got != want {
		t.Errorf("name = %q, want %q", got, want)
	}
	if got, want := pkgs[0].Version, "1.27.1"; got != want {
		t.Errorf("version = %q, want %q", got, want)
	}
	if got, want := pkgs[0].Files, []string{"/usr/local/nginx/sbin/nginx"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("files = %v, want %v", got, want)
	}
}

func TestDiscoverNginxVersionRejectsConflictingBinaries(t *testing.T) {
	root := t.TempDir()
	for name, version := range map[string]string{
		"usr/local/nginx/sbin/nginx": "1.27.1",
		"usr/sbin/nginx":             "1.29.0",
	} {
		filename := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		data := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("nginx/"+version)...)
		if err := os.WriteFile(filename, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if got := discoverNginxVersion(target.NewDirFS(root), pkgdb.FormatAPK); got != nil {
		t.Fatalf("discovered conflicting nginx versions: %+v", got)
	}
}

func TestFilterUninstalledNginx(t *testing.T) {
	native := []pkgdb.Package{{Name: "nginx", Version: "1.27.1"}}
	if got := filterUninstalledNginx(native, []pkgdb.Package{{Name: "nginx"}}); got != nil {
		t.Fatalf("native nginx was not suppressed when package database already contains nginx")
	}
	if got := filterUninstalledNginx(native, []pkgdb.Package{{Name: "openssl"}}); len(got) != 1 {
		t.Fatalf("native nginx was suppressed by unrelated package: %+v", got)
	}
}

// The false positive this demotion exists for.
//
// registry.suse.com/rancher/nginx-ingress-controller:v1.15.2-prime7 compiles
// nginx 1.27.1 into /usr/local/nginx/sbin/nginx. Filed as an OS package it
// picks up SUSE's ecosystem, and SUSE-SU-2026:23118-1 says CVE-2026-42533 is
// fixed in the rpm revision 1.27.2-160000.7.1. Ordering "1.27.1" against that
// is a comparison between two different numbering systems, about a package the
// image does not install -- and Rancher had in fact backported the fix as
// 44_nginx-1.27.1-CVE-2026-42533.patch without touching the version string.
func TestSourceBuiltNginxIsNotDecidedByDistroAdvisories(t *testing.T) {
	pkg := pkgdb.Package{
		Format:  pkgdb.FormatRPM,
		Name:    "nginx",
		Version: "1.27.1",
		Files:   []string{"/usr/local/nginx/sbin/nginx"},
		DB:      "embedded binary /usr/local/nginx/sbin/nginx",
	}
	affected := ecosystem.Finding{
		Module: "nginx", Version: "1.27.1", CVE: "CVE-2026-42533",
		Status: ecosystem.StatusLinked, Method: "elf-needed-closure",
	}

	got := sourceBuiltVerdict(affected, "SUSE", pkg)
	if got.Status != ecosystem.StatusUndetermined {
		t.Errorf("status = %s, want undetermined", got.Status)
	}
	if got.Reason != ReasonSourceBuiltPackage {
		t.Errorf("reason = %q, want %q", got.Reason, ReasonSourceBuiltPackage)
	}
	// Not_affected would be the wrong demotion: nothing in the artifact shows
	// the backport is in this build.
	if got.Status == ecosystem.StatusNotPresent || got.Justification != "" {
		t.Errorf("demoted to a clean verdict (%s/%s); nothing proved the patch is applied",
			got.Status, got.Justification)
	}
	var detail string
	for _, e := range got.Evidence {
		if e.Origin == OriginSourceBuiltPackage {
			detail = e.Detail
		}
	}
	if detail == "" {
		t.Fatal("no evidence recorded for the demotion")
	}
	// The note has to name the binary it was read from, or a reader cannot
	// tell this row apart from one about an installed package.
	for _, want := range []string{"/usr/local/nginx/sbin/nginx", "1.27.1", "SUSE"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail is missing %q:\n%s", want, detail)
		}
	}
}

// Only the affected verdicts move. A not_present verdict was decided by
// reading the filesystem and the ELF closure, which are facts about this image
// whoever compiled the binary, and demoting those would throw away the one
// conclusion that survived the version problem intact.
func TestSourceBuiltNginxKeepsItsRuledOutVerdicts(t *testing.T) {
	pkg := pkgdb.Package{Name: "nginx", Version: "1.27.1",
		Files: []string{"/usr/local/nginx/sbin/nginx"}}
	for _, f := range []ecosystem.Finding{
		{CVE: "CVE-1", Status: ecosystem.StatusNotPresent, Justification: "vulnerable_code_not_present"},
		{CVE: "CVE-2", Status: ecosystem.StatusNotInPath, Justification: "vulnerable_code_not_in_execute_path"},
		{CVE: "CVE-3", Status: ecosystem.StatusUndetermined},
	} {
		got := sourceBuiltVerdict(f, "SUSE", pkg)
		if got.Status != f.Status || got.Reason != f.Reason {
			t.Errorf("%s: %s/%q became %s/%q", f.CVE, f.Status, f.Reason, got.Status, got.Reason)
		}
		if len(got.Evidence) != 0 {
			t.Errorf("%s: evidence added to a verdict that did not move", f.CVE)
		}
	}
}

// An nginx the package manager really did install is the distribution's own,
// and its advisories apply exactly as they always have. filterUninstalledNginx
// keeps the two paths disjoint, so this is a check that the marker never
// reaches an installed package rather than a second behaviour.
func TestInstalledNginxIsUnaffectedByTheDemotion(t *testing.T) {
	pr := &prepared{ecosystem: "SUSE", distro: "sles"}
	installed := pr.component(pkgdb.Package{
		Format: pkgdb.FormatRPM, Name: "nginx", Version: "1.27.2-160000.7.1",
		DB: "/usr/lib/sysimage/rpm/Packages.db",
	})
	if installed.Extra.(*state).sourceBuilt {
		t.Error("a package read from the rpm database was marked source-built")
	}
	native := pr.nativeComponent(pkgdb.Package{
		Format: pkgdb.FormatRPM, Name: "nginx", Version: "1.27.1",
		Files: []string{"/usr/local/nginx/sbin/nginx"},
		DB:    "embedded binary /usr/local/nginx/sbin/nginx",
	})
	if !native.Extra.(*state).sourceBuilt {
		t.Error("a package read from an executable was not marked source-built")
	}
}

func TestNginxComponentUsesBinaryAsEvidence(t *testing.T) {
	pr := &prepared{ecosystem: "Alpine", distro: "alpine"}
	component := pr.component(pkgdb.Package{
		Format:  pkgdb.FormatAPK,
		Name:    "nginx",
		Version: "1.27.1",
		Files:   []string{"/usr/local/nginx/sbin/nginx"},
		DB:      "embedded binary /usr/local/nginx/sbin/nginx",
	})
	if component.Name != "nginx" || component.Version != "1.27.1" {
		t.Fatalf("component = %+v, want nginx 1.27.1", component)
	}
	state, ok := component.Extra.(*state)
	if !ok || len(state.pkg.Files) != 1 || state.pkg.Files[0] != "/usr/local/nginx/sbin/nginx" {
		t.Fatalf("component evidence = %#v, want nginx binary path", component.Extra)
	}
}
