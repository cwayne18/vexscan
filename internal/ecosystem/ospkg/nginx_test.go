package ospkg

import (
	"os"
	"path/filepath"
	"testing"

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
