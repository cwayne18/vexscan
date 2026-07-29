package analyze

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

func tree(t *testing.T, files map[string]string) target.RootFS {
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

func discard(string, ...any) {}

func TestReadOSInfo(t *testing.T) {
	tests := []struct {
		name            string
		files           map[string]string
		wantNil         bool
		wantEcosystem   string
		wantErrFragment string
	}{
		{
			name: "debian",
			files: map[string]string{
				"/etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
			},
			wantEcosystem: "Debian:12",
		},
		{
			// Distroless keeps ID=debian and a PRETTY_NAME of its own; the
			// ecosystem comes from ID and VERSION_ID, not the marketing name.
			name: "distroless",
			files: map[string]string{
				"/etc/os-release": "PRETTY_NAME=\"Distroless\"\nNAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n",
			},
			wantEcosystem: "Debian:12",
		},
		{
			// Some images ship only /usr/lib/os-release, with /etc/os-release
			// as a symlink that image slimming removed.
			name: "usr-lib-fallback",
			files: map[string]string{
				"/usr/lib/os-release": "ID=alpine\nVERSION_ID=3.19.1\n",
			},
			wantEcosystem: "Alpine:v3.19",
		},
		{
			// SLE resolves to the bare family. A derived product name would be
			// wrong for most of the image -- SUSE files base packages against
			// the module that ships them -- so the narrowing happens against
			// the affected entries after the query instead.
			name: "sle-is-the-bare-family",
			files: map[string]string{
				"/etc/os-release": "ID=\"sles\"\nVERSION_ID=\"15.5\"\nPRETTY_NAME=\"SUSE Linux Enterprise Server 15 SP5\"\n",
			},
			wantEcosystem: "SUSE",
		},
		{
			name: "unknown-distro",
			files: map[string]string{
				"/etc/os-release": "ID=nixos\nVERSION_ID=\"24.05\"\n",
			},
			wantErrFragment: "no OSV ecosystem is known",
		},
		{
			// A scratch image with a dpkg database copied in is a real thing;
			// the inventory is still worth printing.
			name:    "no-os-release",
			files:   map[string]string{"/etc/hostname": "host\n"},
			wantNil: true,
		},
		{
			name:    "os-release-without-id",
			files:   map[string]string{"/etc/os-release": "PRETTY_NAME=\"Mystery\"\n"},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readOSInfo(tree(t, tt.files), discard)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("got %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("got nil")
			}
			if got.Ecosystem != tt.wantEcosystem {
				t.Errorf("Ecosystem = %q, want %q", got.Ecosystem, tt.wantEcosystem)
			}
			if tt.wantErrFragment == "" {
				if got.EcosystemError != "" {
					t.Errorf("unexpected EcosystemError: %s", got.EcosystemError)
				}
			} else if !strings.Contains(got.EcosystemError, tt.wantErrFragment) {
				t.Errorf("EcosystemError = %q, want it to mention %q", got.EcosystemError, tt.wantErrFragment)
			}
		})
	}
}

func TestInventoryPackageCount(t *testing.T) {
	inv := &InventoryResult{Databases: []pkgdb.Result{
		{Format: pkgdb.FormatDeb, Packages: make([]pkgdb.Package, 88)},
		{Format: pkgdb.FormatAPK, Packages: make([]pkgdb.Package, 15)},
	}}
	if got := inv.Packages(); got != 103 {
		t.Errorf("Packages() = %d, want 103", got)
	}
	if got := (&InventoryResult{}).Packages(); got != 0 {
		t.Errorf("Packages() on an empty inventory = %d", got)
	}
}

func TestInventoryCountsLanguagesSeparately(t *testing.T) {
	// The two counts must not be summed: a python3-yaml deb and the pyyaml
	// distribution it installs are the same files under two names, so a single
	// total would double-count them.
	inv := &InventoryResult{
		Databases: []pkgdb.Result{{Format: pkgdb.FormatDeb, Packages: make([]pkgdb.Package, 88)}},
		Languages: []langdb.Result{
			{Format: langdb.FormatPyPI, Packages: make([]langdb.Package, 12)},
			{Format: langdb.FormatNPM, Packages: make([]langdb.Package, 900)},
		},
	}
	if got := inv.Packages(); got != 88 {
		t.Errorf("Packages() = %d, want 88 (OS packages only)", got)
	}
	if got := inv.LanguagePackages(); got != 912 {
		t.Errorf("LanguagePackages() = %d, want 912", got)
	}
	if got := (&InventoryResult{}).LanguagePackages(); got != 0 {
		t.Errorf("LanguagePackages() on an empty inventory = %d", got)
	}
}

func TestInventoryRejectsRepoMode(t *testing.T) {
	_, err := Inventory(context.Background(), Options{Repo: "github.com/x/y"})
	if err == nil {
		t.Fatal("repo mode was accepted")
	}
	if !strings.Contains(err.Error(), "--repo") {
		t.Errorf("unhelpful error: %v", err)
	}
	if _, err := Inventory(context.Background(), Options{}); err == nil {
		t.Fatal("an inventory with no target was accepted")
	}
}
