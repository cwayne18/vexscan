package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeRepo(t *testing.T) {
	cases := map[string]string{
		"github.com/rancher/rancher":         "https://github.com/rancher/rancher.git",
		"https://github.com/rancher/rancher": "https://github.com/rancher/rancher.git",
		"http://github.com/x/y/":             "https://github.com/x/y.git",
		"rancher/rancher":                    "https://github.com/rancher/rancher.git",
		"gitlab.com/foo/bar":                 "https://gitlab.com/foo/bar.git",
		"git@github.com:foo/bar.git":         "git@github.com:foo/bar.git",
	}
	for in, want := range cases {
		if got := normalizeRepo(in); got != want {
			t.Errorf("normalizeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePurl(t *testing.T) {
	products := []product{
		{Subcomponents: []struct {
			ID string `json:"@id"`
		}{
			{ID: "pkg:golang/golang.org%2Fx%2Fnet@v0.7.0"},
		}},
	}
	mod, ver := parsePurl(products)
	if mod != "golang.org/x/net" {
		t.Errorf("module = %q, want golang.org/x/net", mod)
	}
	if ver != "v0.7.0" {
		t.Errorf("version = %q, want v0.7.0", ver)
	}
}

func TestParsePurlStdlib(t *testing.T) {
	products := []product{
		{Subcomponents: []struct {
			ID string `json:"@id"`
		}{
			{ID: "pkg:golang/stdlib@go1.21.5"},
		}},
	}
	mod, ver := parsePurl(products)
	if mod != "stdlib" || ver != "go1.21.5" {
		t.Errorf("got %q@%q, want stdlib@go1.21.5", mod, ver)
	}
}

func TestSplitPurl(t *testing.T) {
	tests := []struct {
		id          string
		name        string
		version     string
		ok          bool
		description string
	}{
		{"pkg:golang/golang.org%2Fx%2Fnet@v0.7.0", "golang.org/x/net", "v0.7.0", true,
			"the Go form govulncheck emits"},
		{"pkg:golang/stdlib@go1.21.5", "stdlib", "go1.21.5", true,
			"stdlib has no namespace"},
		{"pkg:golang/golang.org%2Fx%2Fnet", "golang.org/x/net", "", true,
			"a purl need not carry a version"},

		// Any purl type parses. Refusing an unanticipated type would drop the
		// statement instead of reporting it -- the wrong failure direction.
		{"pkg:deb/debian/openssl@3.0.11-1", "debian/openssl", "3.0.11-1", true,
			"a deb purl"},
		{"pkg:pypi/django@4.2.1", "django", "4.2.1", true, "a PyPI purl"},
		{"pkg:npm/%40angular/core@13.0.0", "@angular/core", "13.0.0", true,
			"an npm scoped package"},

		{"pkg:deb/debian/openssl@3.0.11-1?arch=amd64", "debian/openssl", "3.0.11-1", true,
			"qualifiers are trimmed"},
		{"pkg:golang/example.com%2Fm@v1.0.0#sub/dir", "example.com/m", "v1.0.0", true,
			"a subpath is trimmed"},
		// "@" inside a qualifier value must not be read as the version separator.
		{"pkg:deb/debian/x@1.0?note=a@b", "debian/x", "1.0", true,
			"a qualifier containing @ does not confuse the version split"},

		{"golang.org/x/net@v0.7.0", "", "", false, "not a purl at all"},
		{"pkg:golang", "", "", false, "a type with no name"},
		{"pkg:golang/", "", "", false, "an empty name"},
		{"", "", "", false, "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			name, version, ok := splitPurl(tt.id)
			if ok != tt.ok || name != tt.name || version != tt.version {
				t.Errorf("splitPurl(%q) = %q, %q, %v; want %q, %q, %v",
					tt.id, name, version, ok, tt.name, tt.version, tt.ok)
			}
		})
	}
}

// parsePurl skips subcomponents it cannot read and keeps looking, so one
// unparseable @id does not lose the statement.
func TestParsePurlSkipsUnparseableSubcomponents(t *testing.T) {
	products := []product{
		{Subcomponents: []struct {
			ID string `json:"@id"`
		}{
			{ID: "not-a-purl"},
			{ID: "pkg:golang/golang.org%2Fx%2Fnet@v0.7.0"},
		}},
	}
	mod, ver := parsePurl(products)
	if mod != "golang.org/x/net" || ver != "v0.7.0" {
		t.Errorf("got %q@%q", mod, ver)
	}
}

func TestDiagnoseNoOutputOOM(t *testing.T) {
	stderr := "go: downloading golang.org/x/vuln v1.6.0\nsignal: killed"
	err := diagnoseNoOutput(context.Background(), nil, stderr)
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	if !strings.Contains(got, "out of memory") || !strings.Contains(got, "--repo-path") {
		t.Fatalf("unhelpful OOM error: %q", got)
	}
}

func TestDiagnoseNoOutputTimeout(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	err := diagnoseNoOutput(ctx, ctx.Err(), "")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestDiagnoseNoOutputGeneric(t *testing.T) {
	err := diagnoseNoOutput(context.Background(), nil, "some other failure")
	if err == nil || !strings.Contains(err.Error(), "some other failure") {
		t.Fatalf("expected passthrough error, got %v", err)
	}
}

func TestNormalizeGoVersion(t *testing.T) {
	cases := map[string]string{
		"1.24.0":   "1.24.0",
		"go1.24.0": "1.24.0",
		"v1.24.0":  "1.24.0",
		" go1.25 ": "1.25",
	}
	for in, want := range cases {
		if got := normalizeGoVersion(in); got != want {
			t.Errorf("normalizeGoVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckoutLocal(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pkg", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkg", "sub", "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, subPath, wantSubdir, wantDir string
	}{
		{"top level", "", ".", root},
		{"explicit dot", ".", ".", root},
		{"subdirectory", "pkg/sub", "pkg/sub", filepath.Join(root, "pkg", "sub")},
		{"leading slash is stripped", "/pkg/sub", "pkg/sub", filepath.Join(root, "pkg", "sub")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, cleanup, err := Checkout(context.Background(), root, "", tt.subPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			if src.Dir != tt.wantDir {
				t.Errorf("Dir = %q, want %q", src.Dir, tt.wantDir)
			}
			if src.Subdir != tt.wantSubdir {
				t.Errorf("Subdir = %q, want %q", src.Subdir, tt.wantSubdir)
			}
			// FS is rooted at the checkout, not the module subdirectory, so a
			// plugin can look at repo-level files regardless of --repo-path.
			if src.FS.Root() != root {
				t.Errorf("FS.Root() = %q, want %q", src.FS.Root(), root)
			}
		})
	}
}

// TestCheckoutLocalCleanupDoesNotDelete is the property that keeps `--repo .`
// from destroying the user's working tree: nothing Checkout did not create may
// be removed.
func TestCheckoutLocalCleanupDoesNotDelete(t *testing.T) {
	root := t.TempDir()
	canary := filepath.Join(root, "keep")
	if err := os.WriteFile(canary, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := Checkout(context.Background(), "file://"+root, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()

	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("cleanup deleted a local checkout: %v", err)
	}
}
