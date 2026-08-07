package analyze

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// writeTree materializes files under a new temp directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
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
	return root
}

func TestCheckTarget(t *testing.T) {
	tests := []struct {
		name        string
		opts        Options
		wantErr     bool
		errFragment string
	}{
		{name: "image alone", opts: Options{Image: "debian:12"}},
		{name: "rootfs alone", opts: Options{RootFS: "/mnt/x"}},
		{name: "repo alone", opts: Options{Repo: "github.com/x/y"}},
		{name: "nothing", opts: Options{}, wantErr: true, errFragment: "is required"},
		{
			name: "image and rootfs", wantErr: true, errFragment: "--image, --rootfs",
			opts: Options{Image: "debian:12", RootFS: "/mnt/x"},
		},
		{
			name: "rootfs and repo", wantErr: true, errFragment: "--rootfs, --repo",
			opts: Options{RootFS: "/mnt/x", Repo: "github.com/x/y"},
		},
		{
			name: "all three", wantErr: true, errFragment: "--image, --rootfs, --repo",
			opts: Options{Image: "debian:12", RootFS: "/mnt/x", Repo: "github.com/x/y"},
		},
		{name: "sbom alone", opts: Options{SBOM: "bom.json"}},
		{
			name: "sbom and image", wantErr: true, errFragment: "--image, --sbom",
			opts: Options{Image: "debian:12", SBOM: "bom.json"},
		},
		{
			name: "sbom and rpm", wantErr: true, errFragment: "--rpm, --sbom",
			opts: Options{RPM: []string{"a.rpm"}, SBOM: "bom.json"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.checkTarget()
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkTarget() = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.errFragment) {
				t.Errorf("error %q does not mention %q", err, tc.errFragment)
			}
		})
	}
}

func TestOpenRootFS(t *testing.T) {
	root := writeTree(t, map[string]string{"/etc/os-release": "ID=debian\n"})

	img, err := openRootFS(root)
	if err != nil {
		t.Fatalf("openRootFS: %v", err)
	}
	if img.Ref != root {
		t.Errorf("Ref = %q, want the absolute directory %q", img.Ref, root)
	}
	if img.FS == nil {
		t.Fatal("no filesystem")
	}
	if got, err := img.FS.ReadFile("/etc/os-release"); err != nil || string(got) != "ID=debian\n" {
		t.Errorf("the tree does not read back: %q, %v", got, err)
	}
	// The absence of a config is the defining property of this mode, and the
	// plugins branch on it, so it is pinned rather than assumed.
	if img.Config.Entrypoint != nil || img.Config.Cmd != nil {
		t.Errorf("a rootfs invented an entrypoint: %+v", img.Config)
	}
	if img.OS != "" || img.Arch != "" {
		t.Errorf("a rootfs invented a platform: %q/%q", img.OS, img.Arch)
	}
}

func TestOpenRootFSResolvesARelativePath(t *testing.T) {
	root := writeTree(t, map[string]string{"/usr/bin/app": "x"})
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, root)
	if err != nil {
		t.Skipf("no relative path from %s to %s", wd, root)
	}

	img, err := openRootFS(rel)
	if err != nil {
		t.Fatalf("openRootFS(%q): %v", rel, err)
	}
	// The report names the tree that was scanned, and "../../tmp/x" names it
	// only for as long as the reader stays in the directory it was run from.
	if !filepath.IsAbs(img.Ref) {
		t.Errorf("Ref = %q, want an absolute path", img.Ref)
	}
}

func TestOpenRootFSRejectsWhatIsNotADirectory(t *testing.T) {
	root := writeTree(t, map[string]string{"/file": "x"})

	// Both of these would otherwise scan perfectly cleanly: every walk of a
	// non-directory finds nothing, every plugin reports it does not apply, and
	// the run ends with no findings.
	if _, err := openRootFS(filepath.Join(root, "file")); err == nil {
		t.Error("a regular file was accepted as a rootfs")
	}
	if _, err := openRootFS(filepath.Join(root, "nope")); err == nil {
		t.Error("a path that does not exist was accepted as a rootfs")
	}
}

func TestInventoryOfARootFSLeavesItOnDisk(t *testing.T) {
	root := writeTree(t, map[string]string{
		"/etc/os-release":          "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n",
		"/var/lib/dpkg/status":     "Package: openssl\nVersion: 3.0.11-1\nArchitecture: amd64\n\n",
		"/usr/bin/keepme":          "not a binary",
		"/usr/lib/os-release-copy": "x",
	})

	invs, err := Inventory(context.Background(), Options{RootFS: root, Logf: discard})
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	inv := invs[0]
	if inv.Mode != "rootfs" {
		t.Errorf("Mode = %q, want rootfs", inv.Mode)
	}
	if inv.Target != root {
		t.Errorf("Target = %q, want %q", inv.Target, root)
	}
	if inv.OS == nil || inv.OS.Ecosystem != "Debian:12" {
		t.Errorf("os = %+v, want the Debian:12 ecosystem", inv.OS)
	}
	if got := inv.Packages(); got != 1 {
		t.Errorf("Packages() = %d, want 1", got)
	}
	if inv.Unreadable != nil {
		t.Errorf("a readable tree reported gaps: %+v", inv.Unreadable)
	}

	// The point of the whole test. Image mode extracts into a temp directory
	// and deletes it afterwards; carrying that line into rootfs mode would
	// delete the tree the user asked about.
	if _, err := os.Stat(filepath.Join(root, "usr/bin/keepme")); err != nil {
		t.Fatalf("the scan removed the rootfs: %v", err)
	}
}

func TestInventoryReportsWhatItCouldNotEnter(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything, so there is no gap to report")
	}
	root := writeTree(t, map[string]string{
		"/etc/os-release":                        "ID=debian\nVERSION_ID=\"12\"\n",
		"/var/lib/dpkg/status":                   "Package: openssl\nVersion: 3.0.11-1\nArchitecture: amd64\n\n",
		"/opt/private/lib/python3/site-packages": "x",
	})
	closed := filepath.Join(root, "opt", "private")
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })

	invs, err := Inventory(context.Background(), Options{RootFS: root, Logf: discard})
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	inv := invs[0]
	// Not fatal: the databases that did read are still worth printing. But the
	// document has to say it is missing an unknown number of entries, because
	// a site-packages directory nobody listed reports no packages, exactly as
	// an empty one does.
	if inv.Unreadable == nil || !inv.Unreadable.Any() {
		t.Fatal("an unreadable subtree was not reported")
	}
	if got := inv.Unreadable.Paths; len(got) != 1 || got[0] != "/opt/private" {
		t.Errorf("Paths = %v, want [/opt/private]", got)
	}
	if got := inv.Packages(); got != 1 {
		t.Errorf("Packages() = %d; the readable database should still be listed", got)
	}
}

func TestFailedAccountsForWhatCouldNotBeRead(t *testing.T) {
	clean := &Result{}
	if clean.Failed() {
		t.Error("an empty result reported failure")
	}

	// A scan with no findings and no plugin errors, that could not enter one
	// directory, is not a clean scan: nothing looked inside, so nothing could
	// have been found there.
	holed := &Result{Unreadable: &target.Unreadable{Count: 1, Paths: []string{"/opt/vendor"}}}
	if !holed.Failed() {
		t.Error("a scan that could not read part of the tree reported success")
	}
}
