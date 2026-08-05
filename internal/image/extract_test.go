package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// entry is one synthetic tar member.
type entry struct {
	name     string
	typeflag byte
	mode     int64
	body     string
	linkname string
}

func reg(name, body string) entry {
	return entry{name: name, typeflag: tar.TypeReg, mode: 0o644, body: body}
}
func dir(name string) entry {
	return entry{name: name, typeflag: tar.TypeDir, mode: 0o755}
}
func sym(name, linkname string) entry {
	return entry{name: name, typeflag: tar.TypeSymlink, mode: 0o777, linkname: linkname}
}
func hard(name, linkname string) entry {
	return entry{name: name, typeflag: tar.TypeLink, mode: 0o644, linkname: linkname}
}

// writeLayer builds a gzipped tar layer on disk and returns its path.
func writeLayer(t *testing.T, entries []entry) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Linkname: e.linkname,
			Size:     int64(len(e.body)),
		}
		if e.typeflag != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(t.TempDir(), "layer.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// extractLayers applies each layer in order into a fresh dest and returns it.
func extractLayers(t *testing.T, layers ...[]entry) string {
	t.Helper()
	dest := t.TempDir()
	// A budget far larger than any test layer, so ordinary tests exercise the
	// happy path unaffected by the size cap.
	budget := int64(maxImageBytes)
	for i, l := range layers {
		if err := untar(writeLayer(t, l), dest, &budget); err != nil {
			t.Fatalf("layer %d: %v", i, err)
		}
	}
	return dest
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("expected %s to be absent, got err=%v", path, err)
	}
}

func TestUntarLaterLayerOverwrites(t *testing.T) {
	dest := extractLayers(t,
		[]entry{dir("usr/bin/"), reg("usr/bin/app", "v1")},
		[]entry{reg("usr/bin/app", "v2")},
	)
	if got := mustReadFile(t, filepath.Join(dest, "usr/bin/app")); got != "v2" {
		t.Errorf("app = %q, want %q", got, "v2")
	}
}

func TestUntarSymlinkIsRecreated(t *testing.T) {
	// The real case this exists for: soname resolution needs libssl.so.3 to
	// still be a link naming libssl.so.3.0.11.
	dest := extractLayers(t, []entry{
		dir("usr/lib/"),
		reg("usr/lib/libssl.so.3.0.11", "ELF"),
		sym("usr/lib/libssl.so.3", "libssl.so.3.0.11"),
	})

	link := filepath.Join(dest, "usr/lib/libssl.so.3")
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("libssl.so.3 should be a symlink, not a regular file")
	}
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != "libssl.so.3.0.11" {
		t.Errorf("readlink = %q, want %q", got, "libssl.so.3.0.11")
	}
}

func TestUntarHardlinkIsMaterialized(t *testing.T) {
	// busybox-style images ship dozens of applets as hardlinks to one binary.
	// Dropping them made those binaries invisible to the Go-binary scan.
	dest := extractLayers(t, []entry{
		dir("bin/"),
		reg("bin/busybox", "ELF-BUSYBOX"),
		hard("bin/ls", "bin/busybox"),
		hard("bin/sh", "bin/busybox"),
	})

	for _, name := range []string{"bin/ls", "bin/sh"} {
		p := filepath.Join(dest, name)
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("lstat %s: %v", name, err)
		}
		if !fi.Mode().IsRegular() {
			t.Errorf("%s should be a regular file, got mode %v", name, fi.Mode())
		}
		if got := mustReadFile(t, p); got != "ELF-BUSYBOX" {
			t.Errorf("%s = %q, want the busybox contents", name, got)
		}
	}
}

func TestUntarHardlinkToMissingTargetIsSkipped(t *testing.T) {
	dest := extractLayers(t, []entry{
		dir("bin/"),
		hard("bin/ls", "bin/nonexistent"),
	})
	// Must not invent an empty file: a zero-byte /bin/ls would be scanned and
	// reported as a non-Go binary rather than correctly not existing.
	assertAbsent(t, filepath.Join(dest, "bin/ls"))
}

func TestUntarWhiteoutDeletesLowerLayerFile(t *testing.T) {
	dest := extractLayers(t,
		[]entry{dir("usr/bin/"), reg("usr/bin/app", "v1"), reg("usr/bin/keep", "keep")},
		[]entry{reg("usr/bin/.wh.app", "")},
	)
	// Before this fix the whiteout was skipped, so a package deleted in a
	// later layer still appeared installed.
	assertAbsent(t, filepath.Join(dest, "usr/bin/app"))
	if got := mustReadFile(t, filepath.Join(dest, "usr/bin/keep")); got != "keep" {
		t.Errorf("sibling was collateral damage: keep = %q", got)
	}
}

func TestUntarWhiteoutDeletesLowerLayerDirectory(t *testing.T) {
	dest := extractLayers(t,
		[]entry{dir("opt/"), dir("opt/tool/"), reg("opt/tool/bin", "ELF")},
		[]entry{reg("opt/.wh.tool", "")},
	)
	assertAbsent(t, filepath.Join(dest, "opt/tool"))
}

func TestUntarOpaqueWhiteoutClearsDirectory(t *testing.T) {
	dest := extractLayers(t,
		[]entry{dir("var/cache/"), reg("var/cache/a", "a"), reg("var/cache/b", "b")},
		[]entry{reg("var/cache/.wh..wh..opq", ""), reg("var/cache/c", "c")},
	)
	assertAbsent(t, filepath.Join(dest, "var/cache/a"))
	assertAbsent(t, filepath.Join(dest, "var/cache/b"))
	// Content added by the same layer, after the marker, survives.
	if got := mustReadFile(t, filepath.Join(dest, "var/cache/c")); got != "c" {
		t.Errorf("c = %q, want %q", got, "c")
	}
}

func TestUntarSymlinkedDirectoryIsTraversed(t *testing.T) {
	// The usr-merge layout every modern distro ships: /lib is a link to
	// /usr/lib, and later layers write to /lib/... expecting to land in
	// /usr/lib.
	dest := extractLayers(t,
		[]entry{
			dir("usr/"), dir("usr/lib/"),
			sym("lib", "usr/lib"),
		},
		[]entry{reg("lib/libc.so.6", "ELF-LIBC")},
	)

	if got := mustReadFile(t, filepath.Join(dest, "usr/lib/libc.so.6")); got != "ELF-LIBC" {
		t.Errorf("write through /lib did not land in /usr/lib: %q", got)
	}
	fi, err := os.Lstat(filepath.Join(dest, "lib"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Error("/lib should still be a symlink after the write")
	}
}

func TestUntarFileReplacesSymlink(t *testing.T) {
	// Overlay semantics: writing a regular file over a symlink replaces the
	// link, it does not write through it.
	dest := extractLayers(t,
		[]entry{dir("etc/"), reg("etc/real", "original"), sym("etc/link", "real")},
		[]entry{reg("etc/link", "replaced")},
	)

	fi, err := os.Lstat(filepath.Join(dest, "etc/link"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("etc/link should have been replaced by a regular file")
	}
	if got := mustReadFile(t, filepath.Join(dest, "etc/real")); got != "original" {
		t.Errorf("etc/real was written through the link: %q", got)
	}
}

func TestUntarRejectsPathTraversal(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}

	dest := extractLayers(t, []entry{
		reg("../../../../../../../../"+outside, "pwned"),
		reg("../escape", "pwned"),
	})

	if got := mustReadFile(t, outside); got != "untouched" {
		t.Fatalf("path traversal wrote outside the root: %q", got)
	}
	// ".." is clamped at the root rather than dropped, so the entry lands
	// inside dest.
	if _, err := os.Lstat(filepath.Join(dest, "escape")); err != nil {
		t.Errorf("clamped entry should exist inside dest: %v", err)
	}
}

func TestUntarSymlinkEscapeIsContained(t *testing.T) {
	// The classic attack: layer 1 links a directory to somewhere on the host,
	// layer 2 writes through it.
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "passwd")
	if err := os.WriteFile(victim, []byte("root:x:0:0"), 0o600); err != nil {
		t.Fatal(err)
	}

	dest := extractLayers(t,
		[]entry{sym("evil", victimDir)},
		[]entry{reg("evil/passwd", "attacker:x:0:0")},
	)

	if got := mustReadFile(t, victim); got != "root:x:0:0" {
		t.Fatalf("wrote through an escaping symlink: %q", got)
	}
	// The absolute link target is re-rooted, so the write lands inside dest
	// at the same path the container would have seen.
	inside := filepath.Join(dest, victimDir, "passwd")
	if got := mustReadFile(t, inside); got != "attacker:x:0:0" {
		t.Errorf("re-rooted write missing at %s: %q", inside, got)
	}
}

func TestUntarSymlinkLoopTerminates(t *testing.T) {
	// Must not hang. Either entry is fine as long as extraction returns.
	dest := extractLayers(t,
		[]entry{sym("a", "b"), sym("b", "a")},
		[]entry{reg("a/file", "x")},
	)
	_ = dest
}

func TestUntarDirectoryReplacesFile(t *testing.T) {
	dest := extractLayers(t,
		[]entry{reg("thing", "was a file")},
		[]entry{dir("thing/"), reg("thing/inner", "now a dir")},
	)
	fi, err := os.Lstat(filepath.Join(dest, "thing"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatal("thing should have become a directory")
	}
	if got := mustReadFile(t, filepath.Join(dest, "thing/inner")); got != "now a dir" {
		t.Errorf("inner = %q", got)
	}
}

func TestUntarReadOnlyFileCanBeReplaced(t *testing.T) {
	dest := extractLayers(t,
		[]entry{{name: "ro", typeflag: tar.TypeReg, mode: 0o444, body: "v1"}},
		[]entry{reg("ro", "v2")},
	)
	if got := mustReadFile(t, filepath.Join(dest, "ro")); got != "v2" {
		t.Errorf("read-only file blocked replacement: %q", got)
	}
}

// writeRawTar builds an uncompressed tar of entries and returns its bytes, so a
// test can truncate the stream at a byte offset a tar.Writer would never let it
// produce.
func writeRawTar(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Size: int64(len(e.body))}
		if e.typeflag != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUntarTruncatedStreamIsReported(t *testing.T) {
	// A corrupt or truncated layer must fail the run, not be treated like clean
	// trailing padding: everything past the break is a real package, and
	// dropping it silently would under-report what the image ships.
	raw := writeRawTar(t, []entry{
		reg("usr/bin/one", "first"),
		reg("usr/bin/two", "second"),
	})
	// Cut inside the second entry so the reader errors when it advances to it,
	// after the first entry has already been consumed.
	truncated := raw[:len(raw)-600]
	blob := filepath.Join(t.TempDir(), "layer.tar")
	if err := os.WriteFile(blob, truncated, 0o600); err != nil {
		t.Fatal(err)
	}

	budget := int64(maxImageBytes)
	err := untar(blob, t.TempDir(), &budget)
	if err == nil {
		t.Fatal("truncated tar was accepted silently; a real read error must be surfaced")
	}
	// How much was read before the break is the difference between "the pull is
	// broken" and "the last layer was truncated", and it is the operator's next
	// move, so the error has to carry it. Two, not one: the count is of headers
	// successfully parsed, and the second entry's header is intact -- the cut is
	// in its payload, so the reader only fails advancing past it.
	if !strings.Contains(err.Error(), "after 2 entries") {
		t.Errorf("err = %v, want the count of entries read before the failure", err)
	}
}

func TestUntarBudgetExceededIsReported(t *testing.T) {
	// A decompression bomb -- or any file bigger than the remaining budget --
	// must stop extraction with an error rather than write a truncated file and
	// carry on, which would under-report the file's contents.
	dest := t.TempDir()
	budget := int64(8)
	err := untar(writeLayer(t, []entry{reg("big", "way more than eight bytes")}), dest, &budget)
	if !errors.Is(err, errImageTooLarge) {
		t.Fatalf("err = %v, want errImageTooLarge", err)
	}
}

func TestUntarBudgetIsCumulativeAcrossLayers(t *testing.T) {
	// The budget is shared across layers, so a bomb split into many small files
	// over several layers is caught just like one fat file.
	dest := t.TempDir()
	budget := int64(20)
	l1 := writeLayer(t, []entry{reg("a", "0123456789")}) // 10 bytes, leaves 10
	l2 := writeLayer(t, []entry{reg("b", "0123456789")}) // 10 bytes, leaves 0
	l3 := writeLayer(t, []entry{reg("c", "x")})          // 1 byte, overruns
	if err := untar(l1, dest, &budget); err != nil {
		t.Fatalf("layer 1: %v", err)
	}
	if err := untar(l2, dest, &budget); err != nil {
		t.Fatalf("layer 2: %v", err)
	}
	if err := untar(l3, dest, &budget); !errors.Is(err, errImageTooLarge) {
		t.Fatalf("layer 3 err = %v, want errImageTooLarge", err)
	}
}

func TestCopyFileIsChargedAgainstBudget(t *testing.T) {
	// The hardlink copy fallback duplicates a file's bytes, so it must draw on
	// the same image budget as writeFile. Otherwise a layer with one large file
	// plus many hardlink entries to it could duplicate those bytes unaccounted
	// whenever os.Link fails and every entry copies instead.
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("overrun is reported", func(t *testing.T) {
		budget := int64(4)
		dst := filepath.Join(t.TempDir(), "dst")
		if err := copyFile(src, dst, &budget); !errors.Is(err, errImageTooLarge) {
			t.Fatalf("err = %v, want errImageTooLarge", err)
		}
	})

	t.Run("within budget decrements it", func(t *testing.T) {
		budget := int64(100)
		dst := filepath.Join(t.TempDir(), "dst")
		if err := copyFile(src, dst, &budget); err != nil {
			t.Fatalf("copyFile: %v", err)
		}
		if budget != 90 {
			t.Errorf("budget = %d, want 90 (100 - 10 bytes copied)", budget)
		}
		if got := mustReadFile(t, dst); got != "0123456789" {
			t.Errorf("dst = %q, want the full source contents", got)
		}
	})
}

func TestReadConfig(t *testing.T) {
	t.Run("parses entrypoint cmd and env", func(t *testing.T) {
		blob := filepath.Join(t.TempDir(), "config")
		body := `{"architecture":"amd64","config":{
			"Env":["PATH=/usr/bin:/bin","TZ=UTC"],
			"Entrypoint":["/usr/bin/app"],
			"Cmd":["--serve"],
			"WorkingDir":"/srv",
			"User":"nobody"}}`
		if err := os.WriteFile(blob, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		got := readConfig(blob)
		if len(got.Entrypoint) != 1 || got.Entrypoint[0] != "/usr/bin/app" {
			t.Errorf("Entrypoint = %v", got.Entrypoint)
		}
		if len(got.Cmd) != 1 || got.Cmd[0] != "--serve" {
			t.Errorf("Cmd = %v", got.Cmd)
		}
		if len(got.Env) != 2 || got.Env[0] != "PATH=/usr/bin:/bin" {
			t.Errorf("Env = %v", got.Env)
		}
		if got.WorkingDir != "/srv" || got.User != "nobody" {
			t.Errorf("WorkingDir=%q User=%q", got.WorkingDir, got.User)
		}
	})

	// A malformed or missing config must degrade to "no roots known" rather
	// than failing the scan.
	t.Run("missing blob yields empty config", func(t *testing.T) {
		if got := readConfig(filepath.Join(t.TempDir(), "nope")); len(got.Entrypoint) != 0 {
			t.Errorf("got %+v, want empty", got)
		}
	})
	t.Run("malformed blob yields empty config", func(t *testing.T) {
		blob := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(blob, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readConfig(blob); len(got.Entrypoint) != 0 {
			t.Errorf("got %+v, want empty", got)
		}
	})
	t.Run("empty digest yields empty config", func(t *testing.T) {
		if got := readConfig(""); len(got.Cmd) != 0 {
			t.Errorf("got %+v, want empty", got)
		}
	})
}

func TestBlobPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"sha256:abc123", filepath.Join("/raw", "abc123")},
		{"sha512:def", filepath.Join("/raw", "def")},
		{"nocolon", ""},
		{"sha256:", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := blobPath("/raw", tt.in); got != tt.want {
			t.Errorf("blobPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
