package haul

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// writeArchive tars dir into path, zstd-compressed when compress is set. This
// is what `hauler store save` produces: every entry mapped to its base name, so
// the layout lands at the archive root.
func writeArchive(t *testing.T, dir, path string, compress bool) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var w io.Writer = f
	if compress {
		enc, err := zstd.NewWriter(f)
		if err != nil {
			t.Fatal(err)
		}
		defer enc.Close()
		w = enc
	}
	tw := tar.NewWriter(w)
	defer tw.Close()

	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// tarball builds a tar in memory from a list of entries, so a test can write
// the headers a well-behaved archiver never would.
func tarball(t *testing.T, write func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write(tw)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func file(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tw, content); err != nil {
		t.Fatal(err)
	}
}

func writeBytes(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func compressed(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zstd is sniffed by magic, not by file name: `hauler store save` writes
// .tar.zst, but the file that reaches a scanner has been through a transfer
// medium, a ticketing system and someone's Downloads folder.
func TestCompressionIsSniffedNotGuessedFromTheName(t *testing.T) {
	raw := tarball(t, func(tw *tar.Writer) { file(t, tw, "oci-layout", "{}") })

	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"haul.tar", raw},                    // zstd extension absent, plain tar
		{"haul.tar.zst", compressed(t, raw)}, // the usual case
		{"haul.tar", compressed(t, raw)},     // compressed, misnamed
		{"haul.tar.zst", raw},                // plain, misnamed
		{"haul", compressed(t, raw)},         // no extension at all
	} {
		dir := t.TempDir()
		src := filepath.Join(dir, tt.name)
		writeBytes(t, src, tt.data)
		dest := filepath.Join(dir, "out")
		if err := os.MkdirAll(dest, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := unpack(context.Background(), src, dest); err != nil {
			t.Errorf("%s (%d bytes): %v", tt.name, len(tt.data), err)
			continue
		}
		if _, err := os.Stat(filepath.Join(dest, "oci-layout")); err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}

// `tar -cf haul.tar .` prefixes every entry with "./" and writes the root
// itself as an entry. Refusing that would refuse most hand-rolled hauls.
func TestUnpackAcceptsADotSlashArchive(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "haul.tar")
	writeBytes(t, src, tarball(t, func(tw *tar.Writer) {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "./", Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
		file(t, tw, "./oci-layout", "{}")
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "./blobs/sha256/", Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
		file(t, tw, "./blobs/sha256/cafe", "layer")
	}))
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := unpack(context.Background(), src, dest); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	for _, name := range []string{"oci-layout", "blobs/sha256/cafe"} {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(name))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A tar entry names its own path, and an archive off a transfer medium is not
// a trusted document.
func TestUnpackRefusesToWriteOutsideTheDestination(t *testing.T) {
	for _, name := range []string{
		"../escaped",
		"a/../../escaped",
		"/etc/escaped",
		`..\escaped`,
		`a\..\..\escaped`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "haul.tar")
			writeBytes(t, src, tarball(t, func(tw *tar.Writer) { file(t, tw, name, "pwned") }))
			dest := filepath.Join(dir, "out")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}

			_, err := unpack(context.Background(), src, dest)
			if err == nil {
				t.Fatalf("unpack accepted an entry named %q", name)
			}
			if _, err := os.Stat(filepath.Join(dir, "escaped")); err == nil {
				t.Fatal("unpack wrote outside the destination")
			}
		})
	}
}

func TestSafeJoin(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	ok := []struct{ name, want string }{
		{"index.json", filepath.Join(root, "index.json")},
		{"blobs/sha256/cafe", filepath.Join(root, "blobs", "sha256", "cafe")},
		{"./blobs/../index.json", filepath.Join(root, "index.json")},
		{"a/b/../c", filepath.Join(root, "a", "c")},
		// `tar -cf haul.tar .` writes the archive root as its first entry.
		{".", root},
		{"./", root},
	}
	for _, tt := range ok {
		got, err := safeJoin(root, tt.name)
		if err != nil {
			t.Errorf("safeJoin(%q): %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("safeJoin(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
	for _, name := range []string{"", "..", "../x", "/abs", `back\slash`, "a/../../x"} {
		if got, err := safeJoin(root, name); err == nil {
			t.Errorf("safeJoin(%q) = %q, want an error", name, got)
		}
	}
}

// A symlink is how an archive writes outside its destination even when every
// header name is clean: extract "link -> /etc" and then "link/passwd". They are
// counted rather than recreated, because nothing in a layout needs one -- the
// index decides what is in a haul, and it addresses blobs by digest.
func TestNonRegularEntriesAreCountedNotRecreated(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "haul.tar")
	writeBytes(t, src, tarball(t, func(tw *tar.Writer) {
		file(t, tw, "index.json", "{}")
		for _, hdr := range []*tar.Header{
			{Typeflag: tar.TypeSymlink, Name: "escape", Linkname: "/etc", Mode: 0o777},
			{Typeflag: tar.TypeLink, Name: "hard", Linkname: "index.json", Mode: 0o644},
			{Typeflag: tar.TypeFifo, Name: "pipe", Mode: 0o644},
		} {
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
		}
	}))
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}

	skipped, err := unpack(context.Background(), src, dest)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3", skipped)
	}
	for _, name := range []string{"escape", "hard", "pipe"} {
		if _, err := os.Lstat(filepath.Join(dest, name)); err == nil {
			t.Errorf("unpack recreated %q", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "index.json")); err != nil {
		t.Errorf("the regular file was not extracted: %v", err)
	}
}

// A zstd stream is compressed, so its unpacked size is not knowable from the
// file on disk or from a header that may claim anything. The cap is on bytes
// actually written, and it has to stop the write rather than discover the
// problem once the disk is gone -- so it is tested on the writer, at a budget
// a test can reach, rather than on the 128GiB constant.
func TestWriteFileStopsAtTheSizeBudget(t *testing.T) {
	dir := t.TempDir()

	// The budget is the haul's, not the entry's: three entries of four bytes
	// spend it between them, and the one that runs it out is the one refused.
	remaining := int64(10)
	for i, want := range []error{nil, nil, errHaulTooLarge} {
		path := filepath.Join(dir, "blob")
		err := writeFile(strings.NewReader("abcd"), path, &remaining)
		if !errors.Is(err, want) {
			t.Fatalf("entry %d: err = %v, want %v", i, err, want)
		}
	}
	if remaining != 2 {
		t.Errorf("remaining = %d, want 2: the refused write was still charged", remaining)
	}

	// Exactly at the budget is allowed; one past it is not.
	remaining = 4
	if err := writeFile(strings.NewReader("abcd"), filepath.Join(dir, "exact"), &remaining); err != nil {
		t.Errorf("an entry exactly at the budget was refused: %v", err)
	}
	remaining = 4
	if err := writeFile(strings.NewReader("abcde"), filepath.Join(dir, "over"), &remaining); !errors.Is(err, errHaulTooLarge) {
		t.Errorf("err = %v, want errHaulTooLarge", err)
	}
}

// A tar whose body is shorter than its header claims stops the unpack, rather
// than leaving a truncated blob behind for the scan to misread as an image
// that could not be parsed.
func TestUnpackRejectsATruncatedEntry(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "haul.tar")

	// Written by hand rather than through tarball, because a tar.Writer will
	// not close over an entry it is still owed bytes for -- which is the whole
	// point of this archive.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "blob", Mode: 0o644, Size: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(tw, zeroes{}, 512); err != nil {
		t.Fatal(err)
	}
	tw.Flush()
	writeBytes(t, src, buf.Bytes())

	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := unpack(context.Background(), src, dest); err == nil {
		t.Fatal("unpack accepted an archive with a truncated entry")
	}
}

func TestUnpackStopsOnACancelledContext(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "haul.tar")
	writeBytes(t, src, tarball(t, func(tw *tar.Writer) {
		for i := range 64 {
			file(t, tw, "blobs/sha256/"+strings.Repeat("a", i+1), "x")
		}
	}))
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := unpack(ctx, src, dest); err == nil {
		t.Fatal("unpack ran to completion on a cancelled context")
	}
}

func TestUnpackRejectsSomethingThatIsNotAnArchive(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "haul.tar.zst")
	writeBytes(t, src, []byte("this is a text file, not a haul\n"))
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := unpack(context.Background(), src, dest); err == nil {
		t.Fatal("unpack accepted a file that is not an archive")
	}
}

type zeroes struct{}

func (zeroes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
