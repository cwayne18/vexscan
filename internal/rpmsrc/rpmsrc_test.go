package rpmsrc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cwayne18/vexscan/internal/pkgdb"
)

// The fixtures are pkgdb's, read across the package boundary rather than
// copied. They are 116 KB of captured header bytes from three real packages
// and there is nothing about them specific to either package -- a second copy
// would only be a second thing to keep in step.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "pkgdb", "testdata", "rpmfile", name+".hdr"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeRPM drops bytes into dir under name, and returns the path.
func writeRPM(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadParsesANamedFile(t *testing.T) {
	dir := t.TempDir()
	p := writeRPM(t, dir, "openssl-libs-3.5.5-2.el9_8.x86_64.rpm", fixture(t, "rocky9-openssl-libs"))

	res, err := Read(context.Background(), []string{p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(res.Packages))
	}
	pkg := res.Packages[0]
	if pkg.Name != "openssl-libs" {
		t.Errorf("Name = %q", pkg.Name)
	}
	// Src and DB both name the file. DB is what the report renders as the
	// evidence for where a package came from, and for --rpm the file is the
	// honest answer -- there is no database.
	if pkg.Src != p {
		t.Errorf("Src = %q, want %q", pkg.Src, p)
	}
	if pkg.DB != p {
		t.Errorf("DB = %q, want %q", pkg.DB, p)
	}
	if !pkg.Meta.HasELF() {
		t.Error("HasELF() = false for a package of shared libraries")
	}
	if len(res.Failed) != 0 || len(res.Skipped) != 0 {
		t.Errorf("Failed = %v, Skipped = %v, want neither", res.Failed, res.Skipped)
	}
}

func TestReadWalksADirectory(t *testing.T) {
	dir := t.TempDir()
	writeRPM(t, dir, "rocky-release-9.8-1.1.el9.noarch.rpm", fixture(t, "rocky9-rocky-release"))
	writeRPM(t, dir, "openssl-libs-3.5.5-2.el9_8.x86_64.rpm", fixture(t, "rocky9-openssl-libs"))
	// Not an rpm and not claiming to be: skipped by extension, silently.
	writeRPM(t, dir, "repomd.xml", []byte("<metadata/>"))
	// A nested directory is walked too; a repo tree is not flat.
	sub := filepath.Join(dir, "l")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRPM(t, sub, "libopenssl3-3.1.4-150600.2.19.x86_64.rpm", fixture(t, "sle15-libopenssl3"))

	var logged []string
	res, err := Read(context.Background(), []string{dir}, func(f string, a ...any) {
		logged = append(logged, fmt.Sprintf(f, a...))
	})
	if err != nil {
		t.Fatal(err)
	}

	// Sorted by name, so two runs over the same tree report in the same order.
	want := []string{"libopenssl3", "openssl-libs", "rocky-release"}
	var got []string
	for _, p := range res.Packages {
		got = append(got, p.Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("packages = %v, want %v", got, want)
	}
	if len(res.Failed) != 0 {
		t.Errorf("Failed = %v, want none", res.Failed)
	}
	if len(logged) == 0 || !strings.Contains(logged[0], "3 rpm package file(s)") {
		t.Errorf("log = %v, want the count of files found", logged)
	}
}

// TestOneBadPackageDoesNotCostTheOthers is the Unreadable rule on a different
// kind of tree: the good packages still scan, the bad one is named, and the
// caller has what it needs to refuse to call the run complete.
func TestOneBadPackageDoesNotCostTheOthers(t *testing.T) {
	dir := t.TempDir()
	writeRPM(t, dir, "good.rpm", fixture(t, "rocky9-openssl-libs"))
	writeRPM(t, dir, "cut-short.rpm", fixture(t, "rocky9-rocky-release")[:200])
	writeRPM(t, dir, "an-error-page.rpm", []byte("<html><body>404 Not Found</body></html>"))

	res, err := Read(context.Background(), []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "openssl-libs" {
		t.Fatalf("packages = %+v, want just openssl-libs", res.Packages)
	}
	if len(res.Failed) != 2 {
		t.Fatalf("Failed = %+v, want 2", res.Failed)
	}
	for _, want := range []string{"an-error-page.rpm", "cut-short.rpm"} {
		found := false
		for _, n := range res.Failed {
			if filepath.Base(n.Src) == want && n.Reason != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("Failed does not name %s with a reason: %+v", want, res.Failed)
		}
	}
}

func TestASourcePackageIsSkippedNotScanned(t *testing.T) {
	dir := t.TempDir()
	writeRPM(t, dir, "openssl-3.5.5-2.el9_8.src.rpm", srcRPM("openssl", "3.5.5", "2.el9_8"))
	writeRPM(t, dir, "openssl-libs-3.5.5-2.el9_8.x86_64.rpm", fixture(t, "rocky9-openssl-libs"))

	res, err := Read(context.Background(), []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "openssl-libs" {
		t.Fatalf("packages = %+v, want just the binary package", res.Packages)
	}
	if len(res.Skipped) != 1 || !strings.HasSuffix(res.Skipped[0].Src, "openssl-3.5.5-2.el9_8.src.rpm") {
		t.Fatalf("Skipped = %+v, want the src.rpm named", res.Skipped)
	}
	if res.Skipped[0].Reason != "source package" {
		t.Errorf("Reason = %q", res.Skipped[0].Reason)
	}
}

// TestNothingScannableIsAnErrorNotACleanScan is the whole reason Read returns
// an error on an empty inventory. A source rpm parses fine and yields no
// packages; reporting that as a result would render as "no findings".
func TestNothingScannableIsAnErrorNotACleanScan(t *testing.T) {
	dir := t.TempDir()
	p := writeRPM(t, dir, "openssl-3.5.5-2.el9_8.src.rpm", srcRPM("openssl", "3.5.5", "2.el9_8"))

	if _, err := Read(context.Background(), []string{p}, nil); err == nil {
		t.Fatal("a directory of nothing but source packages scanned clean")
	} else if !strings.Contains(err.Error(), "no rpm packages found") {
		t.Errorf("err = %v", err)
	}
}

func TestPathsThatResolveToNoPackages(t *testing.T) {
	empty := t.TempDir()
	writeRPM(t, empty, "repomd.xml", []byte("<metadata/>"))

	tests := []struct {
		name, spec, want string
	}{
		{"a directory with no rpms", empty, "no .rpm files"},
		{"a path that is not there", filepath.Join(empty, "nope.rpm"), "no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(context.Background(), []string{tt.spec}, nil)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
			// Whatever went wrong, the flag that caused it is named. The
			// message is the only place a user learns which --rpm value the
			// path came from when several were given.
			if !strings.Contains(err.Error(), "--rpm") {
				t.Errorf("err = %v, want it to name the flag", err)
			}
		})
	}
}

// TestReadURLStopsWhenTheHeaderEnds is the claim the whole URL mode rests on:
// a 2.4 MB package costs 18 KB. The server here offers 64 MB after the header
// and the test passes only if writing it fails, which happens only because the
// client hung up.
func TestReadURLStopsWhenTheHeaderEnds(t *testing.T) {
	hdr := fixture(t, "rocky9-openssl-libs")

	var wg sync.WaitGroup
	var mu sync.Mutex
	var wrote int
	var hungUp bool

	wg.Add(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		w.Write(hdr)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		chunk := make([]byte, 64<<10)
		for i := 0; i < 1024; i++ {
			n, err := w.Write(chunk)
			mu.Lock()
			wrote += n
			if err != nil {
				hungUp = true
			}
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	var logged []string
	res, err := Read(context.Background(), []string{srv.URL + "/openssl-libs-3.5.5-2.el9_8.x86_64.rpm"}, func(f string, a ...any) {
		logged = append(logged, fmt.Sprintf(f, a...))
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "openssl-libs" {
		t.Fatalf("packages = %+v", res.Packages)
	}
	if res.Packages[0].Src != srv.URL+"/openssl-libs-3.5.5-2.el9_8.x86_64.rpm" {
		t.Errorf("Src = %q, want the URL", res.Packages[0].Src)
	}
	if len(logged) == 0 || !strings.Contains(logged[0], "Fetched the header") {
		t.Errorf("log = %v, want the bytes-read line", logged)
	}

	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if !hungUp {
		t.Errorf("the server wrote all %d bytes without error: the client read the whole package", wrote)
	}
}

func TestURLsThatDoNotServeAPackage(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		body    string
		want    string
		wrapped error
	}{
		// The likeliest real failure. A mirror that answers a missing path
		// with a styled 200 error page must not be reported as a truncated
		// download, because the fix is a different one.
		{"an error page served with 200", 200, "<html><body>Not Found</body></html>", "not an rpm package file", pkgdb.ErrNotRPM},
		// updates.suse.com does this for SLE packages without SCC credentials.
		{"forbidden", 403, "denied", "403", nil},
		{"not found", 404, "nope", "404", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.code)
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			_, err := Read(context.Background(), []string{srv.URL + "/x.rpm"}, nil)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), srv.URL) {
				t.Errorf("err = %v, want it to name the URL", err)
			}
			// The sentinel survives the wrapping, so a caller can tell "this
			// was not a package" from "this package would not parse".
			if tt.wrapped != nil && !errors.Is(err, tt.wrapped) {
				t.Errorf("err = %v, want it to wrap %v", err, tt.wrapped)
			}
		})
	}
}

func TestReadURLHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, []string{srv.URL + "/x.rpm"}, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://dl.rockylinux.org/x.rpm", true},
		{"http://mirror/x.rpm", true},
		{"./x.rpm", false},
		{"/var/cache/dnf", false},
		// A Windows-style path is not a scheme, and neither is anything else
		// that is not http. ftp:// and file:// resolve as paths and fail with
		// a stat error naming what was not found, which is the clearer error.
		{"ftp://mirror/x.rpm", false},
	}
	for _, tt := range tests {
		if got := isURL(tt.in); got != tt.want {
			t.Errorf("isURL(%q) = %v", tt.in, got)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{17913, "17.5 KB"},
		{2411423, "2.3 MB"},
		// A chunked response states no length. Saying "of -1 B" would look
		// like a bug in the tool rather than a fact about the server.
		{-1, "an unstated total"},
	}
	for _, tt := range tests {
		if got := humanBytes(tt.in); got != tt.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// srcRPM builds the smallest rpm that is a source package: a lead, an empty
// signature header, and a main header naming ARCH src. There is no fixture for
// this because a real .src.rpm is megabytes of tarball and the four tags below
// are the entirety of what the skip decision reads.
func srcRPM(name, version, release string) []byte {
	var data []byte
	str := func(s string) uint32 {
		off := uint32(len(data))
		data = append(data, s...)
		data = append(data, 0)
		return off
	}
	type entry struct{ tag, typ, off uint32 }
	entries := []entry{
		{1000, 6, str(name)},
		{1001, 6, str(version)},
		{1002, 6, str(release)},
		{1022, 6, str("src")},
	}

	out := make([]byte, 96)
	copy(out, []byte{0xed, 0xab, 0xee, 0xdb})

	header := func(es []entry, d []byte) []byte {
		h := make([]byte, 16)
		copy(h, []byte{0x8e, 0xad, 0xe8, 0x01})
		binary.BigEndian.PutUint32(h[8:12], uint32(len(es)))
		binary.BigEndian.PutUint32(h[12:16], uint32(len(d)))
		for _, e := range es {
			var b [16]byte
			binary.BigEndian.PutUint32(b[0:4], e.tag)
			binary.BigEndian.PutUint32(b[4:8], e.typ)
			binary.BigEndian.PutUint32(b[8:12], e.off)
			binary.BigEndian.PutUint32(b[12:16], 1)
			h = append(h, b[:]...)
		}
		return append(h, d...)
	}

	sig := header(nil, nil)
	out = append(out, sig...)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	return append(out, header(entries, data)...)
}
