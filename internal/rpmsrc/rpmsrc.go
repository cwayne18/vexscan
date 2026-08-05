// Package rpmsrc resolves what --rpm names into parsed packages.
//
// A --rpm value is a file, a directory of them, or a URL. All three end in the
// same place: pkgdb.ReadFile over an io.Reader, reading the header and stopping.
// Nothing here decompresses a payload or writes anything to disk.
//
// It sits between target and pkgdb rather than inside either. target models
// what a scan runs against and cannot import pkgdb without a cycle; pkgdb
// promises it never talks to the network, and fetching a package over HTTP is
// exactly that.
package rpmsrc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/pkgdb"
)

// maxHeaderRead bounds what a single package may make this read.
//
// The parser stops when the header ends, so on a well-formed file this is never
// reached -- the largest header measured was 85 KB. It exists for the file that
// is not well-formed: a header claiming 200 MB of data is within rpm's own
// limits and would otherwise be pulled in full off a remote server before being
// rejected.
const maxHeaderRead = 8 << 20

// Package is one RPM that parsed, and where it came from.
type Package struct {
	pkgdb.Package
	Meta pkgdb.Meta
	// Src is the file path or URL, for evidence and error messages. It is what
	// Package.DB holds for a package read from a database.
	Src string
}

// Result is everything a --rpm value resolved to.
type Result struct {
	Packages []Package

	// Skipped are files deliberately not scanned: source packages, and
	// anything in a directory that is not an rpm at all. Named rather than
	// counted, because "this directory had 312 packages and I read 311" is
	// only checkable if the twelfth is identifiable.
	Skipped []Note

	// Failed are rpms that could not be parsed. A scan with any of these is
	// not a complete account of what was asked for, and the caller is expected
	// to surface them and fail the run -- a package that would not read must
	// never be indistinguishable from one with nothing wrong in it.
	Failed []Note
}

// Note is one file and why it is not in Packages.
type Note struct {
	Src    string `json:"src"`
	Reason string `json:"reason"`
}

// Read resolves every --rpm value.
//
// A single named file that fails is a hard error: there is nothing else to
// report, and returning an empty inventory would render as a clean scan. A file
// inside a directory that fails is recorded in Failed and the walk continues,
// because one bad package must not cost the other three hundred -- but the
// caller must still fail the run over it.
func Read(ctx context.Context, specs []string, logf func(string, ...any)) (*Result, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	out := &Result{}
	for _, spec := range specs {
		if err := readOne(ctx, spec, out, logf); err != nil {
			return nil, err
		}
	}
	if len(out.Packages) == 0 {
		// Every path resolved and none of them held a package. Reporting an
		// empty inventory would scan clean, which is the one outcome an empty
		// result may never produce.
		return nil, fmt.Errorf("no rpm packages found in %s", strings.Join(specs, ", "))
	}
	sort.SliceStable(out.Packages, func(i, j int) bool {
		if out.Packages[i].Name != out.Packages[j].Name {
			return out.Packages[i].Name < out.Packages[j].Name
		}
		return out.Packages[i].Arch < out.Packages[j].Arch
	})
	return out, nil
}

func readOne(ctx context.Context, spec string, out *Result, logf func(string, ...any)) error {
	if isURL(spec) {
		pkg, err := readURL(ctx, spec, logf)
		if err != nil {
			return fmt.Errorf("%s: %w", spec, err)
		}
		out.add(*pkg, spec, logf)
		return nil
	}

	fi, err := os.Stat(spec)
	if err != nil {
		return fmt.Errorf("--rpm %s: %w", spec, err)
	}
	if !fi.IsDir() {
		pkg, err := readPath(spec)
		if err != nil {
			return fmt.Errorf("%s: %w", spec, err)
		}
		out.add(*pkg, spec, logf)
		return nil
	}
	return readDir(spec, out, logf)
}

// readDir walks a directory for packages.
//
// The order is sorted rather than the filesystem's, so two scans of the same
// tree query OSV in the same order and produce the same report. A file that is
// not an rpm is skipped silently by extension and noted when it claimed to be
// one -- a .rpm that is an HTML error page is worth saying out loud, because it
// is how a broken mirror looks.
func readDir(dir string, out *Result, logf func(string, ...any)) error {
	var found []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			out.Failed = append(out.Failed, Note{Src: p, Reason: err.Error()})
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".rpm") {
			return nil
		}
		found = append(found, p)
		return nil
	})
	if err != nil {
		return fmt.Errorf("--rpm %s: %w", dir, err)
	}
	if len(found) == 0 {
		return fmt.Errorf("--rpm %s: no .rpm files in this directory", dir)
	}
	sort.Strings(found)
	logf("Reading %d rpm package file(s) from %s...", len(found), dir)

	for _, p := range found {
		pkg, err := readPath(p)
		if err != nil {
			out.Failed = append(out.Failed, Note{Src: p, Reason: err.Error()})
			continue
		}
		out.add(*pkg, p, logf)
	}
	return nil
}

// add files a parsed package, or records why it was not one.
func (r *Result) add(pkg Package, src string, logf func(string, ...any)) {
	if pkg.Meta.SourcePackage {
		// A source package installs nothing and is not what any distribution
		// files advisories against. Scanning it would report the source name
		// as an installed component that does not exist anywhere.
		r.Skipped = append(r.Skipped, Note{Src: src, Reason: "source package"})
		logf("  skipping %s: source package", filepath.Base(src))
		return
	}
	pkg.Src = src
	pkg.DB = src
	r.Packages = append(r.Packages, pkg)
}

func readPath(p string) (*Package, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pkg, meta, err := pkgdb.ReadFile(io.LimitReader(f, maxHeaderRead))
	if err != nil {
		return nil, err
	}
	return &Package{Package: pkg, Meta: meta}, nil
}

// readURL streams a package until its header ends, then hangs up.
//
// There is no Range request here on purpose. Each rpm section states its own
// length in its first sixteen bytes, so a plain GET that stops reading is
// enough -- and it works against servers that ignore Range, which several
// mirrors do. Closing the body mid-response is what actually saves the
// transfer; on the packages measured that is 99.3% of a 2.4 MB file left
// unfetched.
func readURL(ctx context.Context, u string, logf func(string, ...any)) (*Package, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 403 is the common one: updates.suse.com serves SLE packages only to
		// registered systems, so it is worth being specific rather than saying
		// the file could not be read.
		return nil, fmt.Errorf("server answered %s", resp.Status)
	}

	c := &counter{r: io.LimitReader(resp.Body, maxHeaderRead)}
	pkg, meta, err := pkgdb.ReadFile(c)
	if err != nil {
		if errors.Is(err, pkgdb.ErrNotRPM) {
			return nil, fmt.Errorf("%w (a mirror answering an error page with 200 looks like this)", err)
		}
		return nil, err
	}
	logf("Fetched the header of %s: read %s of %s", filepath.Base(u), humanBytes(c.n), humanBytes(resp.ContentLength))
	return &Package{Package: pkg, Meta: meta}, nil
}

// counter records how much of a stream was actually consumed, which is the
// number the log line exists to show: a user needs to be able to see that
// --rpm over a URL did not download the package.
type counter struct {
	r io.Reader
	n int64
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func humanBytes(n int64) string {
	switch {
	case n < 0:
		return "an unstated total" // the server sent no Content-Length
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
