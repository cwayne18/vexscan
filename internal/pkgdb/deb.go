package pkgdb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

const (
	dpkgStatus   = "/var/lib/dpkg/status"
	dpkgStatusD  = "/var/lib/dpkg/status.d"
	dpkgInfoDir  = "/var/lib/dpkg/info"
	dpkgAltInfo  = "/usr/lib/dpkg/info"
	maxFieldLine = 1 << 20
)

// Deb reads dpkg's database.
type Deb struct{}

func (*Deb) Format() Format { return FormatDeb }

// Detect looks for either shape of dpkg database.
//
// Debian and Ubuntu ship one concatenated /var/lib/dpkg/status. Google's
// distroless images ship /var/lib/dpkg/status.d/ instead, a directory holding
// one status paragraph per package, because the images are assembled by Bazel
// rather than by dpkg. Both are real and both appear in images people scan.
func (*Deb) Detect(fsys target.RootFS) (string, bool) {
	if db, ok := firstExisting(fsys, dpkgStatus); ok {
		return db, true
	}
	if fi, err := fsys.Stat(dpkgStatusD); err == nil && fi.IsDir() {
		return dpkgStatusD, true
	}
	return "", false
}

func (d *Deb) Read(fsys target.RootFS) ([]Package, error) {
	db, ok := d.Detect(fsys)
	if !ok {
		return nil, fmt.Errorf("no dpkg database at %s or %s", dpkgStatus, dpkgStatusD)
	}

	var (
		pkgs []Package
		err  error
	)
	if db == dpkgStatusD {
		pkgs, err = readStatusDir(fsys, db)
	} else {
		pkgs, err = readStatusFile(fsys, db)
	}
	if err != nil {
		return nil, err
	}

	// A dpkg database with no installed packages is not a thing that exists in
	// a real image. Treat it as a parse failure rather than an inventory,
	// because downstream it would render as "nothing installed, nothing
	// vulnerable" -- a clean bill of health produced by a bug.
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%s parsed to zero installed packages", db)
	}

	info := dpkgInfo(fsys)
	for i := range pkgs {
		pkgs[i].DB = db
		pkgs[i].Files = debFiles(fsys, info, pkgs[i].Name, pkgs[i].Arch)
	}
	sortPackages(pkgs)
	return pkgs, nil
}

func readStatusFile(fsys target.RootFS, name string) ([]Package, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	err = scanParagraphs(f, func(p fields) error {
		pkg, ok, err := debPackage(p)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if ok {
			pkgs = append(pkgs, pkg)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pkgs, nil
}

func readStatusDir(fsys target.RootFS, dir string) ([]Package, error) {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Distroless writes a .md5sums sibling next to each status paragraph.
		if strings.HasSuffix(e.Name(), ".md5sums") {
			continue
		}
		got, err := readStatusFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, got...)
	}
	return pkgs, nil
}

// debPackage turns one status paragraph into a Package, reporting false when
// the paragraph describes a package whose files are not on disk.
func debPackage(p fields) (Package, bool, error) {
	name := p.get("Package")
	if name == "" {
		return Package{}, false, errors.New("status paragraph has no Package field")
	}
	if !debStateHasFiles(p.get("Status")) {
		return Package{}, false, nil
	}

	pkg := Package{
		Format:  FormatDeb,
		Name:    name,
		Version: p.get("Version"),
		Arch:    p.get("Architecture"),
	}
	if src := p.get("Source"); src != "" {
		pkg.Source, pkg.SourceVersion = splitSource(src)
	}
	return pkg, true, nil
}

// debStateHasFiles reports whether a dpkg "Status: <want> <flag> <state>"
// value describes a package whose files are present in the tree.
//
// "config-files" and "not-installed" are the two that are not: the package was
// removed and only its conffiles (or nothing) remain. Reporting those as
// installed would attribute a vulnerable version to an image that does not
// carry the code. Everything else -- unpacked, half-configured, the trigger
// states -- has the payload unpacked on disk and counts.
//
// A paragraph with no Status field at all counts as installed: some
// image-build tooling omits it, and a missed package is a false negative,
// which is the failure mode this tool exists to avoid.
func debStateHasFiles(status string) bool {
	fields := strings.Fields(status)
	if len(fields) == 0 {
		return true
	}
	switch fields[len(fields)-1] {
	case "config-files", "not-installed":
		return false
	}
	return true
}

// dpkgInfo finds the directory holding per-package file lists, if the image
// still has one. Slimmed images frequently delete it; that costs file-level
// evidence but not the inventory, so it is not an error.
func dpkgInfo(fsys target.RootFS) string {
	for _, dir := range []string{dpkgInfoDir, dpkgAltInfo} {
		if fi, err := fsys.Stat(dir); err == nil && fi.IsDir() {
			return dir
		}
	}
	return ""
}

// debFiles reads /var/lib/dpkg/info/<name>[:<arch>].list.
//
// dpkg qualifies the filename with the architecture only for "Multi-Arch:
// same" packages, and the status paragraph does not reliably say which naming
// was used, so both are tried.
func debFiles(fsys target.RootFS, info, name, arch string) []string {
	if info == "" {
		return nil
	}
	candidates := []string{name + ".list"}
	if arch != "" {
		candidates = append([]string{name + ":" + arch + ".list"}, candidates...)
	}
	for _, c := range candidates {
		b, err := fsys.ReadFile(path.Join(info, c))
		if err != nil {
			continue
		}
		return parseFileList(string(b))
	}
	return nil
}

// parseFileList reads dpkg's one-path-per-line list format. Directories are
// listed alongside regular files and are kept: nothing here stats the tree.
func parseFileList(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		// dpkg lists the root itself as "/.".
		if line == "" || line == "/." || !strings.HasPrefix(line, "/") {
			continue
		}
		out = append(out, path.Clean(line))
	}
	sort.Strings(out)
	return out
}

// fields is one RFC822-style paragraph. Values are stored with continuation
// lines joined by newlines, which no caller here looks at but which keeps a
// multi-line Description from being mistaken for more fields.
type fields map[string]string

func (f fields) get(key string) string { return strings.TrimSpace(f[key]) }

// scanParagraphs streams blank-line-separated RFC822 paragraphs to fn.
//
// Streaming rather than reading the file whole: a fat image's dpkg status runs
// to several megabytes, and the OS plugin reads one per image layer set.
func scanParagraphs(r io.Reader, fn func(fields) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxFieldLine)

	cur := fields{}
	last := ""
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		p := cur
		cur, last = fields{}, ""
		return fn(p)
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		// A leading space or tab continues the previous field. Description
		// bodies look like "Package: x" often enough that treating them as
		// fields would corrupt the paragraph.
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" {
				cur[last] += "\n" + strings.TrimSpace(line)
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		cur[key] = strings.TrimSpace(value)
		last = key
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return flush()
}
