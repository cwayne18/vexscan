package pkgdb

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// apkDBs are the locations apk keeps its installed database. Alpine uses the
// first; the second exists on installs where /lib is not a symlink into /usr.
var apkDBs = []string{"/lib/apk/db/installed", "/var/lib/apk/db/installed"}

// APK reads apk's database, as used by Alpine, Wolfi, Chainguard and MinimOS.
type APK struct{}

func (*APK) Format() Format { return FormatAPK }

func (*APK) Detect(fsys target.RootFS) (string, bool) {
	return firstExisting(fsys, apkDBs...)
}

func (a *APK) Read(fsys target.RootFS) ([]Package, error) {
	db, ok := a.Detect(fsys)
	if !ok {
		return nil, fmt.Errorf("no apk database at %s", strings.Join(apkDBs, " or "))
	}
	f, err := fsys.Open(db)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	pkgs, err := parseAPK(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", db, err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%s parsed to zero installed packages", db)
	}
	for i := range pkgs {
		pkgs[i].DB = db
	}
	sortPackages(pkgs)
	return pkgs, nil
}

// parseAPK reads apk's installed database.
//
// The shape is blank-line-separated paragraphs like dpkg's, but every key is a
// single letter and the file list is inline rather than in a sibling file:
//
//	P:libssl3
//	V:3.1.4-r5
//	A:x86_64
//	o:openssl
//	F:lib
//	R:libssl.so.3
//	F:usr/lib
//	R:libssl.so
//
// "F:" sets the current directory (tree-relative, no leading slash) and each
// "R:" that follows names a file in it, so the two have to be read in order --
// a map of key to value would lose the association entirely.
func parseAPK(r io.Reader) ([]Package, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxFieldLine)

	var (
		out  []Package
		cur  Package
		dir  string
		open bool
	)
	flush := func() error {
		if !open {
			return nil
		}
		if cur.Name == "" {
			return fmt.Errorf("package paragraph has no P: field")
		}
		sort.Strings(cur.Files)
		out = append(out, cur)
		cur, dir, open = Package{}, "", false
		return nil
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || len(key) != 1 {
			continue
		}
		open = true
		switch key {
		case "P":
			cur.Format = FormatAPK
			cur.Name = value
		case "V":
			cur.Version = value
		case "A":
			cur.Arch = value
		case "o":
			cur.Source = value
		case "F":
			dir = strings.Trim(value, "/")
		case "R":
			if value == "" {
				continue
			}
			cur.Files = append(cur.Files, path.Clean("/"+path.Join(dir, value)))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}
