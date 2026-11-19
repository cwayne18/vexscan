package ospkg

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"regexp"

	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

var nginxVersionRE = regexp.MustCompile(`nginx/([0-9]+\.[0-9]+\.[0-9]+)`)

// discoverNginx finds an nginx binary compiled into an image rather than
// installed by its package manager. ingress-nginx has this shape: its Alpine
// package database contains the runtime libraries, while nginx itself is
// copied into /usr/local from a build stage.
func discoverNginx(fsys target.RootFS, format pkgdb.Format) []pkgdb.Package {
	var out []pkgdb.Package
	_ = fsys.Walk("/", func(name string, d fs.DirEntry) error {
		if d.IsDir() || d.Type()&os.ModeType != 0 || path.Base(name) != "nginx" {
			return nil
		}
		b, err := fsys.ReadFile(name)
		if err != nil || len(b) < 4 || !bytes.Equal(b[:4], []byte{0x7f, 'E', 'L', 'F'}) {
			return nil
		}
		match := nginxVersionRE.FindSubmatch(b)
		if len(match) != 2 {
			return nil
		}
		out = append(out, pkgdb.Package{
			Format:  format,
			Name:    "nginx",
			Version: string(match[1]),
			Files:   []string{name},
			DB:      "embedded binary " + name,
		})
		return nil
	})
	return out
}

// discoverNginxVersion is kept separate so callers can reject ambiguous
// images without treating one of several different nginx binaries as truth.
func discoverNginxVersion(fsys target.RootFS, format pkgdb.Format) []pkgdb.Package {
	pkgs := discoverNginx(fsys, format)
	if len(pkgs) < 2 {
		return pkgs
	}
	version := pkgs[0].Version
	for _, pkg := range pkgs[1:] {
		if pkg.Version != version {
			return nil
		}
	}
	return pkgs[:1]
}
