// Package buildinfo reports which build of vexscan is running.
//
// It reads what the Go toolchain already stamps into the binary rather than
// taking a version from -ldflags, so a plain `go install
// github.com/cwayne18/vexscan@v0.6.2` self-describes exactly as a release
// build does. There is nothing to keep in sync and nothing to forget to pass.
//
// Every part is best effort and none of it is invented. A binary built by
// `go build` from a checkout reports "(devel)" and a dirty tree is marked as
// such -- those are the honest answers, not gaps to paper over, and a bug
// report that says "(devel)-dirty" has told the reader something true.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// Name is the tool's own name, so the report descriptor and the --version line
// spell it the same way.
const Name = "vexscan"

type info struct {
	version   string
	revision  string
	modified  bool
	goVersion string
}

// read is memoized because ReadBuildInfo walks the whole module graph embedded
// in the binary, and both --version and every report's descriptor want it.
var read = sync.OnceValue(func() info {
	i := info{version: "devel", goVersion: runtime.Version()}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return i
	}
	if bi.Main.Version != "" {
		i.version = bi.Main.Version
	}
	if bi.GoVersion != "" {
		i.goVersion = bi.GoVersion
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			i.revision = s.Value
		case "vcs.modified":
			i.modified = s.Value == "true"
		}
	}
	return i
})

// Version is the module version alone, e.g. "v0.6.2", or "(devel)" for a
// binary built from a checkout.
func Version() string { return read().version }

// Revision is the short commit the binary was built from, suffixed "-dirty"
// when the tree had uncommitted changes. Empty when the build carried no VCS
// stamp at all, which is what happens inside `go test`.
func Revision() string {
	i := read()
	if i.revision == "" {
		return ""
	}
	rev := i.revision
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if i.modified {
		rev += "-dirty"
	}
	return rev
}

// newRevision is Revision(), or "" when the version string already names the
// same commit. `go build` inside the module stamps Main.Version with a
// pseudo-version that ends in the commit and carries its own +dirty marker, so
// without this every line reads "v0.6.3-0.2026...-10b76b7d368a+dirty
// (10b76b7-dirty, ...)" -- the same fact twice, in two spellings.
func newRevision() string {
	rev := Revision()
	if rev == "" {
		return ""
	}
	if strings.Contains(read().version, strings.TrimSuffix(rev, "-dirty")) {
		return ""
	}
	return rev
}

// Short is the provenance stamp a report carries: "vexscan v0.6.2 (a1b2c3d)",
// or just "vexscan v0.6.2" when there is no revision left to add.
func Short() string {
	if rev := newRevision(); rev != "" {
		return fmt.Sprintf("%s %s (%s)", Name, Version(), rev)
	}
	return Name + " " + Version()
}

// String is the line --version prints: everything a bug report needs on one
// line, which is the version, the commit, the toolchain and the platform.
//
//	vexscan v0.6.2 (a1b2c3d, go1.24.4, darwin/arm64)
func String() string {
	i := read()
	parts := make([]string, 0, 3)
	if rev := newRevision(); rev != "" {
		parts = append(parts, rev)
	}
	parts = append(parts, i.goVersion, runtime.GOOS+"/"+runtime.GOARCH)
	return fmt.Sprintf("%s %s (%s)", Name, i.version, strings.Join(parts, ", "))
}
