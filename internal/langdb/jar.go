package langdb

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// maxInnerArchive bounds how much of a nested archive is held in memory.
//
// An outer jar is read through its host path, so the zip reader seeks rather
// than buffers and its size costs nothing. A nested one has to be decompressed
// before it can be read at all, and a fat jar's own uber-jar dependency -- or a
// deliberately malformed entry claiming a huge uncompressed size -- would
// otherwise be a way to make a scan allocate without bound.
const maxInnerArchive = 256 << 20

// nestedLibDirs are the archive-inside-archive layouts worth descending into.
//
// All three are the same idea under three names: a deployable unit that carries
// its dependencies rather than expecting a classpath. Without descending, a
// Spring Boot image inventories as one component and misses the hundred jars
// that are the actual attack surface. The list is closed on purpose -- these are
// specified layouts, and treating every embedded zip as a dependency would pull
// in test fixtures and signed bundles that no classloader ever opens.
var nestedLibDirs = []string{
	"BOOT-INF/lib/", // Spring Boot executable jar
	"WEB-INF/lib/",  // servlet WAR
	"APP-INF/lib/",  // enterprise EAR
	"lib/",          // plain EAR, and Spring Boot's `war` packaging
}

// archive is one opened jar, war or ear: the entry names it holds, and the
// bytes of the few small entries that identify it.
//
// Only the names are kept for the general case. Everything the Maven reader and
// the plugin need afterwards -- the class list, the coordinates -- is either in
// a name or in one of the metadata entries cached at open time, so the file
// handle can be closed immediately. An image can hold a thousand jars, and
// holding a descriptor per jar to re-read entries nobody asks for would be a
// cost paid for nothing.
type archive struct {
	// Path is how the archive is addressed from outside. A nested one uses the
	// JVM's own spelling: "/app/app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar".
	Path string

	// Entries are every file entry name in the central directory, in the order
	// the directory listed them. Directory entries are dropped: they carry no
	// information a file entry's path does not already give.
	Entries []string

	// Nested are the embedded dependency archives, already parsed.
	Nested []*archive

	// Unreadable are nested archives that could not be opened, and this archive
	// itself if its own listing was truncated. Reported rather than dropped: an
	// embedded jar nobody could read is one whose contents must not be asserted
	// absent.
	Unreadable []string

	// meta holds the identifying entries, read while the archive was open.
	meta map[string][]byte
}

// Classes returns the entry names that are compiled classes.
//
// Multi-release entries under META-INF/versions/N are included. They are real
// classes that a new enough JVM loads in preference to the base one, so a scan
// that ignored them would report a class absent that the runtime does load.
func (a *archive) Classes() []string {
	var out []string
	for _, e := range a.Entries {
		if strings.HasSuffix(e, ".class") {
			out = append(out, e)
		}
	}
	return out
}

// Text returns a cached metadata entry, or "" when the archive does not carry
// it. Every caller is probing an optional source of coordinates, where absent
// and unparseable lead to the same next tier.
func (a *archive) Text(name string) string { return string(a.meta[name]) }

// Has reports whether the archive carries an entry.
func (a *archive) Has(name string) bool {
	for _, e := range a.Entries {
		if e == name {
			return true
		}
	}
	return false
}

// isMetadata reports whether an entry is worth caching at open time.
//
// These are the coordinate sources, and there are at most a handful per archive:
// one manifest, and one pom.properties per artifact merged into it.
func isMetadata(entry string) bool {
	if entry == "META-INF/MANIFEST.MF" {
		return true
	}
	return strings.HasPrefix(entry, "META-INF/maven/") &&
		strings.HasSuffix(entry, "/pom.properties")
}

// openArchive reads the archive at a tree-absolute path.
//
// The host path is preferred so the zip reader can seek: an image's fat jar runs
// to hundreds of megabytes, and buffering one to list its central directory
// would be pure waste. ReadFile is the fallback for a RootFS that cannot produce
// a host path.
func openArchive(fsys target.RootFS, name string) (*archive, error) {
	if host, err := fsys.HostPath(name); err == nil {
		if zr, err := zip.OpenReader(host); err == nil {
			defer zr.Close()
			return newArchive(name, &zr.Reader), nil
		}
	}
	b, err := fsys.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return openArchiveBytes(name, b)
}

// openArchiveBytes reads an archive already in memory, which is the only way a
// nested one can be read.
func openArchiveBytes(name string, b []byte) (*archive, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, err
	}
	return newArchive(name, zr), nil
}

// newArchive snapshots a zip's central directory, caches its metadata entries
// and parses its nested dependency archives. It must complete before the
// underlying reader is closed.
func newArchive(name string, zr *zip.Reader) *archive {
	a := &archive{Path: name, meta: map[string][]byte{}}

	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		a.Entries = append(a.Entries, f.Name)

		switch {
		case isMetadata(f.Name):
			if b, err := readZipEntry(f); err == nil {
				a.meta[f.Name] = b
			}
		case isNestedArchive(f.Name):
			a.addNested(name+"!/"+f.Name, f)
		}
	}
	sort.Strings(a.Unreadable)
	return a
}

// addNested parses one embedded dependency archive.
func (a *archive) addNested(inner string, f *zip.File) {
	b, err := readZipEntry(f)
	if err != nil {
		a.Unreadable = append(a.Unreadable, inner)
		return
	}
	na, err := openArchiveBytes(inner, b)
	if err != nil {
		a.Unreadable = append(a.Unreadable, inner)
		return
	}
	// One level only. Spring Boot and the servlet spec both nest exactly once,
	// and a jar inside a jar inside a jar is a repackaging no classloader
	// resolves without help.
	a.Unreadable = append(a.Unreadable, na.Unreadable...)
	na.Nested, na.Unreadable = nil, nil
	a.Nested = append(a.Nested, na)
}

// isNestedArchive reports whether an entry is a dependency archive in one of the
// specified fat-archive layouts.
func isNestedArchive(entry string) bool {
	if !isArchiveName(entry) {
		return false
	}
	for _, dir := range nestedLibDirs {
		// Directly in the lib directory, not somewhere below it: BOOT-INF/lib is
		// a flat directory of jars, and anything deeper shipped inside one of
		// them rather than beside them.
		if rest, ok := strings.CutPrefix(entry, dir); ok && !strings.Contains(rest, "/") {
			return true
		}
	}
	return false
}

// readZipEntry decompresses one entry, refusing anything over the memory bound.
//
// The declared uncompressed size is checked first so a zip bomb is rejected
// before it is expanded, and the copy is bounded anyway so a lying header cannot
// get past it.
func readZipEntry(f *zip.File) ([]byte, error) {
	if f == nil {
		return nil, errors.New("no such entry")
	}
	if f.UncompressedSize64 > maxInnerArchive {
		return nil, fmt.Errorf("%s: %d bytes exceeds the %d byte limit",
			f.Name, f.UncompressedSize64, maxInnerArchive)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	b, err := io.ReadAll(io.LimitReader(rc, maxInnerArchive+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxInnerArchive {
		return nil, fmt.Errorf("%s: exceeds the %d byte limit", f.Name, maxInnerArchive)
	}
	return b, nil
}

// archiveExts are the file extensions this reader treats as Java archives.
var archiveExts = []string{".jar", ".war", ".ear"}

// isArchiveName reports whether a path names a Java archive.
func isArchiveName(name string) bool {
	return hasAnySuffix(strings.ToLower(path.Base(name)), archiveExts)
}
