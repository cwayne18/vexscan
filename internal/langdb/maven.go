package langdb

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// Maven reads Java artifacts out of the jar, war and ear files in an image.
//
// A Java archive is a zip, which makes this the only ecosystem here whose
// presence test can go below the package: listing the central directory names
// every compiled class without executing anything, so "this artifact does not
// contain the vulnerable class" is a checkable claim rather than an inference.
// That case is not hypothetical -- the canonical Log4Shell mitigation was
// deleting JndiLookup.class from a jar whose version stayed 2.14.1, which every
// version-matching scanner still reports as vulnerable.
//
// What the archive does not reliably carry is its own coordinates. Maven writes
// META-INF/maven/<groupId>/<artifactId>/pom.properties, and OSV keys Java on
// exactly that pair; Gradle writes nothing of the sort, so spring-core-6.1.14.jar
// has no groupId anywhere in it. readCoords therefore descends through four
// tiers, and records which one answered: a coordinate this package guessed may
// never support a claim that something is absent from it.
type Maven struct{}

// Format implements Reader.
func (*Maven) Format() Format { return FormatMaven }

// DirNames implements Reader. Java archives are files that live anywhere -- a
// servlet container's lib directory, /usr/share/java, an app's working
// directory -- so there is no directory to key on and FileSuffixes does the
// work instead.
func (*Maven) DirNames() []string { return nil }

// FileSuffixes implements FileReader.
func (*Maven) FileSuffixes() []string { return archiveExts }

// Read implements Reader. Its roots are archive paths rather than directories.
func (r *Maven) Read(fsys target.RootFS, roots []string) (Result, error) {
	res := Result{Format: FormatMaven, Roots: roots}

	for _, root := range roots {
		a, err := openArchive(fsys, root)
		if err != nil {
			// A file that ends in .jar and is not a zip is ordinary -- images
			// carry truncated downloads, placeholder files and jars that are
			// really shell scripts with an archive appended. It is never silent,
			// because an archive nobody could open is one whose contents must
			// not be asserted absent.
			res.Unreadable = append(res.Unreadable, root)
			continue
		}
		res.Unreadable = append(res.Unreadable, a.Unreadable...)
		r.collect(a, path.Dir(root), &res)
		for _, n := range a.Nested {
			r.collect(n, root, &res)
		}
	}

	sortPackages(res.Packages)
	sort.Strings(res.Unreadable)
	sort.Strings(res.Unidentified)
	return res, nil
}

// collect turns one archive into the packages it declares.
func (r *Maven) collect(a *archive, db string, res *Result) {
	pkgs := readCoords(a)
	if len(pkgs) == 0 {
		res.Unidentified = append(res.Unidentified, a.Path)
		return
	}

	classes := a.Classes()
	for _, pkg := range pkgs {
		pkg.Format = FormatMaven
		pkg.Dir = a.Path
		pkg.DB = db
		// The whole entry list, not a share of it. A shaded uber-jar declares
		// several artifacts and there is no way to tell whose class is whose, so
		// every declared artifact is credited with everything -- which is the
		// safe direction, since the only thing this list is used to prove is
		// that something is *not* in it.
		pkg.Files = append([]string(nil), a.Entries...)
		pkg.FilesKnown = true
		pkg.ImportNames = classPrefixes(classes)
		pkg.ImportNamesKnown = len(classes) > 0
		res.Packages = append(res.Packages, pkg)
	}
}

// readCoords identifies an archive, descending tiers until one answers.
func readCoords(a *archive) []Package {
	if pkgs := mavenCoords(a); len(pkgs) > 0 {
		return pkgs
	}
	mf := parseManifest(a.Text("META-INF/MANIFEST.MF"))
	if pkg, ok := nativeImageCoords(a, mf); ok {
		return []Package{pkg}
	}
	if pkg, ok := manifestCoords(mf); ok {
		return []Package{pkg}
	}
	if pkg, ok := filenameCoords(a); ok {
		return []Package{pkg}
	}
	return nil
}

// mavenCoords reads META-INF/maven/<groupId>/<artifactId>/pom.properties, the
// only source in an archive that Maven itself wrote and that names the exact
// pair OSV keys on.
//
// More than one is normal rather than an error: maven-shade-plugin merges the
// metadata of everything it absorbs, so an uber-jar honestly declares all of
// them. Each becomes a package, and a CVE against any of them lands.
func mavenCoords(a *archive) []Package {
	var out []Package
	for _, e := range a.Entries {
		if !isMetadata(e) || !strings.HasSuffix(e, "/pom.properties") {
			continue
		}
		props := parseProperties(a.Text(e))
		group, artifact, version := props["groupId"], props["artifactId"], props["version"]
		if group == "" || artifact == "" {
			// The path itself is META-INF/maven/<groupId>/<artifactId>/, so a
			// pom.properties missing a key can still be located.
			rest := strings.TrimSuffix(strings.TrimPrefix(e, "META-INF/maven/"), "/pom.properties")
			if g, aid, ok := strings.Cut(rest, "/"); ok {
				group, artifact = orDefault(group, g), orDefault(artifact, aid)
			}
		}
		if group == "" || artifact == "" {
			continue
		}
		out = append(out, Package{
			Name:        group + ":" + artifact,
			Version:     version,
			CoordsKnown: true,
		})
	}
	return out
}

// nativeImageCoords reads META-INF/native-image/<groupId>/<artifactId>/, the
// GraalVM reachability-metadata layout.
//
// It exists because Gradle writes no META-INF/maven, which would leave the whole
// Spring ecosystem unidentifiable: spring-core-6.1.14.jar carries no groupId
// anywhere except this directory. The convention requires the same two
// coordinates in the same order, so it is as authoritative as pom.properties --
// the build wrote it, nothing here inferred it.
func nativeImageCoords(a *archive, mf map[string]string) (Package, bool) {
	const prefix = "META-INF/native-image/"
	for _, e := range a.Entries {
		rest, ok := strings.CutPrefix(e, prefix)
		if !ok {
			continue
		}
		parts := strings.Split(rest, "/")
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
			// Two segments and a file: anything shallower is metadata that was
			// not filed under coordinates.
			continue
		}
		version := firstOf(mf, "Implementation-Version", "Bundle-Version")
		if version == "" {
			_, version = splitArchiveName(a.Path)
		}
		if version == "" {
			continue
		}
		return Package{
			Name:        parts[0] + ":" + parts[1],
			Version:     version,
			CoordsKnown: true,
		}, true
	}
	return Package{}, false
}

// manifestCoords reads coordinates out of MANIFEST.MF.
//
// This is the first guessing tier. Implementation-Vendor-Id is conventionally
// the groupId and often is, but it is a free-text vendor string that nothing
// validates, and Bundle-SymbolicName is an OSGi identity that only sometimes
// coincides with one. The result is queryable and must not support absence.
func manifestCoords(mf map[string]string) (Package, bool) {
	version := firstOf(mf, "Implementation-Version", "Bundle-Version", "Specification-Version")
	if version == "" {
		return Package{}, false
	}

	group := coordToken(firstOf(mf, "Implementation-Vendor-Id"))
	artifact := coordToken(firstOf(mf, "Implementation-Title", "Automatic-Module-Name"))

	// OSGi allows directives after a semicolon ("org.foo.bar;singleton:=true").
	symbolic, _, _ := strings.Cut(firstOf(mf, "Bundle-SymbolicName"), ";")
	symbolic = coordToken(strings.TrimSpace(symbolic))

	// A symbolic name is usually the whole dotted coordinate with the separator
	// lost, so the best that can be done is to guess where it was:
	// "org.apache.commons.lang3" -> org.apache.commons:lang3. Each half is
	// taken only where the manifest's own fields left a hole, so a jar that
	// states its vendor id keeps it.
	sGroup, sArtifact := splitDotted(symbolic)
	if group == "" {
		group = sGroup
	}
	if artifact == "" {
		artifact = orDefault(sArtifact, symbolic)
	}
	if group == "" || artifact == "" {
		return Package{}, false
	}

	pkg := Package{Name: group + ":" + artifact, Version: version}
	// Maven's own naming convention is that an artifactId's first hyphenated
	// segment repeats the last segment of its groupId -- org.apache.tomcat
	// publishes tomcat-catalina, org.apache.commons publishes commons-lang3 --
	// and an OSGi symbolic name has no way to spell that boundary, so
	// "org.apache.tomcat-catalina" splits one segment too shallow. The deeper
	// reading is offered alongside rather than instead: one more name in a
	// batch query costs nothing, and querying only the wrong one reports a
	// vulnerable artifact as clean.
	if head, _, ok := strings.Cut(artifact, "-"); ok && head != "" {
		if _, last, found := lastSegment(group); !found || last != head {
			pkg.AltNames = append(pkg.AltNames, group+"."+head+":"+artifact)
		}
	}
	return pkg, true
}

// coordToken keeps a manifest value only if it could be a groupId or
// artifactId.
//
// Maven allows letters, digits, hyphens, underscores and dots and nothing
// else, which is enough to throw out the field that most often derails this
// tier: Implementation-Title is a product name ("Apache Tomcat") at least as
// often as it is an artifactId, and letting one through both names the
// artifact wrongly and suppresses the Bundle-SymbolicName that would have
// named it right.
func coordToken(s string) string {
	if s == "" {
		return ""
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return ""
		}
	}
	return s
}

// lastSegment splits a dotted name into everything before the final dot and
// the final segment.
func lastSegment(s string) (head, last string, ok bool) {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return "", s, false
	}
	return s[:i], s[i+1:], true
}

// filenameCoords is the last resort: the Maven Central file-naming convention
// for the artifact and version, and the classes' own package prefixes as
// candidate groupIds.
//
// It is the weakest tier and demonstrably fallible -- guava's classes live under
// com.google.common while its groupId is com.google.guava -- which is why every
// plausible prefix is offered as an alternate name. Querying five names costs
// five entries in a batch request; querying the wrong single one reports a
// vulnerable artifact as clean.
func filenameCoords(a *archive) (Package, bool) {
	artifact, version := splitArchiveName(a.Path)
	if artifact == "" || version == "" {
		return Package{}, false
	}
	groups := groupCandidates(a.Classes())
	if len(groups) == 0 {
		return Package{}, false
	}

	pkg := Package{Name: groups[0] + ":" + artifact, Version: version}
	for _, g := range groups[1:] {
		pkg.AltNames = append(pkg.AltNames, g+":"+artifact)
	}
	return pkg, true
}

// splitArchiveName splits "log4j-core-2.14.1.jar" into artifact and version.
//
// The split is the last hyphen followed by a digit, which is what makes
// "guava-32.1.3-jre.jar" yield 32.1.3-jre rather than stopping at the
// classifier-looking suffix.
func splitArchiveName(p string) (artifact, version string) {
	base := path.Base(p)
	for _, ext := range archiveExts {
		if len(base) > len(ext) && strings.EqualFold(base[len(base)-len(ext):], ext) {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	for i := 0; i+1 < len(base); i++ {
		if base[i] != '-' || base[i+1] < '0' || base[i+1] > '9' {
			continue
		}
		return base[:i], base[i+1:]
	}
	return "", ""
}

// maxGroupSegments bounds how deep a candidate groupId is guessed. Four dotted
// segments covers org.apache.logging.log4j; past that a prefix is a package
// name, not a coordinate anybody publishes under.
const maxGroupSegments = 4

// groupCandidates offers the dotted prefixes a set of classes could have been
// published under, longest first.
//
// Only the prefix every class shares is used. A jar whose classes span two
// unrelated roots has been repackaged, and the shared prefix of "org/foo" and
// "com/bar" is nothing -- which is the correct answer, since nothing about that
// jar's layout implies a coordinate.
func groupCandidates(classes []string) []string {
	var common []string
	for i, c := range classes {
		segs := strings.Split(path.Dir(stripMultiRelease(c)), "/")
		if i == 0 {
			common = segs
			continue
		}
		n := 0
		for n < len(common) && n < len(segs) && common[n] == segs[n] {
			n++
		}
		common = common[:n]
		if len(common) < 2 {
			return nil
		}
	}
	if len(common) < 2 {
		return nil
	}
	if len(common) > maxGroupSegments {
		common = common[:maxGroupSegments]
	}

	var out []string
	for n := len(common); n >= 2; n-- {
		out = append(out, strings.Join(common[:n], "."))
	}
	return out
}

// classPrefixes are the two-segment package roots the archive's classes live
// under, for evidence and for a reader skimming an inventory.
func classPrefixes(classes []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range classes {
		segs := strings.Split(stripMultiRelease(c), "/")
		if len(segs) < 3 {
			continue
		}
		p := segs[0] + "." + segs[1]
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// stripMultiRelease removes the META-INF/versions/N/ prefix from a versioned
// class entry, leaving the package path the class actually declares.
func stripMultiRelease(entry string) string {
	rest, ok := strings.CutPrefix(entry, "META-INF/versions/")
	if !ok {
		return entry
	}
	_, after, found := strings.Cut(rest, "/")
	if !found {
		return entry
	}
	return after
}

// parseProperties reads a java.util.Properties file, which is enough of an INI
// for the three keys pom.properties carries.
func parseProperties(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// parseManifest reads MANIFEST.MF, undoing the 72-byte line folding the jar
// specification requires. A continuation line begins with exactly one space,
// and the space is not part of the value -- reading the file line by line
// without this yields truncated coordinates.
func parseManifest(text string) map[string]string {
	out := map[string]string{}
	key, val := "", strings.Builder{}
	flush := func() {
		if key != "" {
			out[key] = strings.TrimSpace(val.String())
		}
		key, val = "", strings.Builder{}
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, " ") {
			val.WriteString(line[1:])
			continue
		}
		flush()
		if k, v, ok := strings.Cut(line, ":"); ok {
			key = strings.TrimSpace(k)
			val.WriteString(strings.TrimSpace(v))
		}
	}
	flush()
	return out
}

// splitDotted guesses where a dotted OSGi symbolic name divides into groupId and
// artifactId: everything but the last segment, and the last segment.
func splitDotted(s string) (group, artifact string) {
	i := strings.LastIndex(s, ".")
	if i <= 0 || i == len(s)-1 {
		return "", ""
	}
	return s[:i], s[i+1:]
}

// firstOf returns the first non-empty value among keys.
func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

// orDefault returns s, or fallback when s is empty.
func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// MavenPURL renders an artifact as a package URL. The groupId is the purl
// namespace, so the OSV name's colon becomes a slash.
func MavenPURL(name, version string) string {
	group, artifact, ok := strings.Cut(name, ":")
	if !ok {
		return ""
	}
	s := fmt.Sprintf("pkg:maven/%s/%s", group, artifact)
	if version != "" {
		s += "@" + version
	}
	return s
}
