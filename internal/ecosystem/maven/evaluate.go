package maven

import (
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/langdb"
)

// Methods name the deterministic test behind a status, and appear in the
// output. They are part of the tool's published vocabulary.
const (
	// MethodInventory: the image's archives were listed and nothing else.
	MethodInventory = "jar-inventory"
	// MethodNoCode: the archive is present and holds no compiled class.
	MethodNoCode = "jar-no-code"
)

// evaluator holds what every finding for one component needs.
type evaluator struct {
	st *state

	// meta is set when the inventory was handed in rather than read out of a
	// tree, so no archive was ever opened. Both of this plugin's tests read an
	// entry list, and there is not one. See ecosystem.SBOMFinding.
	meta bool
}

// evaluate decides one advisory against one artifact.
//
// The order of the cases is the order of increasing cost and decreasing
// certainty, the same order the other plugins use: whether the artifact is in
// the image at all, and whether it holds compiled code.
func (e evaluator) evaluate(c ecosystem.Component, req ecosystem.Request) ecosystem.Finding {
	f := ecosystem.Finding{
		Module:  c.Name,
		Version: c.Version,
		PURL:    c.PURL,
		CVE:     req.ID,
	}

	// Absence is decided before the advisory is looked at. Whether OSV carries
	// a record for this id makes no difference to the fact that the image does
	// not contain the artifact the id was asked about.
	if e.st.absent {
		if e.meta {
			return ecosystem.SBOMAbsent(f, c.Name, MethodInventory)
		}
		return e.absent(f, c)
	}

	if req.Advisory == nil {
		// An explicitly requested id that OSV could not map to this artifact.
		// Reported rather than dropped: a missing finding reads as a clean one.
		f.Status = ecosystem.StatusUndetermined
		f.Reason = "no_osv_package_mapping"
		return f
	}

	// Before the entry list, because there is not one. Everything below reads
	// an empty list as an archive that could not be opened, which is a
	// different fact and carries a different verdict: a component out of a
	// bill of materials has no archive to open in the first place.
	if e.meta {
		return ecosystem.SBOMFinding(f, c.Name)
	}

	entries := e.st.entries()
	classes := classEntries(entries)

	if len(classes) == 0 {
		// Every zip holds at least one entry, so an empty list is not an
		// archive that ships nothing -- it is a central directory that could
		// not be read. "We could not look" must never render as "there is
		// nothing there".
		if !e.st.filesKnown() || len(entries) == 0 {
			f.Status = ecosystem.StatusLinked
			f.Method = MethodInventory
			f.Evidence = []ecosystem.Evidence{{
				Origin:   MethodInventory,
				Detail:   fmt.Sprintf("%s is present and its archive could not be listed, so what it contains is unknown", c.Name),
				Blocking: true,
			}}
			f.Reachability = "present, with no readable archive listing to say what it contains"
			return f
		}
		// A sources, javadoc or resources jar. It is a real artifact at a real
		// version that OSV will match, and it holds nothing a JVM can load.
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "vulnerable_code_not_present"
		f.Method = MethodNoCode
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodNoCode,
			Detail: fmt.Sprintf("%s holds %s and no compiled class",
				c.Name, count(len(entries), "entry", "entries")),
		}}
		return f
	}

	f.Evidence = []ecosystem.Evidence{{
		Origin: MethodInventory,
		Detail: fmt.Sprintf("%s is present at %s and holds %s",
			c.Name, strings.Join(c.Locations, ", "), count(len(classes), "class", "classes")),
	}}
	f.Evidence = append(f.Evidence, e.coordinateTaint(c)...)

	// The one test that can look below the artifact: the advisory sometimes
	// names the vulnerable class, and a class is an entry in the archive.
	var done bool
	if f, done = e.mined(f, c, req); done {
		return f
	}

	// Nothing left to narrow with. There is no reference graph for Java here,
	// so an artifact that holds the code is reported as holding it, with no
	// claim about whether anything calls it.
	f.Status = ecosystem.StatusLinked
	if f.Method == "" {
		f.Method = MethodInventory
	}
	f.Reachability = "present: the artifact is in the image and its classes are loadable (whether anything calls them is not asserted)"
	return f
}

// absent decides a component the user named that no archive declares.
func (e evaluator) absent(f ecosystem.Finding, c ecosystem.Component) ecosystem.Finding {
	// An archive that would not open and an archive that could be the artifact
	// asked about are the same obstacle: "no archive here is X" is not a claim
	// this scan is entitled to make while one of them is on the disk. An
	// unreadable archive is opaque and always counts; an unidentified one counts
	// only when it could plausibly be X -- a jar positively identified as some
	// other artifact, or one that ships no code at all, no longer stands in the
	// way of an answer it cannot be the subject of.
	group, artifact := splitCoord(c.Name)
	blocked := append([]string(nil), e.st.unreadable...)
	for _, u := range e.st.unidentified {
		if couldBe(u, group, artifact) {
			blocked = append(blocked, u.Path)
		}
	}
	if len(blocked) > 0 {
		f.Status = ecosystem.StatusUndetermined
		f.Reason = "unidentified_archive"
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodInventory,
			Detail: fmt.Sprintf("no archive in this image declares %s, but %s could not be identified",
				c.Name, list(blocked)),
			Blocking: true,
		}}
		return f
	}
	f.Status = ecosystem.StatusNotPresent
	f.Justification = "component_not_present"
	f.Method = MethodInventory
	f.Evidence = []ecosystem.Evidence{{
		Origin: MethodInventory,
		Detail: fmt.Sprintf("no jar, war or ear in this image declares %s", c.Name),
	}}
	return f
}

// splitCoord separates a Maven coordinate into its groupId and artifactId. A
// bare artifactId with no colon leaves the group empty.
func splitCoord(name string) (group, artifact string) {
	if g, a, ok := strings.Cut(name, ":"); ok {
		return g, a
	}
	return "", name
}

// couldBe reports whether an unidentified archive could be the artifact named by
// group and artifact -- the only case in which it may block a claim of absence.
//
// The conclusion is only ever narrowed toward "yes, it could", so a false clean
// cannot slip through here: the archive stops blocking only on positive evidence
// that it is something else.
//
//   - A codeless archive ships no class, so it cannot hold the vulnerable class
//     of any artifact and cannot be the one asked about.
//   - An archive whose file name names a different artifact, and whose classes
//     live under none of the asked-about group's packages, has said what it is
//     twice over. A repackaged copy that lied about its name would still carry
//     the artifact's classes, and those are checked regardless of the name.
//   - Anything else -- an anonymous jar, or one whose classes could belong to
//     the artifact -- still blocks.
func couldBe(u langdb.UnidentifiedArchive, group, artifact string) bool {
	if !u.HasClasses {
		return false
	}
	if u.FileArtifact != "" && artifact != "" && u.FileArtifact != artifact &&
		group != "" && !packagesUnder(u.ClassPackages, group) {
		return false
	}
	return true
}

// packagesUnder reports whether any of the archive's class packages could belong
// to the given groupId, comparing the group as a package path against each class
// package in either direction so a class deeper than the group, or a group
// deeper than the package root, both count.
func packagesUnder(classPackages []string, group string) bool {
	root := strings.ReplaceAll(group, ".", "/")
	if root == "" {
		return true
	}
	for _, p := range classPackages {
		if p == root ||
			strings.HasPrefix(p+"/", root+"/") ||
			strings.HasPrefix(root+"/", p+"/") {
			return true
		}
	}
	return false
}

// coordinateTaint records that this artifact's identity was reconstructed
// rather than read.
//
// It is not blocking. A guessed coordinate is a reason to distrust that OSV
// matched the right artifact in the first place, which cuts both ways and is
// something a reader has to know; it is not a reason to refuse a status the
// analysis would otherwise reach. What it does gate is the mined-class layer,
// which asks a question that only makes sense once the artifact is known.
func (e evaluator) coordinateTaint(c ecosystem.Component) []ecosystem.Evidence {
	if e.st.coordsKnown() {
		return nil
	}
	return []ecosystem.Evidence{{
		Origin: MethodInventory,
		Detail: fmt.Sprintf("%s carries no META-INF/maven or native-image metadata, so its coordinates were reconstructed from its file name and class layout and may name the wrong artifact", c.Name),
	}}
}

// classEntries are the entries that are compiled classes, multi-release copies
// under META-INF/versions/N included: a new enough JVM loads those in
// preference to the base copy, so they are code that runs.
func classEntries(entries []string) []string {
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e, ".class") {
			out = append(out, e)
		}
	}
	return out
}

// count renders a number with the right form of its noun.
func count(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// list renders paths as prose, naming at most a few so an image with two
// hundred unreadable archives produces a readable sentence.
func list(paths []string) string {
	const max = 3
	if len(paths) <= max {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%s and %d others", strings.Join(paths[:max], ", "), len(paths)-max)
}
