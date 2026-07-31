package maven

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
)

// Methods for the mined-class layer. Both only ever appear under
// --mine-advisories.
const (
	// MethodClassAbsent: the class the advisory names is not an entry in this
	// artifact's archive, under any package spelling.
	MethodClassAbsent = "jar-class-absent"
	// MethodMined marks an observation from the mining layer that changed no
	// status -- including every case where validation rejected a hint.
	MethodMined = "llm-mined"
)

// classCheck is what the mined-class layer concluded about one advisory
// against one artifact.
type classCheck struct {
	// Validated are the mined names that survived the literal and shape gates.
	Validated []string
	// Found are the archive entries the validated names resolve to. Empty is
	// the interesting case: it is what supports absence.
	Found []foundClass
	// Why records what happened, for the evidence line. Always set.
	Why string
	// Usable reports whether the check may influence a status at all.
	Usable bool
}

// foundClass is one validated class name matched against one archive entry.
type foundClass struct {
	// Mined is the name as the advisory wrote it.
	Mined string
	// Entry is the archive entry that provides it.
	Entry string
	// Relocated marks a match found under a package other than the one the
	// advisory named -- the signature of a shaded jar, and the reason a match
	// under any spelling has to count.
	Relocated bool
}

// classRe is what a mined name has to look like to be a class.
//
// The last dotted segment must begin with a capital, which is the whole of the
// shape gate and is enough to do the one job it has: keeping method names out.
// Java's convention is not a rule the language enforces, but advisories are
// written by people who follow it, and the alternative -- checking the archive
// for an entry named after a method and finding nothing -- would turn every
// mined method name into a false claim of absence.
var classRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9_$]*$`)

// checkClasses applies the hallucination containment rule to the mined class
// names and then looks for each survivor in the archive.
//
// It is the same shape as npm.checkSubpaths and pypi.checkModules, and the
// gates that differ are the two that Java's packaging makes possible.
//
// The first gate is shared: a mined name must appear *literally* in the
// advisory's own text. The model was told to extract rather than infer, and
// this is where that instruction stops being trusted and starts being enforced.
//
// The second is the shape gate. A Java class is the unit of code and the unit
// of packaging at once, so the check downstream is exact -- but only for a
// name that is a class. "doLookup" is a method, there is no doLookup.class, and
// concluding absence from its absence would be a straightforward lie.
//
// The third is that a validated name is looked for under *every* package
// spelling in the archive, not only the one the advisory wrote. That is what
// makes a bare "JndiLookup" -- which is all GHSA-jfh8-c2jp-5v3q ever writes --
// checkable at all, and it is simultaneously the relocation guard:
// maven-shade-plugin defeats a class-presence test by rewriting
// org.apache.commons.X to com.foo.shaded.org.apache.commons.X, and a relocated
// copy still ends in /X.class. So a shaded artifact is reported as holding the
// class, never as missing it.
func (e evaluator) checkClasses(adv *osv.Advisory, hints *llm.Hints) classCheck {
	if hints == nil {
		return classCheck{Why: "advisory mining was not run for this advisory"}
	}
	if len(hints.Symbols) == 0 {
		note := hints.Note
		if note == "" {
			note = "the advisory text names no class"
		}
		return classCheck{Why: "no class could be mined: " + note}
	}

	text := advisoryText(adv)
	var literal []string
	for _, s := range hints.Symbols {
		if strings.Contains(text, s) {
			literal = append(literal, s)
		}
	}
	if len(literal) == 0 {
		return classCheck{Why: "every mined class (" + strings.Join(hints.Symbols, ", ") +
			") is absent from the advisory's own text, so it was invented rather than extracted"}
	}

	entries := e.st.entries()
	c := classCheck{}
	var rejected []string
	for _, s := range literal {
		simple := s
		if i := strings.LastIndex(s, "."); i >= 0 {
			simple = s[i+1:]
		}
		if !classRe.MatchString(simple) {
			rejected = append(rejected, s+" (not shaped like a class name)")
			continue
		}
		c.Validated = append(c.Validated, s)
		c.Found = append(c.Found, findClass(entries, s, simple)...)
	}
	if len(c.Validated) == 0 {
		return classCheck{Why: "every mined class was rejected: " + strings.Join(rejected, "; ")}
	}

	c.Usable = true
	if len(c.Found) == 0 {
		c.Why = strings.Join(c.Validated, ", ") + " named by the advisory, shipped by no entry in " + e.st.name()
	} else {
		c.Why = strings.Join(c.Validated, ", ") + " named by the advisory, shipped by " + e.st.name() +
			" as " + list(foundEntries(c.Found))
	}
	return c
}

// findClass returns every archive entry that provides one mined class.
//
// A fully qualified name is looked for at its own path first, so that the
// evidence can say whether a match was where the advisory said it would be.
// Either way the search then widens to every package in the archive, because
// the question a class-presence test answers is whether the JVM can load this
// type from this artifact, and a relocated copy can be loaded exactly as well
// as an original.
//
// Multi-release copies count. A jar's META-INF/versions/9/org/foo/C.class is
// what a JDK 9 or newer runtime loads in preference to the base copy, so an
// artifact that ships the class only there still ships it.
func findClass(entries []string, mined, simple string) []foundClass {
	var want string
	if strings.Contains(mined, ".") {
		want = strings.ReplaceAll(mined, ".", "/") + ".class"
	}
	suffix := "/" + simple + ".class"
	bare := simple + ".class"

	var out []foundClass
	for _, entry := range entries {
		path := stripVersions(entry)
		if !strings.HasSuffix(path, suffix) && path != bare {
			continue
		}
		out = append(out, foundClass{
			Mined:     mined,
			Entry:     entry,
			Relocated: want != "" && path != want,
		})
	}
	return out
}

// stripVersions reduces a multi-release entry to the class path it provides.
func stripVersions(entry string) string {
	rest, ok := strings.CutPrefix(entry, "META-INF/versions/")
	if !ok {
		return entry
	}
	if _, after, ok := strings.Cut(rest, "/"); ok {
		return after
	}
	return entry
}

// foundEntries lists the archive entries behind a set of matches.
func foundEntries(found []foundClass) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.Entry)
	}
	return out
}

// relocated returns the matches found under a package the advisory did not
// name.
func relocated(found []foundClass) []foundClass {
	var out []foundClass
	for _, f := range found {
		if f.Relocated {
			out = append(out, f)
		}
	}
	return out
}

// mined applies the mined-class layer, returning done when it decided the
// finding on its own.
//
// It changes nothing without --mine-advisories, and nothing when validation
// rejected every hint -- but it records what it did either way, because a
// reader has to be able to tell "the model found nothing usable" from "the
// model was never asked".
func (e evaluator) mined(f ecosystem.Finding, c ecosystem.Component, req ecosystem.Request) (ecosystem.Finding, bool) {
	m := e.checkClasses(req.Advisory, req.Hints)
	if !m.Usable {
		if req.Hints != nil {
			f.Evidence = append(f.Evidence, ecosystem.Evidence{Origin: MethodMined, Detail: m.Why})
		}
		return f, false
	}
	f.Evidence = append(f.Evidence, ecosystem.Evidence{Origin: MethodMined, Detail: m.Why})

	if len(m.Found) > 0 {
		// The class is loadable from this artifact, so there is nothing to
		// narrow: without a reference graph, "present" is the end of the story.
		// A copy found under a package the advisory did not name is worth
		// saying out loud, because it is the case where a reader might
		// otherwise expect absence -- the advisory's own path is empty, and the
		// only reason the answer is not not_present is that the build
		// relocated the class rather than removing it.
		if rel := relocated(m.Found); len(rel) > 0 {
			f.Evidence = append(f.Evidence, ecosystem.Evidence{
				Origin: MethodMined,
				Detail: fmt.Sprintf("%s holds the class under a package the advisory does not name (%s), which is what a shaded or relocated build looks like; it is loadable either way",
					c.Name, list(foundEntries(rel))),
				Blocking: true,
			})
		}
		return f, false
	}

	// Nothing in the archive provides the class, under any spelling. Two things
	// have to be true before that is a conclusion rather than an observation.
	//
	// The listing has to be complete: an archive whose central directory could
	// not be read holds nothing as far as this code can see, which is precisely
	// the failure that must never render as an answer.
	//
	// And the coordinates have to have been read rather than reconstructed.
	// Saying "this artifact ships no such class" about an artifact this scan
	// only believes the jar to be is two guesses stacked, and the second hides
	// the first.
	var why []string
	if !e.st.filesKnown() {
		why = append(why, "its archive listing is incomplete")
	}
	if !e.st.coordsKnown() {
		why = append(why, "its coordinates were reconstructed rather than read from the archive")
	}
	if len(why) > 0 {
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: MethodMined,
			Detail: fmt.Sprintf("no entry provides %s, but that is not a conclusion about %s because %s",
				strings.Join(m.Validated, ", "), c.Name, strings.Join(why, " and ")),
			Blocking: true,
		})
		return f, false
	}

	f.Status = ecosystem.StatusNotPresent
	f.Justification = "vulnerable_code_not_present"
	f.Method = MethodClassAbsent
	f.Evidence = append(f.Evidence, ecosystem.Evidence{
		Origin: MethodClassAbsent,
		Detail: fmt.Sprintf("%s ships %s and none of them provides %s, under any package",
			c.Name, count(len(classEntries(e.st.entries())), "class", "classes"),
			strings.Join(m.Validated, ", ")),
	})
	return f, true
}

// advisoryText is everything the advisory says, for the literal-substring gate.
func advisoryText(adv *osv.Advisory) string {
	if adv == nil {
		return ""
	}
	return adv.Summary + "\n" + adv.Details
}
