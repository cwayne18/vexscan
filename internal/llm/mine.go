package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MineRequest asks the model to extract checkable identifiers from one
// advisory's prose.
type MineRequest struct {
	// ID is the advisory identifier, for the cache key and the prompt.
	ID string
	// Ecosystem is the plugin the advisory was resolved for ("os").
	Ecosystem string
	// Package is the affected package name, so the model can tell which of the
	// identifiers in a multi-package advisory belong to the one being checked.
	Package string
	// Summary and Details are the advisory text, verbatim from OSV.
	Summary string
	Details string
}

// Hints are the identifiers a model claims an advisory names.
//
// Every field is a *candidate*. Nothing here is a fact until the caller has
// matched it against something in the artifact: a hint that cannot be checked
// is indistinguishable from one that was invented, and the two must therefore
// be treated the same way. See the validation in the ospkg plugin.
type Hints struct {
	// Symbols are function or variable names the advisory says are vulnerable
	// ("SSL_free_buffers", "png_handle_iCCP").
	Symbols []string `json:"symbols"`
	// Sonames are shared-library names the advisory names ("libssl.so.3").
	Sonames []string `json:"sonames"`
	// Modules are importable module paths the advisory names, for the
	// language ecosystems: a dotted Python path ("yaml.cyaml") or an npm
	// subpath. Only the language mining prompts ask for these, so they are
	// empty for an OS advisory.
	Modules []string `json:"modules"`
	// Files are paths or file names the advisory names.
	Files []string `json:"files"`
	// Note is the model's own account of what it did, kept for the record so a
	// reader can see whether an empty result meant "the advisory names nothing"
	// or "the model declined".
	Note string `json:"note"`
}

// Empty reports whether the hints carry nothing checkable.
func (h *Hints) Empty() bool {
	return h == nil || (len(h.Symbols) == 0 && len(h.Sonames) == 0 &&
		len(h.Modules) == 0 && len(h.Files) == 0)
}

// minePrompt is written to make a wrong answer cheap and an invented one
// unlikely: it forbids inference, demands the identifier appear literally in
// the text, and makes the empty result an explicitly correct answer. That last
// part matters most -- a model given no way to say "nothing here" will produce
// something, and everything downstream of this is built to distrust it.
const minePrompt = `You extract checkable identifiers from security advisory text. You do not analyze, judge, or infer.
You are given the text of one advisory and the name of one affected package.
List ONLY identifiers that appear LITERALLY in the advisory text and belong to that package:
- symbols: names of vulnerable functions or variables, exactly as written (e.g. "SSL_free_buffers")
- sonames: shared library file names, exactly as written (e.g. "libssl.so.3")
- files: source or installed file names or paths, exactly as written
Do NOT guess, expand, complete, correct, or infer any identifier. Do NOT include a name that is merely typical of the package.
Do NOT include CVE ids, package names, version numbers, URLs, or commit hashes.
If the advisory names none of a category, return an empty array for it. Returning all three empty is a correct and expected answer.
Respond with ONLY a JSON object, no prose, of the form:
{"symbols":[],"sonames":[],"files":[],"note":"one sentence on what the advisory did or did not name"}`

// pyMinePrompt is the same instruction for a Python distribution.
//
// It is a separate constant rather than a generalization of minePrompt for the
// reason goPrompt and osPrompt are separate: a word changed in the shared one
// would move every OS result the tool has produced.
//
// The one addition that matters is the modules category, and the line telling
// the model that a function or attribute is not a module. Python's dotted
// names make "yaml.cyaml" and "yaml.load" look alike, and only the first is
// something an import statement can name -- so the plugin's validation is
// built to survive the model getting this wrong, and the prompt is written to
// make it wrong less often.
const pyMinePrompt = `You extract checkable identifiers from security advisory text. You do not analyze, judge, or infer.
You are given the text of one advisory and the name of one affected Python distribution.
List ONLY identifiers that appear LITERALLY in the advisory text and belong to that distribution:
- modules: importable Python module paths, exactly as written (e.g. "yaml.cyaml", "PIL.WebPImagePlugin"). A module is something an "import" statement can name. A function, class, method or attribute is NOT a module and belongs in symbols, even when the advisory writes it as a dotted path.
- symbols: names of vulnerable functions, classes or methods, exactly as written (e.g. "safe_load")
- files: source or installed file names or paths, exactly as written
Do NOT guess, expand, complete, correct, or infer any identifier. Do NOT include a name that is merely typical of the distribution.
Do NOT include CVE ids, distribution names, version numbers, URLs, or commit hashes.
If the advisory names none of a category, return an empty array for it. Returning all three empty is a correct and expected answer.
Respond with ONLY a JSON object, no prose, of the form:
{"modules":[],"symbols":[],"files":[],"note":"one sentence on what the advisory did or did not name"}`

// npmMinePrompt is the same instruction for an npm package.
//
// It asks for the one thing about an npm advisory that is mechanically
// checkable: the subpath. JavaScript writes a module with a slash and a
// property with a dot, so "lodash/template" is a file the package either ships
// or does not, while "lodash.template" is an expression. That syntactic split
// is what the Python prompt has to plead for and cannot enforce, and it is why
// this prompt can state the rule in one clause.
const npmMinePrompt = `You extract checkable identifiers from security advisory text. You do not analyze, judge, or infer.
You are given the text of one advisory and the name of one affected npm package.
List ONLY identifiers that appear LITERALLY in the advisory text and belong to that package:
- modules: importable subpaths of that package, exactly as written and including the package name (e.g. "lodash/template", "@babel/traverse/lib/path"). A module is something require() or import can name, and it always contains a slash. A property access written with a dot ("lodash.template") is NOT a module and belongs in symbols.
- symbols: names of vulnerable functions, classes or methods, exactly as written (e.g. "sanitizeUrl")
- files: source or installed file names or paths, exactly as written
Do NOT guess, expand, complete, correct, or infer any identifier. Do NOT include a name that is merely typical of the package.
Do NOT include CVE ids, bare package names, version numbers, URLs, or commit hashes.
If the advisory names none of a category, return an empty array for it. Returning all three empty is a correct and expected answer.
Respond with ONLY a JSON object, no prose, of the form:
{"modules":[],"symbols":[],"files":[],"note":"one sentence on what the advisory did or did not name"}`

// mavenMinePrompt is the same instruction for a Java artifact.
//
// It asks for class names into the symbols category rather than adding a
// category of its own, because a Java class is the unit of code and the unit of
// packaging at once: org.apache.logging.log4j.core.lookup.JndiLookup names a
// vulnerable type and names the entry JndiLookup.class in one breath. There is
// nothing left for a separate modules list to hold.
//
// It accepts both spellings on purpose. Advisories are inconsistent about
// qualification -- the Log4Shell record writes only "JndiLookup", never the
// package it lives in -- and the plugin can check either, so demanding the
// fully qualified form would throw away the case this ecosystem exists for. A
// bare name is checked against every spelling in the archive instead, which is
// the same test that keeps a shaded copy from being missed.
const mavenMinePrompt = `You extract checkable identifiers from security advisory text. You do not analyze, judge, or infer.
You are given the text of one advisory and the Maven coordinates of one affected Java artifact.
List ONLY identifiers that appear LITERALLY in the advisory text and belong to that artifact:
- symbols: names of vulnerable Java classes, exactly as written, whether the advisory writes them fully qualified ("org.apache.logging.log4j.core.lookup.JndiLookup") or bare ("JndiLookup"). A class name begins with a capital letter. A method name ("doLookup") is NOT a class and does not belong here, and neither does a package name that names no type.
- files: resource or configuration file names the advisory names, exactly as written (e.g. "log4j2.xml")
Do NOT guess, expand, complete, correct, or infer any identifier. In particular, do NOT add a package prefix the advisory did not write, and do NOT shorten one it did.
Do NOT include CVE ids, groupId or artifactId coordinates, version numbers, URLs, or commit hashes.
If the advisory names none of a category, return an empty array for it. Returning both empty is a correct and expected answer.
Respond with ONLY a JSON object, no prose, of the form:
{"symbols":[],"files":[],"note":"one sentence on what the advisory did or did not name"}`

// minePromptFor selects the mining instruction for an ecosystem.
func minePromptFor(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "pypi":
		return pyMinePrompt
	case "npm":
		return npmMinePrompt
	case "maven":
		return mavenMinePrompt
	default:
		return minePrompt
	}
}

// Mine extracts the identifiers an advisory names. Results are cached per
// advisory, because one advisory routinely applies to several packages and to
// several images in the same run.
func (c *Client) Mine(ctx context.Context, r MineRequest) (*Hints, error) {
	key := "mine|" + r.Ecosystem + "|" + r.ID + "|" + r.Package
	if h := c.cachedHints(key); h != nil {
		return h, nil
	}

	text := strings.TrimSpace(r.Summary + "\n\n" + r.Details)
	if text == "" {
		// Nothing to mine is not a failure, and asking anyway invites the model
		// to fill the silence.
		h := &Hints{Note: "the advisory carries no text"}
		c.storeHints(key, h)
		return h, nil
	}
	// Advisory details run to whole patch descriptions on some records; the
	// identifiers are always near the top.
	const maxText = 8000
	if len(text) > maxText {
		text = text[:maxText] + "\n[truncated]"
	}

	user := fmt.Sprintf("Advisory: %s\nAffected package: %s\nAdvisory text:\n%s", r.ID, r.Package, text)
	raw, err := c.chat(ctx, minePromptFor(r.Ecosystem), user)
	if err != nil {
		return nil, err
	}
	h, err := parseHints(raw)
	if err != nil {
		return nil, err
	}
	c.storeHints(key, h)
	return h, nil
}

func (c *Client) cachedHints(key string) *Hints {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	return c.hints[key]
}

func (c *Client) storeHints(key string, h *Hints) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.hints == nil {
		c.hints = make(map[string]*Hints)
	}
	c.hints[key] = h
}

// identRe is what an identifier is allowed to look like. It is a filter, not a
// parser: anything that could not be a C symbol, soname or file name did not
// come out of an advisory's identifier list, and letting it through would only
// give the validation layer more strings to fail to match.
var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.+/-]*$`)

// parseHints extracts the JSON object from a reply and discards anything in it
// that is not shaped like an identifier.
//
// An unparseable reply yields empty hints rather than an error: mining is
// optional, and a model that answered with prose has told us it found nothing
// it could name. Failing the scan over it would make an advisory layer able to
// break a deterministic one.
func parseHints(content string) (*Hints, error) {
	match := jsonObjRe.FindString(content)
	if match == "" {
		return &Hints{Note: "the model did not answer with JSON"}, nil
	}
	var h Hints
	if err := json.Unmarshal([]byte(match), &h); err != nil {
		return &Hints{Note: "the model's JSON could not be parsed"}, nil
	}
	h.Symbols = cleanIdents(h.Symbols)
	h.Sonames = cleanIdents(h.Sonames)
	h.Modules = cleanIdents(h.Modules)
	h.Files = cleanIdents(h.Files)
	h.Note = strings.TrimSpace(h.Note)
	return &h, nil
}

// cleanIdents trims, filters and dedupes one hint list.
func cleanIdents(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		s = strings.Trim(s, "`'\"()")
		// A "symbol" of one or two characters matches half the symbol table by
		// accident; that is worse than not having it.
		if len(s) < 3 || len(s) > 200 || seen[s] || !identRe.MatchString(s) {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
