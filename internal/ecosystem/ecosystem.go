// Package ecosystem defines the contract every language or OS package
// ecosystem implements so vexscan can triage it.
//
// The governing rule is that a plugin brings a *deterministic presence test*
// and nothing else. Plugins never query OSV and never call the LLM: the
// orchestrator resolves advisories and applies the optional LLM overlay itself.
// That makes "the LLM is advisory, never the primary signal" a structural
// property of the code rather than a convention someone has to remember.
package ecosystem

import (
	"context"
	"strings"

	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// Status classifies one (location, advisory) pair.
//
// These five values are the tool's published vocabulary and deliberately do not
// grow: "the package isn't installed at all" is expressed as StatusNotPresent
// with a component_not_present justification, which VEX consumers already read,
// rather than as a sixth status every downstream parser would have to learn.
type Status string

const (
	StatusNotPresent   Status = "not_present"         // vulnerable code absent
	StatusNotInPath    Status = "not_in_execute_path" // present but not reachable
	StatusLinked       Status = "linked"              // genuinely linked (image mode)
	StatusReachable    Status = "reachable"           // genuinely called (source mode)
	StatusUndetermined Status = "undetermined"        // no mapping could be resolved
)

// Plugin is what every ecosystem implements. Capability is expressed by also
// implementing ImageAnalyzer, SourceAnalyzer, or both.
type Plugin interface {
	// ID is the stable selector used by --ecosystem and printed in output
	// ("golang", "os", "pypi").
	ID() string

	// Ecosystems lists the OSV ecosystem strings this plugin can produce
	// components for. Distro ecosystems are versioned at detect time
	// ("Debian:12"), so the OS plugin returns the unversioned families it
	// understands ("Debian", "Alpine") and callers match on prefix.
	Ecosystems() []string
}

// ImageAnalyzer analyzes a container image in three phases, because the
// orchestrator has to sit between them: it is the one that turns an inventory
// into advisories, and the one that decides which advisories were asked for.
type ImageAnalyzer interface {
	Plugin

	// DetectImage reports whether this plugin applies to img at all. A plugin
	// that does not apply is skipped silently; an error means detection itself
	// failed and must be surfaced, never treated as "does not apply".
	DetectImage(ctx context.Context, img *target.Image) (bool, error)

	// InventoryImage lists the components present, restricted to subjects when
	// any are given.
	//
	// Returning an empty inventory means "nothing is installed". A plugin that
	// found a package database it could not read must return an error instead:
	// an empty inventory renders as "no vulnerable packages", which is the
	// worst possible failure mode for a tool whose output becomes an
	// attestation.
	InventoryImage(ctx context.Context, img *target.Image, subjects []Subject) ([]Component, error)

	// AnalyzeImage decides each work item. Findings must carry no LLM verdict;
	// the orchestrator adds that.
	AnalyzeImage(ctx context.Context, img *target.Image, items []WorkItem) ([]Finding, error)
}

// SourceAnalyzer analyzes a source checkout in two phases rather than three.
//
// The split differs from ImageAnalyzer on purpose. In image mode the
// orchestrator resolves advisories, because an inventory of (name, version)
// pairs is exactly an OSV query. In source mode the analysis tool *is* the
// advisory source — govulncheck reports the module version along with the
// verdict — so forcing repo mode through an inventory phase would mean either
// running govulncheck twice or fabricating an inventory to satisfy the shape.
type SourceAnalyzer interface {
	Plugin

	// DetectSource reports whether this plugin applies to src.
	DetectSource(ctx context.Context, src *target.Source) (bool, error)

	// AnalyzeSource decides the requested ids against src. An empty requested
	// list means "every advisory that applies".
	AnalyzeSource(ctx context.Context, src *target.Source, subjects []Subject, requested []string) ([]Finding, error)
}

// Subject is what the user asked to scan, before anything has been resolved
// against a real target: the --package / --module selection.
type Subject struct {
	// Ecosystem restricts the subject to one plugin ("golang", "os"). Empty
	// matches any plugin, which is how a bare `--package openssl` resolves
	// against whatever inventory turns out to contain it.
	Ecosystem string
	// Name is the package or module name as given, or "" for "everything".
	Name string
	// PURL is set instead of Name when the user gave a full package URL.
	PURL string
	// Raw is exactly what the user typed, for error messages.
	Raw string
}

// MatchesAll reports whether s selects everything (no name and no purl).
func (s Subject) MatchesAll() bool {
	return s.Name == "" && s.PURL == ""
}

// Component is one installed thing a plugin found: a Go module, an OS package,
// a Python distribution.
type Component struct {
	// Ecosystem is the OSV ecosystem string ("Go", "Debian:12", "PyPI").
	Ecosystem string

	// Name is the package name *as OSV keys it*. For deb and rpm that is the
	// source package, not the binary package the database lists — getting this
	// backwards produces both false negatives and false positives, so plugins
	// map it during inventory rather than leaving it to the orchestrator.
	Name string

	// AltNames are further names to query OSV under, beyond Name.
	//
	// This exists because "which name does the advisory database key this
	// package on" has no consistent answer, even within one package format.
	// Debian and Alpine file against the source package, Red Hat and AlmaLinux
	// against the binary package, and Rocky Linux -- a rebuild of Red Hat --
	// against the source package like its upstream does not. Querying both
	// costs one extra entry in a batch request; picking the wrong single name
	// reports a vulnerable package as clean.
	//
	// The advisories from every name are merged into one set, so an advisory
	// filed under both names produces one finding, not two.
	AltNames []string

	// Version is the version string OSV can compare.
	Version string

	// PURL is the package URL. It is the stable identity in output and the key
	// a future vendor-VEX layer will match statements on.
	PURL string

	// Locations are the paths inside the target this component occupies or is
	// linked into. In Go image mode these are the binaries linking the module,
	// which is what lets the Go plugin keep its existing per-binary output
	// shape without a special case: one component per (module, version), one
	// finding per (binary, advisory).
	Locations []string

	// Extra is plugin-private state carried from inventory to analysis — a
	// loaded symbol table, the file list a package owns. The orchestrator never
	// inspects it.
	Extra any
}

// Key identifies a component for advisory resolution. Components sharing a key
// need only one OSV lookup between them.
func (c Component) Key() string {
	return c.Ecosystem + "|" + c.Name + "|" + c.Version
}

// WorkItem pairs a component with the advisories to decide on.
type WorkItem struct {
	Component Component

	// Advisories are what the orchestrator resolved, keyed by every id each
	// advisory is known by, so a plugin can look up a CVE, GHSA or GO id
	// interchangeably.
	Advisories map[string]*osv.Advisory

	// Requested are the ids the user explicitly asked about; empty means "every
	// advisory that applies". An id in this list with no matching advisory must
	// still produce a finding, recorded undetermined — otherwise a --cves scan
	// silently drops the ids it could not map, which reads as "not affected".
	Requested []string
}

// Evidence is one recorded observation behind a finding.
//
// Findings carry evidence rather than just a status so that a reader can tell a
// deterministic result from an advisory one, and so a future vendor-VEX layer
// can merge claims of different origin under a single policy instead of each
// source inventing its own way to overrule the others.
type Evidence struct {
	// Origin names what produced the observation: "pclntab", "govulncheck",
	// "pkgdb-inventory", "elf-needed-closure", "llm-mined", "vendor-vex".
	Origin string `json:"origin"`

	// Detail is a short statement of what was observed.
	Detail string `json:"detail"`

	// Blocking marks a taint: something that prevents concluding the component
	// is unaffected. A taint never sets a status by itself — it stops the
	// analysis from reaching a not_affected one, and says why in the output.
	Blocking bool `json:"blocking,omitempty"`
}

// Finding is the per-location, per-advisory result.
//
// The JSON shape is the tool's published output. Fields are added, never
// renamed or removed, and the Go-specific ones stay for compatibility even
// though other ecosystems leave them empty.
type Finding struct {
	Binary        string       `json:"binary,omitempty"`
	Module        string       `json:"module"`
	Version       string       `json:"version"`
	CVE           string       `json:"cve"`
	GoID          string       `json:"go_id,omitempty"`
	Packages      []string     `json:"packages,omitempty"`
	Granularity   string       `json:"granularity,omitempty"` // package | module
	Stripped      bool         `json:"stripped"`
	Status        Status       `json:"status"`
	Method        string       `json:"method,omitempty"`
	Justification string       `json:"justification,omitempty"`
	Reason        string       `json:"reason,omitempty"` // for undetermined
	LLM           *llm.Verdict `json:"llm,omitempty"`
	Evidence      []Evidence   `json:"evidence,omitempty"`

	// Reachability is how the plugin's deterministic layer characterized a
	// genuinely-affected component, in its own words ("linked (symbols
	// retained; reachability not asserted)"). It exists so the orchestrator can
	// build an LLM prompt without knowing anything ecosystem-specific, and is
	// not serialized.
	Reachability string `json:"-"`
}

// Affected reports whether a finding is a real one — something the LLM overlay
// should be asked about and a reader should act on.
func (f Finding) Affected() bool {
	return f.Status == StatusLinked || f.Status == StatusReachable
}

// EcosystemResult records how one plugin fared, independently of its findings.
//
// It exists so a failure is never indistinguishable from a clean result. A
// plugin that found a package database and could not read it reports the error
// here and contributes no findings, rather than contributing an empty inventory
// that renders as "nothing vulnerable".
type EcosystemResult struct {
	ID string `json:"id"`
	// Ecosystems are the concrete OSV ecosystem strings that were detected
	// ("Debian:12"), not the families the plugin supports.
	Ecosystems []string `json:"ecosystems,omitempty"`
	// Components is how many the inventory phase found.
	Components int `json:"components"`
	// Error is set when the plugin could not complete. Findings for this
	// ecosystem are then absent, not empty.
	Error string `json:"error,omitempty"`
}

// MatchEcosystem reports whether selector names a plugin, by its ID or by one
// of the OSV ecosystems it produces. Matching is case-insensitive and matches
// an unversioned family against a versioned ecosystem ("debian" vs
// "Debian:12").
func MatchEcosystem(p Plugin, selector string) bool {
	sel := strings.ToLower(strings.TrimSpace(selector))
	if sel == "" {
		return false
	}
	if strings.ToLower(p.ID()) == sel {
		return true
	}
	for _, e := range p.Ecosystems() {
		e = strings.ToLower(e)
		if e == sel || strings.HasPrefix(e, sel+":") || strings.HasPrefix(sel, e+":") {
			return true
		}
	}
	return false
}
