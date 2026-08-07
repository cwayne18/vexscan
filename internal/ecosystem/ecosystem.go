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
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
	"github.com/cwayne18/vexscan/internal/triage"
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

// OriginSBOM is the evidence origin on every finding produced from a bill of
// materials, and ReasonNoReachabilityTest is the reason those findings carry.
//
// They live here rather than in one plugin because five plugins write them and
// the report reads them: --sbom hands an inventory to all of os, golang, npm,
// pypi and maven at once, and the report's caveat sizes itself by counting the
// reason. A per-plugin spelling would make that count silently short by
// whichever plugins spelled it differently, and a caveat that undercounts the
// rows it explains is worse than no caveat.
//
// OriginSBOM is an evidence origin rather than a method. It names the absence
// of a test and not a test: a bill of materials says a package is there, which
// no plugin here can turn into a statement about whether its code would run.
const (
	OriginSBOM               = "sbom-metadata"
	ReasonNoReachabilityTest = "no_reachability_test_possible"

	// OriginGovulncheckUnavailable marks a linked Go finding whose reachability
	// could not be tested because the govulncheck binary was not on PATH. Like
	// OriginSBOM it lives here because the golang plugin writes it and the
	// report counts it, and a caveat that miscounts the rows it explains is
	// worse than none.
	OriginGovulncheckUnavailable = "govulncheck-unavailable"

	// OriginFalseCleanGuard is the evidence origin Finding.Validate stamps on a
	// finding it had to correct. It exists so a downgrade the guard performed is
	// visible in the output rather than silent: a reader can see the status the
	// plugin emitted was overruled and why.
	OriginFalseCleanGuard = "false-clean-guard"

	// ReasonUnprovenClean is the reason on a finding the guard demoted to
	// undetermined because nothing deterministic underwrote its clean verdict.
	ReasonUnprovenClean = "clean_status_without_manifest_grade_evidence"
)

// SBOMFinding is the verdict for a component that a bill of materials named.
//
// There is only one, and it is undetermined. Every plugin here decides a status
// in two steps -- does the package ship code, and would that code be loaded --
// and a CycloneDX component takes both away at once: it lists no files, so
// nothing rules the code out, and it comes with no tree, so nothing rules the
// reachability out. Anything more confident than this would be a conclusion
// drawn from an input that does not contain it.
//
// A function rather than the same literal written into each plugin, because the
// report's caveat sizes itself by counting these rows and five spellings would
// make the count short.
func SBOMFinding(f Finding, name string) Finding {
	f.Status = StatusUndetermined
	f.Reason = ReasonNoReachabilityTest
	f.Evidence = []Evidence{{
		Origin: OriginSBOM,
		Detail: fmt.Sprintf("%s was listed in a bill of materials, which gives its name and version "+
			"and says nothing about what it installs or whether anything would load it", name),
	}}
	return f
}

// SBOMAbsent is the verdict for a package the user named that the bill of
// materials does not list.
//
// Still not_present, and for the same reason a package database's silence is:
// the document is put forward as the complete inventory of what is there, so a
// name missing from it is a name that is not there. What changes is only the
// prose -- every plugin's own wording says "in this image", and there is no
// image, which in a report whose whole subject is what was and was not examined
// is not a detail to leave wrong.
//
// method is the caller's own inventory method, because that is what was
// consulted; only the document behind it differs.
func SBOMAbsent(f Finding, name, method string) Finding {
	f.Status = StatusNotPresent
	f.Justification = "component_not_present"
	f.Method = method
	f.Evidence = []Evidence{{
		Origin: method,
		Detail: fmt.Sprintf("no component in the bill of materials is named %s", name),
	}}
	return f
}

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

// HintConsumer is implemented by a plugin that can do something with hints
// mined from an advisory's prose.
//
// It exists so the orchestrator does not pay for mining nobody will read. The
// Go plugin has pclntab, which answers presence outright; asking a model to
// guess at symbol names for it would be a round trip per advisory spent on an
// answer the plugin discards. A plugin that says yes here is also promising to
// validate what it receives — an unvalidated hint is indistinguishable from a
// hallucination, and must never reach a status.
type HintConsumer interface {
	WantsHints() bool
}

// UsesHints reports whether a plugin opted into advisory mining.
func UsesHints(p Plugin) bool {
	c, ok := p.(HintConsumer)
	return ok && c.WantsHints()
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

// InventorySourceAnalyzer analyzes a source checkout in the same three phases
// as an image, for an ecosystem whose source-mode evidence is a lock file
// rather than a call-graph tool.
//
// It exists because SourceAnalyzer's two-phase shape encodes an assumption that
// only holds for Go: that the analysis tool supplies the advisories. A lock
// file supplies coordinates and nothing else, so an ecosystem reading one needs
// the orchestrator to sit in the middle and resolve them -- which is exactly
// what ImageAnalyzer's three phases are for. Reusing the phase structure means
// repo mode gets --cves filtering, the shared advisory cache and the LLM
// overlay for free, and means a plugin still cannot query OSV itself.
//
// AnalyzeSource deliberately collides with SourceAnalyzer's method of the same
// name at a different signature, so a type can satisfy one interface or the
// other but never both. That is the correct constraint: govulncheck and a lock
// file are two answers to one question, and an ecosystem has to pick.
type InventorySourceAnalyzer interface {
	Plugin

	// DetectSource reports whether this plugin applies to src.
	DetectSource(ctx context.Context, src *target.Source) (bool, error)

	// InventorySource lists the components the checkout declares, restricted
	// to subjects when any are given. The same rule as InventoryImage applies:
	// a lock file that was found and could not be parsed is an error, never an
	// empty inventory.
	InventorySource(ctx context.Context, src *target.Source, subjects []Subject) ([]Component, error)

	// AnalyzeSource decides each work item. Findings must carry no LLM verdict.
	AnalyzeSource(ctx context.Context, src *target.Source, items []WorkItem) ([]Finding, error)
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

	// Release narrows a bare-family Ecosystem to one product release, and is
	// empty unless the ecosystem needs it. Only SUSE does today: its query has
	// to be the bare family to match anything, so the product an advisory
	// applies to can only be checked after the fact. See osv.Ref.Release.
	Release string

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
	return c.Ecosystem + "|" + c.Release + "|" + c.Name + "|" + c.Version
}

// WorkItem pairs a component with the advisories to decide on.
type WorkItem struct {
	Component Component

	// Advisories are what the orchestrator resolved, keyed by every id each
	// advisory is known by, so a plugin can look up a CVE, GHSA or GO id
	// interchangeably.
	Advisories map[string]*osv.Advisory

	// Requested are the ids the user explicitly asked about; empty means "every
	// advisory that applies".
	Requested []string

	// Targeted says the user named this component, rather than it arriving from
	// an enumeration of everything installed.
	//
	// It decides what happens to a requested id this component has no advisory
	// for. Named, the user asked about this package and is owed an answer, so
	// the id reports undetermined; a --cves scan that silently dropped the ids
	// it could not map would read as "not affected". Enumerated, the same
	// answer repeated across four hundred packages is noise that buries the one
	// package the id actually landed on. An id that lands on nothing at all is
	// the orchestrator's to report, because it is the only thing that can see
	// the whole image at once.
	Targeted bool

	// Hints are the identifiers an LLM claimed each advisory's text names,
	// keyed by the advisory's canonical id. Present only under
	// --mine-advisories, and nil the rest of the time.
	//
	// Nothing here is a fact. A plugin must validate a hint against something
	// it can observe in the artifact before letting it support a
	// not_affected-flavored status, and an unvalidatable hint must be inert:
	// it is indistinguishable from an invented one. The validation lives in
	// the plugins because they are what hold the evidence to do it with.
	Hints map[string]*llm.Hints
}

// Request is one advisory to decide on, paired with the id the caller asked
// about -- which may be a CVE or GHSA alias rather than the record's own id.
type Request struct {
	ID       string
	Advisory *osv.Advisory

	// Hints are the mined identifiers for this advisory, or nil. See
	// WorkItem.Hints for what a plugin owes them.
	Hints *llm.Hints
}

// Requests turns a WorkItem's requested-id list into concrete lookups.
//
// In filter mode every requested id is returned, with a nil advisory when OSV
// has no mapping -- as long as the component was named. See Targeted for why an
// enumerated component drops the ids that do not apply to it. With no ids
// requested, every distinct advisory is returned under its canonical OSV id.
func (w WorkItem) Requests() []Request {
	if len(w.Requested) > 0 {
		out := make([]Request, 0, len(w.Requested))
		for _, id := range w.Requested {
			adv := w.Advisories[id]
			if adv == nil && !w.Targeted {
				continue
			}
			out = append(out, Request{ID: id, Advisory: adv, Hints: w.hintsFor(adv)})
		}
		return out
	}
	seen := map[string]bool{}
	var out []Request
	for _, adv := range w.Advisories {
		if seen[adv.ID] {
			continue
		}
		seen[adv.ID] = true
		out = append(out, Request{ID: adv.ID, Advisory: adv, Hints: w.hintsFor(adv)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// hintsFor looks up an advisory's mined hints. Hints are keyed by the
// advisory's own id, not by the alias the caller asked under, so a --cves scan
// naming a CVE finds the hints mined for the GHSA record behind it.
func (w WorkItem) hintsFor(adv *osv.Advisory) *llm.Hints {
	if adv == nil || w.Hints == nil {
		return nil
	}
	return w.Hints[adv.ID]
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
// renamed or removed, so the Go-only spellings below stay even though every
// other ecosystem leaves them empty.
//
// Identity is therefore written twice. ID/Package/Location are the
// ecosystem-neutral names new consumers should read; CVE/Module/Binary are the
// same values under the names gomod-vex published, kept so existing `jq`
// pipelines keep working. The orchestrator copies one onto the other rather
// than asking plugins to fill in both, so they cannot drift.
type Finding struct {
	// Ecosystem is the plugin that produced this finding ("golang", "os").
	// Plugins do not set it -- the orchestrator stamps every finding with the
	// analyzer it came from, so no plugin can forget to and no plugin can
	// claim to be another.
	Ecosystem string `json:"ecosystem,omitempty"`

	// ID is the advisory, under the id the caller asked about. Same value as
	// CVE.
	ID string `json:"id"`
	// Package is the component's name in its ecosystem's terms: a Go module
	// path, an OS source package. Same value as Module.
	Package string `json:"package"`
	// Location is the path inside the target the finding is about, empty when
	// the finding is about the whole target. Same value as Binary.
	Location string `json:"location,omitempty"`
	// PURL is the component's package URL, and the key the vendor-VEX layer
	// matches statements on. Plugins set this one; nothing else can.
	PURL string `json:"purl,omitempty"`

	// Product is the purl of the shipped artifact this finding was found in --
	// the scanned image, or a Go binary's main module. It is the other half of
	// a VEX lookup: a hub keys its documents by product and names components
	// like PURL inside them.
	//
	// Plugins do not set it. The orchestrator stamps the image product on every
	// finding, and a plugin that knows a narrower artifact overrides it.
	Product string `json:"product,omitempty"`

	Binary      string   `json:"binary,omitempty"`
	Module      string   `json:"module"`
	Version     string   `json:"version"`
	CVE         string   `json:"cve"`
	GoID        string   `json:"go_id,omitempty"`
	Packages    []string `json:"packages,omitempty"`
	Granularity string   `json:"granularity,omitempty"` // package | module

	// Upstream is the CVEs this advisory says its patch fixes, when it is a
	// bundle of more than one. Distro advisories routinely are: SUSE-SU-2026
	// :0312-1 addresses eight, RHSA-2024:2447 seven, and neither id names a
	// CVE anywhere.
	//
	// Plugins do not set it; the orchestrator fills it from the OSV record.
	// Empty is the ordinary case and means the advisory is about one thing,
	// which the row already names.
	Upstream []string `json:"upstream,omitempty"`

	// FixedVersion is the version the advisory's patch lands in for this
	// finding's package, when the OSV record publishes one. It is the
	// report's one actionable field: what to upgrade to.
	//
	// Plugins do not set it; the orchestrator fills it from the OSV record's
	// affected ranges, joined on Package. Empty means no fix was published --
	// a real and common state that the renderer shows as "no fix", not as a
	// blank cell, because the two mean opposite things.
	//
	// Emitted even when empty, and that is the whole point. "" is the "no fix"
	// answer, so omitting it would drop the fact a JSON consumer most needs --
	// the flaw is acknowledged and no patch has shipped -- and leave it
	// indistinguishable from a scan run before this field existed. The text
	// report goes to the trouble of printing "no fix" rather than a blank for
	// exactly this reason; omitempty would have undone that for every
	// non-human reader. Same rule as known_exploited.
	FixedVersion string `json:"fixed_version"`

	// FixedVersions is every version the advisory published a fix in, set only
	// when there is more than one and FixedVersion is therefore a choice rather
	// than the only answer.
	//
	// A vendor maintaining several branches fixes them all: GO-2022-0623 names
	// Vault 1.5.9, 1.6.5 and 1.7.2. Those are alternatives, and the one to
	// install depends on the branch you are on, so the report shows the target
	// it picked and the ones it did not. Omitted in the ordinary single-fix
	// case, where it would only repeat FixedVersion -- unlike that field, an
	// absence here has no second meaning to lose.
	FixedVersions []string `json:"fixed_versions,omitempty"`

	// Stripped is a pointer because it is a Go-only fact with three states: a
	// binary with symbols, a binary without, and an OS package that is not a
	// binary at all. A plain bool would report every deb in the image as
	// unstripped.
	Stripped *bool `json:"stripped,omitempty"`

	// Severity is the advisory's rating, in the vocabulary of internal/cvss,
	// and CVSS is the v3 base vector it was computed from when the record
	// published one. Plugins do not set these: the orchestrator fills them
	// from advisories it has already fetched, for the same reason it stamps
	// Ecosystem, so no plugin can forget to.
	//
	// Empty means no advisory data was resolved for the finding at all, which
	// is not the same as UNKNOWN -- that is a record which was read and
	// published no rating.
	Severity string `json:"severity,omitempty"`
	CVSS     string `json:"cvss,omitempty"`

	Status        Status       `json:"status"`
	Method        string       `json:"method,omitempty"`
	Justification string       `json:"justification,omitempty"`
	Reason        string       `json:"reason,omitempty"` // for undetermined
	LLM           *llm.Verdict `json:"llm,omitempty"`
	Evidence      []Evidence   `json:"evidence,omitempty"`

	// VEX is a published vendor statement covering this finding, when a
	// --vexhub was given and one matched. It never changes Status: the verdict
	// above is what local evidence concluded, and stays comparable between a
	// run with a hub and a run without one.
	VEX *VEXStatement `json:"vex,omitempty"`

	// Priority is exploitation evidence -- an EPSS score, a KEV listing --
	// attached by --triage. Like VEX it never changes Status: whether anyone is
	// exploiting a vulnerability elsewhere says nothing about whether the code
	// is present here, which is the only question this tool answers.
	//
	// Nil means --triage was off. Non-nil with Scored false means the flag was
	// on and this finding could not be looked up, which is a different fact and
	// must not be allowed to look like a low score.
	Priority *triage.Priority `json:"priority,omitempty"`

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

// clean reports whether a status is one of the two exculpatory verdicts: the
// vulnerable code is absent, or present but unreachable. These are the only
// statuses that can be a false clean, so they are the only ones Validate has to
// police.
func (s Status) clean() bool {
	return s == StatusNotPresent || s == StatusNotInPath
}

// hasCleanProvenance reports whether a finding carries something that could
// underwrite a clean verdict: a named deterministic method, or an evidence
// entry from a real test.
//
// A bill of materials is explicitly not such a test. OriginSBOM names a package
// and says nothing about what it installs or whether its code runs, so a clean
// resting on nothing but an SBOM origin has no ground to stand on. Blocking
// evidence is excluded too — a taint is the opposite of provenance for a clean.
func (f Finding) hasCleanProvenance() bool {
	if f.Method != "" {
		return true
	}
	for _, e := range f.Evidence {
		if !e.Blocking && e.Origin != "" && e.Origin != OriginSBOM {
			return true
		}
	}
	return false
}

// blockingTaint reports whether any evidence on the finding is a taint: an
// observation that, by construction, stops the analysis concluding a component
// is unaffected.
func (f Finding) blockingTaint() bool {
	for _, e := range f.Evidence {
		if e.Blocking {
			return true
		}
	}
	return false
}

// Validate enforces the false-clean invariant, the one property the whole tool
// rests on: a clean verdict — not_present or not_in_execute_path — is only ever
// emitted when a deterministic test established it, and never in the face of a
// taint that says the test could not be conclusive.
//
// Every plugin already honours this at the call site, gating each clean on a
// manifest-grade signal (filesKnown, coordsKnown, a package database's own file
// list, pclntab) and downgrading to linked with a recorded taint when the
// signal is missing. Validate is the net under that discipline: a defence in
// depth so a future plugin, refactor, or code path that forgets the guard
// cannot ship a false negative, and so the invariant is a checked property
// rather than a convention. On correct output it changes nothing.
//
// The correction is deliberately asymmetric, always toward the safe side:
//
//   - A clean carrying a taint becomes linked. A taint means the code may well
//     be present and merely could not be ruled out, which is exactly what
//     linked says; this mirrors the demotion the plugins perform themselves.
//   - A clean with no deterministic provenance becomes undetermined. Nothing
//     established the code's presence or absence, so neither clean nor linked is
//     warranted — only "no conclusion could be reached".
//
// It returns the finding, corrected when it violated the rule, and a non-empty
// reason when a correction was made, so the caller can log the violation
// loudly. A silent correction would hide the bug the guard exists to surface.
func (f Finding) Validate() (Finding, string) {
	if !f.Status.clean() {
		return f, ""
	}
	switch {
	case f.blockingTaint():
		reason := fmt.Sprintf("%s verdict for %s carries a blocking taint and cannot be a clean; downgraded to linked",
			f.Status, f.identity())
		f.Status = StatusLinked
		f.Justification = ""
		f.Evidence = append(f.Evidence, Evidence{Origin: OriginFalseCleanGuard, Detail: reason})
		return f, reason
	case !f.hasCleanProvenance():
		reason := fmt.Sprintf("%s verdict for %s rests on no manifest-grade evidence; downgraded to undetermined",
			f.Status, f.identity())
		f.Status = StatusUndetermined
		f.Justification = ""
		f.Reason = ReasonUnprovenClean
		f.Evidence = append(f.Evidence, Evidence{Origin: OriginFalseCleanGuard, Detail: reason})
		return f, reason
	}
	return f, ""
}

// identity names a finding for a log line, using whichever of the neutral or
// legacy spellings the caller has filled in.
func (f Finding) identity() string {
	pkg := f.Package
	if pkg == "" {
		pkg = f.Module
	}
	id := f.ID
	if id == "" {
		id = f.CVE
	}
	if pkg == "" {
		return id
	}
	return pkg + " / " + id
}

// VEXStatement is a vendor's published claim about a finding, copied out of a
// VEX hub document.
//
// Everything needed to audit the claim without re-fetching the hub is here:
// which hub, which author, which product it was filed under, and any spelling
// disagreement the match tolerated to get there.
type VEXStatement struct {
	// Status is OpenVEX's, not vexscan's: not_affected, affected, fixed,
	// under_investigation. It is deliberately a different vocabulary from
	// Finding.Status so the two can never be confused in the JSON.
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`

	Author    string `json:"author,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	// Product is the artifact purl the statement was filed under, and Hub the
	// --vexhub it came from.
	Product string `json:"product,omitempty"`
	Hub     string `json:"hub,omitempty"`
	// Match records how the statement's component purl differed from the
	// finding's, when it did. Empty means they agreed exactly.
	Match string `json:"match,omitempty"`
}

// Exculpatory reports whether the vendor's statement says the reader has
// nothing to do here.
//
// Only such a statement moves a row out of AFFECTED. A vendor confirming a
// finding, or saying they are still looking, must not make it quieter.
func (v *VEXStatement) Exculpatory() bool {
	return v != nil && (v.Status == "not_affected" || v.Status == "fixed")
}

// VEXHubResult records how one --vexhub fared, for the same reason
// EcosystemResult does: a hub that could not be reached must not look like a
// hub that had nothing to say.
type VEXHubResult struct {
	URL string `json:"url"`
	// Author is whoever signed the documents actually read from this hub.
	Author string `json:"author,omitempty"`
	// Products is how many artifacts the hub indexes, and Matched how many
	// findings it spoke to.
	Products int `json:"products,omitempty"`
	Matched  int `json:"matched"`
	// Error is why the hub contributed nothing. Unlike an ecosystem error it
	// does not make the whole run incomplete: see the comment on vexOverlay.
	Error string `json:"error,omitempty"`
}

// osPURLTypes are the purl types whose namespace is a distribution rather than
// part of the package's name.
var osPURLTypes = map[string]bool{"deb": true, "rpm": true, "apk": true}

// Component is the installed artifact's own name: the binary package, not the
// source package the advisory is filed against.
//
// For an OS package these differ, and printing Package instead makes the report
// appear to contradict itself. One Debian source package fans out into several
// binary packages with genuinely different answers -- gcc-12 ships gcc-12-base,
// which contains no ELF object and is not_present, alongside libgcc-s1 and
// libstdc++6, which are linked -- and all three are filed under the same
// advisory. Rendered as "gcc-12" they are three identical-looking rows with two
// different verdicts. The binary name is the thing that tells them apart, and
// it survives only in the purl.
//
// For every other ecosystem this returns exactly what Package does, so the
// distinction stays confined to the case where it is real. Anything unparseable
// falls back to Package: a name that is merely coarse beats no name at all.
func (f Finding) Component() string {
	if name, ok := purlName(f.PURL); ok {
		return name
	}
	return f.Package
}

// purlName pulls the binary package name out of an OS package URL.
//
// Only the OS types are handled. For npm the namespace is half the name and for
// Go the whole path is the name, so re-deriving those from the purl would be
// work that can only introduce a disagreement with what Package already says
// correctly.
func purlName(purl string) (string, bool) {
	body, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", false
	}
	// Qualifiers ("?arch=amd64") and the subpath are not part of the name.
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	typ, rest, found := strings.Cut(body, "/")
	if !found || !osPURLTypes[strings.ToLower(typ)] {
		return "", false
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[:at]
	}
	// What remains is "<distro>/<name>" or a bare "<name>"; the namespace is
	// the distribution and carries nothing a reader needs here.
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	// purl percent-encodes reserved characters. Package names rarely contain
	// any, but decoding failure must not lose the name.
	if decoded, err := url.PathUnescape(rest); err == nil {
		rest = decoded
	}
	if rest == "" {
		return "", false
	}
	return rest, true
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
