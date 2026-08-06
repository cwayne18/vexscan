// Package sbomsrc turns a CycloneDX bill of materials into the inventory the
// ecosystem plugins already consume.
//
// It is --rpm's sibling: an external artifact naming packages, with no
// filesystem behind it. The difference is how much less an SBOM carries. An rpm
// header lists every file the package installs and file(1)'s verdict on each,
// which is enough to say a package ships no executable code; a CycloneDX
// component is a name, a version and a purl. Nothing here can be turned into a
// reachability answer, and nothing here pretends otherwise -- see
// pkgdb.Meta.CanRuleOutCode, whose zero value is what makes that safe.
//
// It sits beside rpmsrc rather than inside target or pkgdb for the same
// reasons: target cannot import pkgdb without a cycle, and pkgdb promises it
// only ever parses a filesystem.
package sbomsrc

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/pkgdb"
)

// maxDocument bounds what a single SBOM may make this read. Real documents run
// to a few megabytes -- the Debian 12 bill measured 89 components and 120 KB --
// and the limit exists for the file that is not one, since the whole document
// has to be held in memory to be decoded at all.
const maxDocument = 256 << 20

// Component is one SBOM entry vexscan knows how to scan.
type Component struct {
	// PluginID names the ecosystem plugin that will evaluate this component:
	// "os", "golang", "npm", "pypi" or "maven". Tagged here, at the point the
	// purl type is read, so --ecosystem and the per-ecosystem outcome list
	// behave exactly as they do for an image.
	PluginID string

	// Format and Release describe an OS package and are empty for the rest.
	//
	// Release is left as a distro identity rather than resolved to an OSV
	// ecosystem, because --osv-ecosystem, the bare-family fallbacks and the
	// SUSE product narrowing all already live in ospkg, and a second copy of
	// that decision here is a second copy that can disagree.
	Format  pkgdb.Format
	Release osv.Release

	// Name is the component's name as OSV keys it. AltNames are other
	// spellings worth querying, on the same reasoning as pkgdb.OSVNames: a name
	// that matches nothing costs one entry in a batch query, and choosing the
	// wrong single name reports a vulnerable package as clean.
	Name     string
	AltNames []string

	// Source is the source package an OS binary package was built from. It is
	// the field that decides whether a Debian or Alpine scan finds anything at
	// all -- both file advisories against the source name -- and it is the one
	// the two producers spell most differently. See source().
	Source string

	Version string
	Arch    string
	Epoch   int

	// PURL is the component's package URL verbatim, for evidence.
	PURL string
	// Ref identifies the entry in the document, for notes and messages.
	Ref string
}

// Result is everything one SBOM resolved to.
type Result struct {
	Components []Component

	// Skipped are entries deliberately not scanned: structural components that
	// name no package, purl types vexscan has no ecosystem for, and components
	// with no version to match a range against. Named rather than counted,
	// because "this document had 400 components and I scanned 280" is only
	// checkable if the other 120 are identifiable.
	Skipped []Note

	// Failed are entries whose purl was present and would not parse. A scan
	// with any of these is not a complete account of the document, and the
	// caller is expected to surface them and fail the run -- a component that
	// could not be read must never be indistinguishable from one with nothing
	// wrong in it.
	Failed []Note
}

// Note is one entry and why it is not in Components.
type Note struct {
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
}

// Open resolves what --sbom names: a file, or "-" for standard input.
//
// Standard input is the point of the flag as much as the file is:
// `syft ... -o cyclonedx-json | vexscan --sbom -` is how a build pipeline hands
// its bill of materials straight to a scanner without writing it down.
func Open(spec string, logf func(string, ...any)) (*Result, error) {
	if spec == "-" {
		return Read(os.Stdin, "standard input", logf)
	}
	f, err := os.Open(spec)
	if err != nil {
		return nil, fmt.Errorf("--sbom %s: %w", spec, err)
	}
	defer f.Close()
	return Read(f, spec, logf)
}

// Read decodes one CycloneDX JSON document.
//
// src names where it came from, for error messages only.
//
// An error means the document could not be understood. It is never an empty
// Result: a bill of materials nobody could read and a bill of materials with
// nothing vulnerable in it must not produce the same report.
func Read(r io.Reader, src string, logf func(string, ...any)) (*Result, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var doc document
	dec := json.NewDecoder(io.LimitReader(r, maxDocument))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("--sbom %s: not JSON: %w", src, err)
	}
	// The format field is checked rather than sniffed, so an SPDX document --
	// the other thing a user will reach for, and the next format to support --
	// is told what it is instead of scanning as a document with no components.
	if doc.BOMFormat != "" && !strings.EqualFold(doc.BOMFormat, "CycloneDX") {
		return nil, fmt.Errorf("--sbom %s: this is a %s document; --sbom reads CycloneDX JSON", src, doc.BOMFormat)
	}
	if doc.BOMFormat == "" && doc.SpecVersion == "" && len(doc.Components) == 0 {
		return nil, fmt.Errorf("--sbom %s: this is JSON, but not a CycloneDX bill of materials", src)
	}

	flat := flatten(doc.Components, nil)
	out := &Result{}
	fallback := osFallback(flat)
	for _, c := range flat {
		out.add(c, fallback)
	}
	if len(out.Components) == 0 {
		// Every entry resolved and none of them was a package this tool can
		// query. Returning an empty inventory would scan clean, which is the
		// one outcome an empty result may never produce.
		return nil, fmt.Errorf("--sbom %s: no scannable components (%d entry/entries were skipped, %d would not parse)",
			src, len(out.Skipped), len(out.Failed))
	}
	sort.SliceStable(out.Components, func(i, j int) bool {
		if out.Components[i].PluginID != out.Components[j].PluginID {
			return out.Components[i].PluginID < out.Components[j].PluginID
		}
		return out.Components[i].Name < out.Components[j].Name
	})
	logf("Read %d component(s) from %s.", len(out.Components), src)
	return out, nil
}

// add files one entry, or records why it is not a component.
func (r *Result) add(c component, fallback osv.Release) {
	ref := c.ref()
	if c.PURL == "" {
		// Structural entries -- the container the bill describes, the "go.mod"
		// marker trivy emits, the operating-system row -- name no package and
		// their absence is not a gap. A library with no purl is a gap, and is
		// noted as one rather than dropped.
		r.Skipped = append(r.Skipped, Note{Ref: ref, Reason: fmt.Sprintf("no package URL (component type %q)", c.typeOrUnstated())})
		return
	}
	p, err := parsePURL(c.PURL)
	if err != nil {
		r.Failed = append(r.Failed, Note{Ref: ref, Reason: fmt.Sprintf("%s: %v", c.PURL, err)})
		return
	}
	out, ok := build(p, c, fallback)
	if !ok {
		r.Skipped = append(r.Skipped, Note{Ref: ref, Reason: fmt.Sprintf("no vexscan ecosystem for purl type %q", p.Type)})
		return
	}
	if out.Version == "" {
		// An unversioned component cannot be matched against an advisory's
		// affected range, and querying it anyway would return every advisory
		// ever filed against the name. trivy emits one of these for the module
		// being scanned, so this is ordinary rather than broken -- but it is
		// still a component that went unexamined, and it says so.
		r.Skipped = append(r.Skipped, Note{Ref: ref, Reason: "no version in the package URL, so no advisory range can be matched"})
		return
	}
	out.Ref = ref
	r.Components = append(r.Components, out)
}

// build maps one parsed purl onto the plugin that can evaluate it.
//
// The type-specific naming rules live here rather than in the parser, because
// each of them is a statement about how OSV keys that ecosystem and not about
// how a purl is written.
func build(p purl, c component, fallback osv.Release) (Component, bool) {
	out := Component{Version: p.Version, PURL: c.PURL}
	switch p.Type {
	case "deb", "rpm", "apk":
		out.PluginID = "os"
		out.Format = map[string]pkgdb.Format{"deb": pkgdb.FormatDeb, "rpm": pkgdb.FormatRPM, "apk": pkgdb.FormatAPK}[p.Type]
		out.Name = strings.ToLower(p.Name)
		out.Release = distro(p, fallback)
		out.Arch = p.Qualifiers["arch"]
		out.Source = source(p, c, out.Format)
		if out.Format == pkgdb.FormatRPM {
			out.Version, out.Epoch = rpmEVR(p.Version, p.Qualifiers["epoch"])
		}

	case "golang":
		out.PluginID = "golang"
		// OSV keys Go by the full module path, which is the namespace and the
		// name rejoined. Module paths are case-sensitive in the module system
		// but OSV records them lowercased, which is also what the purl
		// specification requires for this type.
		out.Name = strings.ToLower(join(p.Namespace, "/", p.Name))

	case "npm":
		out.PluginID = "npm"
		// A scope is a namespace, and OSV keys the scoped name whole.
		out.Name = strings.ToLower(p.Name)
		if p.Namespace != "" {
			out.Name = strings.ToLower(strings.TrimPrefix(p.Namespace, "@") + "/" + p.Name)
			out.Name = "@" + out.Name
		}

	case "pypi":
		out.PluginID = "pypi"
		out.Name = langdb.NormalizePyPI(p.Name)
		if p.Name != out.Name {
			// The spelling the document used, kept as a second query. OSV keys
			// PyPI normalized, but not every record was written that way.
			out.AltNames = []string{p.Name}
		}

	case "maven":
		out.PluginID = "maven"
		if p.Namespace == "" {
			return Component{}, false // a Maven artifact with no group is not resolvable
		}
		// OSV keys Java as "groupId:artifactId", case preserved.
		out.Name = p.Namespace + ":" + p.Name

	default:
		return Component{}, false
	}
	return out, true
}

// distro derives the distribution an OS component came from.
//
// The two producers measured disagree on the "distro" qualifier, and neither
// spelling is wrong. syft writes the full identity, "distro=debian-12"; trivy
// writes the same for Debian, "distro=debian-12.15", but for Alpine writes the
// version alone, "distro=3.19.9". So the qualifier supplies the version and
// the purl namespace ("alpine", "debian", "rhel") supplies the id when the
// qualifier does not carry one.
//
// The document-level operating-system component is the last resort: trivy emits
// one naming the distribution and its version, and on a bill whose purls carry
// no qualifier at all it is the only statement of which release this is.
func distro(p purl, fallback osv.Release) osv.Release {
	id, version := strings.ToLower(p.Namespace), ""
	if q := p.Qualifiers["distro"]; q != "" {
		qid, qver := splitDistro(q)
		if qid != "" {
			id = qid
		}
		version = qver
	}
	if version == "" {
		version = fallback.VersionID
	}
	if id == "" {
		id = fallback.ID
	}
	return osv.ReleaseFromDistro(id, version)
}

// splitDistro reads "debian-12", "opensuse-leap-15.5" or a bare "3.19.9".
//
// Split at the last dash, not the first: several distribution ids contain one
// ("opensuse-leap", "sle-micro") and no version ever does.
func splitDistro(q string) (id, version string) {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return "", ""
	}
	if isDigit(q[0]) {
		return "", q // a bare version, which is what trivy writes for Alpine
	}
	i := strings.LastIndexByte(q, '-')
	if i <= 0 || i == len(q)-1 || !isDigit(q[i+1]) {
		return q, "" // an id with no version in it
	}
	return q[:i], q[i+1:]
}

// source names the package an OS binary package was built from.
//
// Three spellings, because this is the field the producers agree on least and
// the one it costs the most to miss. Debian and Alpine file advisories against
// the source name and not the binary one, so a component that arrives without
// it is queried under a name OSV has no record for -- and no record reads as no
// vulnerability.
//
//	upstream=       the purl qualifier, which syft writes. For rpm it is the
//	                SOURCERPM filename, so it is parsed as one.
//	SrcName         trivy's property, which is the only place trivy puts it --
//	                its Alpine purls carry no upstream qualifier at all, and
//	                every Alpine advisory is filed against the origin.
//	syft:package:   syft's own property namespace, for the same field.
func source(p purl, c component, format pkgdb.Format) string {
	src := p.Qualifiers["upstream"]
	if src == "" {
		src = c.property("SrcName")
	}
	if src == "" {
		return ""
	}
	// syft writes rpm upstreams as "openssl-3.0.7-24.el9.src.rpm" and
	// sometimes as a bare "openssl"; SourceRPMName handles both.
	if format == pkgdb.FormatRPM && strings.HasSuffix(src, ".rpm") {
		src = pkgdb.SourceRPMName(src)
	}
	// An upstream qualifier may carry a version of its own ("openssl@3.0.11").
	src, _, _ = strings.Cut(src, "@")
	if strings.EqualFold(src, p.Name) {
		return "" // the same name is not a second name
	}
	return strings.ToLower(src)
}

// rpmEVR canonicalises an rpm version to the epoch-version-release form the
// Red Hat, Rocky and AlmaLinux records are written in, where the epoch is
// always present. A purl may carry it inside the version or beside it as a
// qualifier, or not at all -- and "3.0.7-24.el9" against a record written
// "1:3.0.7-24.el9" compares as an older version, which is a false positive that
// no amount of patching clears.
func rpmEVR(version, epochQualifier string) (string, int) {
	epoch := 0
	if head, tail, ok := strings.Cut(version, ":"); ok && allDigits(head) {
		epoch, _ = strconv.Atoi(head)
		version = tail
	} else if n, err := strconv.Atoi(strings.TrimSpace(epochQualifier)); err == nil && n >= 0 {
		epoch = n
	}
	return fmt.Sprintf("%d:%s", epoch, version), epoch
}

// osFallback finds the document-level statement of which operating system this
// is: CycloneDX's "operating-system" component type, which trivy emits as
// {name: "debian", version: "12.15"}.
//
// The first one wins. A bill describing two operating systems is not something
// this can scan coherently, and picking one silently is better than the
// alternative only because the per-component qualifier overrides it anyway.
func osFallback(cs []component) osv.Release {
	for _, c := range cs {
		if strings.EqualFold(c.Type, "operating-system") && c.Name != "" {
			return osv.ReleaseFromDistro(c.Name, c.Version)
		}
	}
	return osv.Release{}
}

// The CycloneDX subset that is read. Everything else in the schema -- hashes,
// licences, suppliers, the dependency graph -- describes the components rather
// than identifying them, and identifying them is the whole job here.
type document struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Components  []component `json:"components"`
}

type component struct {
	BOMRef  string `json:"bom-ref"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`

	Properties []property `json:"properties"`
	// Components nests. Producers mostly write a flat list, but the schema
	// allows a tree and a component hidden inside one must not go unscanned.
	Components []component `json:"components"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// property reads a producer-namespaced property by its trailing name, so
// "aquasecurity:trivy:SrcName" and "syft:package:SrcName" are both found by
// asking for "SrcName".
//
// Matching on the tail rather than the full key is deliberate: the namespaces
// are the producers' own and change with their versions, while the field names
// are what the field means.
func (c component) property(name string) string {
	for _, p := range c.Properties {
		if k := p.Name[strings.LastIndexByte(p.Name, ':')+1:]; strings.EqualFold(k, name) {
			return strings.TrimSpace(p.Value)
		}
	}
	return ""
}

// ref identifies a component in a message, preferring the document's own
// bom-ref. Producers set it to the purl when there is one, which is exactly
// what a reader needs to find the entry again.
func (c component) ref() string {
	switch {
	case c.BOMRef != "":
		return c.BOMRef
	case c.PURL != "":
		return c.PURL
	case c.Name != "" && c.Version != "":
		return c.Name + "@" + c.Version
	case c.Name != "":
		return c.Name
	}
	return "an unnamed component"
}

func (c component) typeOrUnstated() string {
	if c.Type == "" {
		return "unstated"
	}
	return c.Type
}

// flatten walks the nested component tree into one list, in document order.
func flatten(cs []component, out []component) []component {
	for _, c := range cs {
		out = append(out, c)
		out = flatten(c.Components, out)
	}
	return out
}

func join(a, sep, b string) string {
	if a == "" {
		return b
	}
	return a + sep + b
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}
