// Package distrofeed reads a distribution's own security feed -- Debian's
// security tracker, Red Hat's CSAF, Alpine's secdb -- and turns it into the
// same kind of published-vendor-statement the VEX Hub layer already consumes.
//
// A distro feed answers a question the reachability closure cannot: whether the
// vendor built the vulnerable code into this package at all. Debian routinely
// marks a CVE <not-affected> for a source package because the flaw is in a code
// path they do not compile, or fixed it in a point release whose version an
// upstream OSV range does not know about. Both are false positives on an image
// that a version scanner -- and vexscan's own OSV lookup -- will still flag.
//
// Like a VEX Hub statement, a feed statement is a *second opinion*, never a
// verdict. It is recorded as evidence and, when it is exculpatory, moves a row
// out of AFFECTED for the reader -- but it never changes a finding's Status. The
// local deterministic answer is what the scan concluded and stays that way, so a
// wrong or stale feed can only ever make the report noisier, never hide a real
// CVE. That asymmetry is the whole safety argument: this package may add
// reasons to look, and may add a vendor's reason to relax, but the clean
// verdict a build gates on still comes from local evidence alone.
package distrofeed

import "context"

// Status is a vendor feed's claim about one (package, CVE) pair, in OpenVEX's
// vocabulary so it drops straight into the same VEXStatement the hub layer uses.
//
// Deliberately the OpenVEX terms and not vexscan's own: a feed makes a vendor
// claim, which is a different kind of thing from a presence verdict and must
// never be confused with one in the output.
type Status string

const (
	// StatusNotAffected is the vendor saying the vulnerable code is not present
	// or not reachable in their build of this package. This is the false
	// positive a feed exists to clear.
	StatusNotAffected Status = "not_affected"
	// StatusFixed is the vendor saying a patch shipped. It only clears a
	// finding once the installed version is at or past the fix; see Statement.
	StatusFixed Status = "fixed"
	// StatusAffected is the vendor confirming the flaw. It is carried as
	// evidence but never relaxes anything.
	StatusAffected Status = "affected"
	// StatusUnderInvestigation is the vendor not having decided yet. Like
	// StatusAffected it clears nothing.
	StatusUnderInvestigation Status = "under_investigation"
)

// Exculpatory reports whether a status is one that lets a reader stop looking.
// Only these move a row out of AFFECTED, and only for a finding whose local
// verdict was not already clean.
func (s Status) Exculpatory() bool {
	return s == StatusNotAffected || s == StatusFixed
}

// Provider is one distribution's feed. It answers for the packages and
// advisories it recognizes and is silent about the rest.
type Provider interface {
	// Name is the feed's own name, e.g. "Debian Security Tracker", recorded as
	// the statement author.
	Name() string
	// Handles reports whether this provider speaks for a given os-release ID
	// ("debian", "ubuntu", "rhel", "alpine"). The overlay asks only providers
	// that do.
	Handles(osID string) bool
	// Lookup returns the vendor's statements about the queried packages. An
	// error means the feed could not be read: like an unreachable VEX Hub, that
	// is warned about but never fails the scan, because a feed that could not be
	// read only leaves rows in AFFECTED that a vendor might have cleared -- it
	// can never invent a clean the local analysis did not reach.
	Lookup(ctx context.Context, q Query) ([]Statement, error)
}

// Scorer is a vendor that publishes its own CVSS score per CVE, which
// --prefer-vendor favours over the OSV-derived rating.
//
// It is a separate interface from Provider because scoring is a different join
// from clearing. A Provider's verdict is about a package in a product, so it
// needs the image's os-release and CPE and only ever speaks to OS-package
// findings. A vendor's score is about the CVE itself -- SUSE rates CVE-2026-1234
// once, and that rating is as true of a Go module bundling the flaw as of an rpm
// -- so a Scorer is keyed by CVE alone and answers for a finding in any
// ecosystem. That is what lets --prefer-vendor rescore a GO-2026-xxxx finding,
// not just the OS layer.
type Scorer interface {
	// Name is the vendor's author string, matched against --prefer-vendor
	// case-insensitively, e.g. "SUSE Security Team".
	Name() string
	// Scores returns, for the CVEs it has a record of, an uppercase-CVE -> CVSS
	// v3 vector string map. A CVE the vendor did not score is absent rather than
	// present with an empty string. Ids that are not CVEs are ignored, so a
	// caller may pass a finding's whole alias set and let the Scorer pick the
	// CVEs out. An error is the feed being unreadable: like Lookup's, it is
	// warned about but never fatal, since a missing score only leaves the OSV
	// rating in place and can never invent a clean.
	Scores(ctx context.Context, cves []string) (map[string]string, error)
}

// Query is what the overlay knows about the image and asks a provider to speak
// to. A provider answers for the packages and advisories it recognizes and is
// silent about the rest.
type Query struct {
	// OSID is the os-release ID ("debian", "rhel", "alpine"). A provider that
	// does not Handle it is never asked.
	OSID string
	// Release is the distribution version as os-release reports it -- "12",
	// "9.4", "3.19" -- from which a provider derives whatever release key its
	// feed is indexed by (Debian's codename, Alpine's branch). Empty when the
	// scan could not read one, in which case a release-scoped feed must decline
	// to clear rather than guess.
	Release string
	// CPE is the image's CPE_NAME from os-release, e.g.
	// "cpe:/o:suse:sles:15:sp5". A CSAF feed joins on it exactly: it names the
	// vendor's product line and service pack unambiguously, where Release alone
	// ("15.5") cannot tell a SUSE Server from a Desktop. Empty when os-release
	// carried none, in which case a CPE-scoped feed declines rather than guess.
	CPE string
	// Packages are the OS-package findings to speak to, one per (package, CVE)
	// the scan is carrying.
	Packages []PkgRef
}

// PkgRef identifies one installed package the scan found an advisory against.
type PkgRef struct {
	// ID is an opaque token the caller uses to tie a returned Statement back to
	// the exact finding it was computed for. A provider echoes it on every
	// Statement it derives from this ref and interprets nothing about it.
	//
	// It is the fix for a real hazard: one source package fans out into several
	// binary packages filed under the same advisory, at versions that can
	// differ, so a statement matched only on (package, CVE) could be a "fixed"
	// verdict for one binary landing on another that is still vulnerable. The ID
	// keeps a verdict on the version it was actually decided against.
	ID string
	// Source is the source-package name the advisory is filed under, and Name
	// the installed binary package. A distro tracks security by source package,
	// so Source is the key; Name is carried for the record and for feeds that
	// are keyed by binary package instead.
	Source string
	Name   string
	// Version is the installed version, in the distribution's own version
	// grammar, used to decide whether a published fix has already landed.
	Version string
	// CVEs is every id this finding goes by -- its own plus the OSV aliases --
	// so a feed filed under a different one of them still matches.
	CVEs []string
}

// Statement is a provider's answer about one (package, CVE) pair, in the shape
// the analyze overlay copies into a VEXStatement.
type Statement struct {
	// RefID is the PkgRef.ID this statement was derived from. The overlay
	// attaches the statement to exactly that finding and no other, so a
	// version-specific verdict can never leak onto a sibling package at a
	// different version.
	RefID string
	// Distro is the feed's own name for the distribution, for the record.
	Distro string
	// Package is the package the claim is about, and CVE the advisory. CVE is
	// whichever of the query's ids the feed actually matched on.
	Package string
	CVE     string
	// Status is the vendor's claim. Only an Exculpatory one clears anything.
	Status Status
	// FixedVersion is the version the vendor's patch landed in, when Status is
	// StatusFixed. The overlay has already confirmed the installed version is
	// at or past it before treating the statement as exculpatory; it is carried
	// so the report can show what cleared the row.
	FixedVersion string
	// Justification is the vendor's stated reason, when the feed gives one
	// (Debian's nodsa note, a CSAF flag). Free text, shown to the reader.
	Justification string
	// Source is the feed URL the claim was read from, for auditing.
	Source string
	// Author is who published the feed, e.g. "Debian Security Tracker".
	Author string
}
