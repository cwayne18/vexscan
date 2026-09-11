// Package vexpr writes VEX documents recording the findings vexscan ruled out,
// laid out as a VEX Hub repository so they can be contributed to one.
//
// It is the write counterpart to internal/vex, which only reads. The split is
// deliberate and matches the invariant that package documents: nothing that
// reaches a verdict may also publish one. vexpr never touches a finding's
// status -- it reads the verdict local evidence already produced and serialises
// the ruled-out ones into the format a hub distributes, so the documents say
// exactly what the scan said and nothing the scan did not.
//
// Two serialisations are written, OpenVEX and CSAF-VEX, and which one is a
// caller's choice rather than something inferred: unlike reading, where the
// bytes say what they are, writing has to be told. Selection stops at the
// encoder. Everything before it -- which findings qualify, which the hub
// already answers, what a product is filed under -- is one code path producing
// Claims, because none of it differs between the two formats. What differs is
// how a claim is spelled, and that is the whole of what an encoder does.
//
// It writes to a directory and stops there. Getting those files into a hub is a
// pull request against somebody else's repository, and that is git's job and
// gh's job: they already handle forks, signing, branch protection and the
// review itself, and a hand-rolled API client handles none of them. Splitting
// there also puts a human in front of the diff, which for a statement that
// tells other people's scanners to stop reporting a vulnerability is the point
// rather than an inconvenience.
package vexpr

import (
	"errors"
	"fmt"
	"strings"
)

// Format is a VEX serialisation.
type Format string

// The formats this package writes.
const (
	FormatOpenVEX Format = "openvex"
	FormatCSAF    Format = "csaf"
)

// Formats is every value --vex-format accepts, in the order --help lists them.
var Formats = []Format{FormatOpenVEX, FormatCSAF}

// ParseFormat resolves a --vex-format value.
//
// The empty string is OpenVEX, which is both the older default and the one a
// hub is overwhelmingly likely to hold: changing what an unset flag means would
// silently change the shape of everybody's output.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(strings.TrimSpace(s))); f {
	case "":
		return FormatOpenVEX, nil
	case FormatOpenVEX, FormatCSAF:
		return f, nil
	default:
		return "", fmt.Errorf("vexpr: unknown VEX format %q; want %s", s, joinFormats())
	}
}

func joinFormats() string {
	out := make([]string, 0, len(Formats))
	for _, f := range Formats {
		out = append(out, string(f))
	}
	return strings.Join(out, " or ")
}

// Meta is what every document written in one run says about itself.
//
// Author and Timestamp are all OpenVEX asks for. CSAF asks for an identity --
// a publisher category and a namespace, both mandatory in the VEX profile --
// which is why the two extra fields exist and why they are only meaningful for
// that format.
type Meta struct {
	// Author is who is answerable for the claims. It has no default: an author
	// is a claim of responsibility for the assertion, and there is nobody but
	// the caller who can make it.
	Author string
	// Timestamp is the scan time, written on every claim so a re-run of the
	// same scan produces the same document.
	Timestamp string
	// PublisherCategory is the CSAF publisher category. Empty means "other".
	PublisherCategory string
	// PublisherNamespace is the URI identifying the publisher, required by CSAF
	// and unused by OpenVEX.
	PublisherNamespace string
}

// defaultPublisherCategory is what a caller who says nothing gets.
//
// "other" rather than "vendor": vexscan is run by whoever is scanning, who is
// usually a consumer of the image rather than the party that publishes it, and
// claiming to be the vendor of somebody else's artifact is a claim the tool has
// no business making on its user's behalf.
const defaultPublisherCategory = "other"

// publisherCategory is the category to write.
func (m Meta) publisherCategory() string {
	if m.PublisherCategory == "" {
		return defaultPublisherCategory
	}
	return m.PublisherCategory
}

// encoder is the write side of one serialisation.
//
// The interface is deliberately narrow. An encoder is handed the bytes the hub
// already publishes for a product and the claims to fold in, and returns the
// file to write -- it does not fetch, does not decide which claims qualify and
// does not know where the file lives beyond what it is called.
type encoder interface {
	// fileName is what a product's document is called inside the hub.
	fileName() string
	// merge folds the proposal's claims into the hub's existing document for
	// the product, or builds a fresh one when raw is empty.
	//
	// added is the vulnerabilities actually written. It is empty when the
	// document already answered every claim, and in that case content is
	// ignored and the file left exactly as published, so a re-run that changes
	// nothing produces no diff.
	merge(raw []byte, prop ProductProposal, meta Meta) (content []byte, added []string, err error)
}

// encoderFor returns the encoder for a format.
func encoderFor(f Format) (encoder, error) {
	switch f {
	case FormatOpenVEX:
		return openvexEncoder{}, nil
	case FormatCSAF:
		return csafEncoder{}, nil
	default:
		return nil, fmt.Errorf("vexpr: unknown VEX format %q", f)
	}
}

// errUnreadable is an encoder reporting that a document is there and it cannot
// decode it -- which is not the same as it not being there, and takes a
// different branch.
var errUnreadable = errors.New("vexpr: document could not be parsed")

// declineError is an encoder refusing to touch a document it understands
// perfectly well, with the reason a human needs to see.
//
// It is separate from errUnreadable because the two ask different things of the
// operator. An unreadable document is a bug report or a broken hub; a declined
// one is usually a flag away from working, and the reason has to say which.
type declineError struct{ reason string }

func (e *declineError) Error() string { return "vexpr: " + e.reason }

// decline builds a refusal. The reason is a fragment, not a sentence: the
// caller prefixes it with the product and location it applies to.
func decline(format string, a ...any) error {
	return &declineError{reason: fmt.Sprintf(format, a...)}
}
