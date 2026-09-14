package vexpr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/cwayne18/vexscan/internal/csaf"
)

// An aggregate is a hub document that carries every product's statements in one
// file, so a CI run scanning a fleet of images can hand a scanner a single
// --vex instead of assembling one document per image. rancher/vexhub publishes
// three of them -- reports/rancher.openvex.json and two variants -- each a
// merge of everything under pkg/.
//
// Nothing in the VEX Repository specification describes them. index.json maps a
// product to one document, and none of rancher's aggregates appear in it: they
// are a convention that hub grew, sitting beside the spec rather than inside
// it. That is why an aggregate is named by the operator instead of discovered.
// A hub may publish several, none, or one under any name it likes, and from the
// outside a merged report is indistinguishable from an unrelated JSON file in
// the same tree -- so guessing would eventually mean writing VEX statements
// into somebody's changelog.
//
// It is also why an aggregate is never added to index.json. Indexing one would
// tell every reader of the hub that the merged report is *the* document for
// some single product, which is exactly what it is not.

// aggregator is an encoder that can also write an aggregate.
//
// Only OpenVEX implements it. CSAF has no shape for this: an advisory is
// identified by document.tracking.id, revised as a unit and attributed to one
// publisher, so a single advisory holding every product's claims would be
// claiming to be the authority on all of them at once. Declining is better than
// inventing a mapping no hub has asked for.
type aggregator interface {
	mergeAggregate(raw []byte, props []ProductProposal, meta Meta) ([]byte, []ProductChange, error)
}

// mergeAggregate folds every proposal into one document.
//
// It is merge's counterpart for a file that is not about one product, and the
// two share everything below the signature: the same dedupe, the same
// byte-preserving round-trip, the same refusal to touch what it cannot read.
func (e openvexEncoder) mergeAggregate(raw []byte, props []ProductProposal, meta Meta) ([]byte, []ProductChange, error) {
	doc := NewDoc(meta.Author, meta.Timestamp)
	if len(bytes.TrimSpace(raw)) > 0 {
		switch {
		case isLFSPointer(raw):
			return nil, nil, decline("it is an unfetched Git LFS pointer, not the document it stands for; " +
				"fetch it (git lfs pull --include=<path>) and re-run")
		case csaf.Looks(raw):
			return nil, nil, decline("it is a CSAF advisory; an aggregate is a merged OpenVEX report")
		}
		parsed, ok := ParseDoc(raw)
		if !ok {
			return nil, nil, errUnreadable
		}
		doc = parsed
	}

	changes := mergeClaims(doc, props, meta)
	if len(changes) == 0 {
		return nil, nil, nil
	}
	content, err := doc.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return content, changes, nil
}

// lfsPointerMax is the size the Git LFS specification caps a pointer file at,
// and so as much of a file as this has to look at to recognise one.
const lfsPointerMax = 1024

// isLFSPointer reports whether these bytes are a Git LFS pointer rather than
// the document it stands for.
//
// This is the difference between a 121 MB merged report and the 133 bytes that
// name it. A clone made without git-lfs installed holds the latter, and so does
// one made with GIT_LFS_SKIP_SMUDGE=1 -- which is the sensible way to clone a
// hub carrying hundreds of megabytes of objects this flow has no use for.
//
// A pointer is not JSON, so it would be refused as unreadable either way. The
// check exists for the message: "could not be parsed" sends someone hunting for
// malformed JSON, when what they need is one git command. Getting this wrong in
// the other direction -- writing a small document over the pointer -- would put
// a pull request in front of a maintainer that silently replaces their hub's
// merged report with a fraction of its contents.
func isLFSPointer(b []byte) bool {
	if len(b) > lfsPointerMax {
		b = b[:lfsPointerMax]
	}
	return bytes.HasPrefix(b, []byte("version https://git-lfs.github.com/spec/v1")) &&
		bytes.Contains(b, []byte("\noid sha256:"))
}

// checkAggregatePath rejects a --vex-merge-into value that could not name a
// document inside the hub.
//
// Unlike a product location this is not derived from anything -- the operator
// typed it -- but it still becomes a path written into a clone of somebody
// else's repository, so it gets the same treatment: no absolute paths, no
// climbing out, and not the index, which is the one file in a hub that is
// certainly not a VEX document.
func checkAggregatePath(p string) error {
	switch {
	case strings.TrimSpace(p) == "":
		return fmt.Errorf("vexpr: empty --vex-merge-into path")
	case p != path.Clean(p):
		return fmt.Errorf("vexpr: --vex-merge-into %q is not a clean path (did you mean %q?)", p, path.Clean(p))
	case strings.HasPrefix(p, "/"):
		return fmt.Errorf("vexpr: --vex-merge-into %q is absolute; it must be a path inside the hub", p)
	case p == "index.json":
		return fmt.Errorf("vexpr: --vex-merge-into index.json is the hub's index, not a VEX document")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("vexpr: --vex-merge-into %q climbs out of the hub", p)
		}
	}
	return nil
}

// planAggregates folds the run's proposals into each aggregate the caller
// named, appending one change per aggregate that gained something.
//
// Every eligible proposal goes into every aggregate, including ones whose own
// per-product document was declined or unreadable. The two files are
// independent: a product filed under the other serialisation is a reason not to
// touch that product's document, not a reason to withhold the claim from a
// merged report this run can write perfectly well -- and the merged report is
// the one a CI run actually reads.
func planAggregates(ctx context.Context, plan *Plan, enc encoder, props []ProductProposal, opts Options, meta Meta) error {
	if len(opts.Aggregates) == 0 || len(props) == 0 {
		return nil
	}
	agg, ok := enc.(aggregator)
	if !ok {
		return fmt.Errorf("vexpr: --vex-merge-into cannot be written as %s; an aggregate is a merged OpenVEX report", opts.Format)
	}

	for _, p := range dedupeStrings(opts.Aggregates) {
		if err := checkAggregatePath(p); err != nil {
			return err
		}
		// A path this run is already writing as some product's document would
		// otherwise be written twice, and the second write -- built from the
		// hub's original bytes -- would drop the first one's statements.
		if plan.writes(p) {
			return fmt.Errorf("vexpr: --vex-merge-into %s: this run already writes that path as a product's document", p)
		}

		raw, err := hubRaw(ctx, opts.Hub, p)
		if err != nil {
			return err
		}
		if opts.Hub != nil && len(bytes.TrimSpace(raw)) == 0 {
			// A hub was given and publishes nothing there. Creating the file
			// would be the wrong guess far more often than the right one: an
			// aggregate is an existing convention of an existing hub, so the
			// likeliest reason it is missing is a mistyped path -- and the
			// result of guessing is a pull request adding a file nobody asked
			// for. With no hub there is nothing to be wrong about, and the
			// aggregate is created alongside the tree being bootstrapped.
			return fmt.Errorf("vexpr: --vex-merge-into %s: the hub publishes no document there", p)
		}

		// An aggregate that cannot be written fails the run, where a product
		// document that cannot be written is reported and stepped over.
		//
		// The difference is who chose the file. A product's location comes from
		// the hub's index, and one unreadable document among a thousand is no
		// reason to withhold the other nine hundred and ninety-nine. An
		// aggregate was named on the command line, because a contribution to
		// this hub is not usable without it -- that is the entire reason the
		// flag exists. Carrying on would produce exactly the pull request the
		// operator was trying to avoid: per-product documents updated, the
		// merged report everything actually reads left behind, and a warning
		// somewhere above the diff.
		//
		// Nothing has been written at this point -- Write runs on the finished
		// plan -- so failing here leaves the tree untouched rather than half
		// done.
		content, changes, err := agg.mergeAggregate(raw, props, meta)
		switch {
		case errors.Is(err, errUnreadable):
			return fmt.Errorf("vexpr: --vex-merge-into %s: exists but could not be parsed as an OpenVEX document", p)
		case err != nil:
			var d *declineError
			if !errors.As(err, &d) {
				return err
			}
			return fmt.Errorf("vexpr: --vex-merge-into %s: %s", p, d.reason)
		}
		if len(changes) == 0 {
			continue
		}

		n := 0
		for _, c := range changes {
			n += len(c.Vulns)
		}
		plan.Changes = append(plan.Changes, FileChange{Path: p, Content: content})
		plan.Aggregates = append(plan.Aggregates, AggregateChange{Path: p, Products: changes, Statements: n})
	}
	return nil
}

// dedupeStrings drops repeats while keeping the first occurrence's position, so
// naming the same aggregate twice is not an error and not two writes.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
