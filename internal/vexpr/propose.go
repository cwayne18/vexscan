package vexpr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// HubReader is the read side of a VEX hub: enough to merge into what a hub
// already publishes without holding a credential that could write to it.
//
// *vex.Hub satisfies it, and that is the point. The hub this merges against is
// the same hub --vexhub already read during the scan, over the same transport,
// with the same URL-or-directory handling -- there is no second notion of what
// a hub is, and no second way to reach one.
type HubReader interface {
	// IndexRaw is index.json exactly as published.
	IndexRaw() []byte
	// Raw returns one file's bytes by a location the index gave, or ok=false
	// when the hub has no such file.
	Raw(ctx context.Context, loc string) ([]byte, bool, error)
}

// Options configures a proposal.
type Options struct {
	// Hub is the hub to merge against, read-only. Nil starts from an empty
	// index, which is how a hub gets bootstrapped rather than added to.
	Hub HubReader
	// Format is the serialisation to write. The zero value is OpenVEX.
	Format Format
	// Aggregates are hub-relative paths to merged documents that receive every
	// product's claims in addition to the per-product documents -- the "master"
	// report some hubs publish for a CI run that scans a fleet. They are never
	// added to the index; see aggregate.go for why they are named rather than
	// discovered.
	Aggregates []string
	// Author is the author recorded on every statement written. It has no
	// default: an author is a claim of responsibility for the assertion, and
	// there is nobody but the caller who can make it.
	Author string
	// Timestamp is the scan time, used on every statement so a re-run of the
	// same scan produces the same document.
	Timestamp string
	// PublisherCategory and PublisherNamespace are the rest of the identity
	// CSAF requires of a publisher. They are ignored by, and rejected for, any
	// other format.
	PublisherCategory  string
	PublisherNamespace string
	// Logf receives progress lines. Nil discards them.
	Logf func(string, ...any)
}

// FileChange is one file to write, path relative to the output directory (and
// so also relative to the hub root, since the two share a layout).
type FileChange struct {
	Path    string
	Content []byte
}

// Plan is every file a proposal would write, computed but not yet on disk.
//
// Computing and writing are separate so the caller can report what is about to
// happen, and so the whole merge is testable without a filesystem.
type Plan struct {
	Changes  []FileChange
	Products []ProductChange
	// Statements counts the per-product documents only. An aggregate carries the
	// same claims a second time, and adding those in would report every
	// statement twice.
	Statements int
	// Aggregates is every merged document the plan adds to, reported separately
	// for that reason.
	Aggregates []AggregateChange
	// Skipped is how many ruled-out findings could not be written as a
	// matchable statement (no product, component or id).
	Skipped int
	// Unparsable is every hub document that exists but could not be decoded,
	// and was therefore left exactly as the hub published it. Reported rather
	// than counted silently: each one is a product this proposal says nothing
	// about, and a reader would otherwise have no way to tell that from a
	// product with nothing to say.
	Unparsable []string
	// Untouched is every hub document that decoded perfectly well and was still
	// left alone -- because it is in the other serialisation, or because it is
	// an advisory somebody else published. Separate from Unparsable because the
	// two ask different things of the operator, and the reason says which.
	Untouched []Untouched
}

// Untouched is one document the proposal deliberately left as published, and
// why.
type Untouched struct {
	Product  string
	Location string
	Reason   string
}

// ProductChange records, for the summary, which vulnerabilities were added to
// one product's document.
type ProductChange struct {
	Product string
	Vulns   []string
}

// AggregateChange records one merged document the plan adds to, and what it
// gained. Products is not always the same as the plan's own Products: an
// aggregate can lag the per-product tree, in which case it gains claims the
// product documents already carried.
type AggregateChange struct {
	Path       string
	Products   []ProductChange
	Statements int
}

// Empty reports whether the proposal would change nothing -- every ruled-out
// finding was already covered, or there were none to begin with.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// writes reports whether the plan already writes a path.
func (p *Plan) writes(path string) bool {
	for _, ch := range p.Changes {
		if ch.Path == path {
			return true
		}
	}
	return false
}

// Propose computes the documents that record this scan's ruled-out findings,
// merged into whatever the hub already publishes. It writes nothing; Write does.
func Propose(ctx context.Context, res *analyze.Result, opts Options) (*Plan, error) {
	return ProposeAll(ctx, []*analyze.Result{res}, opts)
}

// ProposeAll is Propose over a fleet: every result contributes to one plan.
//
// A batch scan is one contribution to a hub, not one per image. Each image is
// still its own product with its own document -- nothing is pooled that the hub
// would keep apart -- but reading the hub, resolving the index and merging any
// aggregate happen once for the run instead of once per target, which is the
// difference between a fleet scan being practical against a hub with a
// hundred-megabyte merged report and not.
func ProposeAll(ctx context.Context, results []*analyze.Result, opts Options) (*Plan, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	format, err := ParseFormat(string(opts.Format))
	if err != nil {
		return nil, err
	}
	// Resolved back onto the options so everything downstream sees the format
	// that is actually being written rather than the zero value standing for it.
	opts.Format = format
	meta := Meta{
		Author:             opts.Author,
		Timestamp:          opts.Timestamp,
		PublisherCategory:  opts.PublisherCategory,
		PublisherNamespace: opts.PublisherNamespace,
	}
	if err := checkMeta(format, meta); err != nil {
		return nil, err
	}
	enc, err := encoderFor(format)
	if err != nil {
		return nil, err
	}

	proposals, skipped := selectProposals(results, opts.Timestamp)
	if len(proposals) == 0 {
		return &Plan{Skipped: skipped}, nil
	}

	idx := newIndex()
	if opts.Hub != nil {
		parsed, err := parseIndex(opts.Hub.IndexRaw())
		if err != nil {
			return nil, err
		}
		idx = parsed
	}

	plan := &Plan{Skipped: skipped}
	indexTouched := false
	// eligible is the proposals an aggregate is built from: the ones whose
	// product could be filed in the hub at all. A purl too malformed to yield a
	// path is too malformed to write into a merged report either, so the two
	// stay in step rather than the aggregate quietly accepting what the tree
	// rejected.
	var eligible []ProductProposal
	for _, prop := range proposals {
		loc, idxChanged, err := idx.ensure(prop.Product, enc.fileName())
		if err != nil {
			logf("  ! vex-out: %s skipped: %v", prop.Product, err)
			continue
		}
		eligible = append(eligible, prop)

		raw, err := hubRaw(ctx, opts.Hub, loc)
		if err != nil {
			return nil, err
		}

		content, added, err := enc.merge(raw, prop, meta)
		switch {
		case errors.Is(err, errUnreadable):
			// The file is there and this cannot read it, which is not the same
			// as it not being there. Starting a fresh document would overwrite
			// whatever the file said: a statement vexscan cannot decode is
			// still one its publisher meant, and quite possibly one another
			// reader acts on. Leave it exactly as it is, and account for it.
			logf("  ! vex-out: %s: %s exists but could not be parsed; left untouched", prop.Product, loc)
			plan.Unparsable = append(plan.Unparsable, loc)
			continue
		case err != nil:
			var d *declineError
			if !errors.As(err, &d) {
				return nil, err
			}
			logf("  ! vex-out: %s: %s left untouched: %s", prop.Product, loc, d.reason)
			plan.Untouched = append(plan.Untouched, Untouched{
				Product: prop.Product, Location: loc, Reason: d.reason,
			})
			continue
		}
		if len(added) == 0 {
			// Nothing new for this product: leave the index untouched even if
			// ensure would have added a key (it only does so for a product with
			// no document, which always yields something added, so this is a
			// guard).
			continue
		}
		indexTouched = indexTouched || idxChanged

		sort.Strings(added)
		plan.Changes = append(plan.Changes, FileChange{Path: loc, Content: content})
		plan.Statements += len(added)
		plan.Products = append(plan.Products, ProductChange{Product: prop.Product, Vulns: added})
	}

	// After the per-product documents, so an aggregate naming a path this run
	// already writes is caught rather than silently overwriting it -- and before
	// the empty check, because an aggregate that lags the tree can have
	// something to add when no product document does.
	if err := planAggregates(ctx, plan, enc, eligible, opts, meta); err != nil {
		return nil, err
	}

	if len(plan.Changes) == 0 {
		return plan, nil
	}
	// A hub being bootstrapped has no index.json on disk yet, so it is written
	// even when no product was added to it -- otherwise the output would be a
	// tree of documents nothing points at.
	if indexTouched || opts.Hub == nil {
		idxContent, err := idx.marshal()
		if err != nil {
			return nil, err
		}
		plan.Changes = append(plan.Changes, FileChange{Path: "index.json", Content: idxContent})
	}
	return plan, nil
}

// checkMeta rejects a run that cannot produce a valid document, before the work
// rather than after it.
func checkMeta(f Format, m Meta) error {
	if m.Author == "" {
		return fmt.Errorf("vexpr: no author to record on the statements")
	}
	if f == FormatCSAF {
		return checkCSAFMeta(m)
	}
	if m.PublisherNamespace != "" || m.PublisherCategory != "" {
		return fmt.Errorf("vexpr: the publisher fields describe a CSAF publisher and %s carries none", f)
	}
	return nil
}

// hubRaw fetches the hub's existing document for a location, returning nil
// bytes when there is none -- which is the same thing an encoder does with a
// hub that was never given.
func hubRaw(ctx context.Context, hub HubReader, loc string) ([]byte, error) {
	if hub == nil {
		return nil, nil
	}
	raw, exists, err := hub.Raw(ctx, loc)
	if err != nil || !exists {
		return nil, err
	}
	return raw, nil
}

// Write puts the plan on disk under dir, creating parent directories as needed.
//
// dir may be a clone of the hub itself, which is the intended shape: merge
// against the clone, write back into it, and read the result as a git diff.
// Nothing is written outside dir -- the paths were vetted where they were built,
// and vetted again here, because this is the step that touches a filesystem and
// the check that matters is the one nearest the syscall.
func (p *Plan) Write(dir string) error {
	if dir == "" {
		return fmt.Errorf("vexpr: no output directory")
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("vexpr: %s: %w", dir, err)
	}
	for _, ch := range p.Changes {
		rel := filepath.FromSlash(ch.Path)
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("vexpr: refusing to write %q: not a path inside %s", ch.Path, dir)
		}
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("vexpr: %s: %w", ch.Path, err)
		}
		if err := os.WriteFile(full, ch.Content, 0o644); err != nil {
			return fmt.Errorf("vexpr: %s: %w", ch.Path, err)
		}
	}
	return nil
}
