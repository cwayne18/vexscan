package vexpr

import (
	"context"
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
	// Author is the OpenVEX author recorded on every statement written. It has
	// no default: an author is a claim of responsibility for the assertion, and
	// there is nobody but the caller who can make it.
	Author string
	// Timestamp is the scan time, used on every statement so a re-run of the
	// same scan produces the same document.
	Timestamp string
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
	Changes    []FileChange
	Products   []ProductChange
	Statements int
	// Skipped is how many ruled-out findings could not be written as a
	// matchable statement (no product, component or id).
	Skipped int
	// Unparsable is every hub document that exists but could not be decoded,
	// and was therefore left exactly as the hub published it. Reported rather
	// than counted silently: each one is a product this proposal says nothing
	// about, and a reader would otherwise have no way to tell that from a
	// product with nothing to say.
	Unparsable []string
}

// ProductChange records, for the summary, which vulnerabilities were added to
// one product's document.
type ProductChange struct {
	Product string
	Vulns   []string
}

// Empty reports whether the proposal would change nothing -- every ruled-out
// finding was already covered, or there were none to begin with.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// Propose computes the documents that record this scan's ruled-out findings,
// merged into whatever the hub already publishes. It writes nothing; Write does.
func Propose(ctx context.Context, res *analyze.Result, opts Options) (*Plan, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if opts.Author == "" {
		return nil, fmt.Errorf("vexpr: no author to record on the statements")
	}

	proposals, skipped := selectProposals(res, opts.Timestamp)
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

	var (
		changes      []FileChange
		productChgs  []ProductChange
		unparsable   []string
		stmtTotal    int
		indexTouched bool
	)
	for _, prop := range proposals {
		loc, idxChanged, err := idx.ensure(prop.Product)
		if err != nil {
			logf("  ! vex-out: %s skipped: %v", prop.Product, err)
			continue
		}

		doc, ok, err := readDoc(ctx, opts.Hub, loc)
		if err != nil {
			return nil, err
		}
		if !ok {
			// The file is there and this cannot read it, which is not the same
			// as it not being there. Starting a fresh document would overwrite
			// whatever the file said: a statement vexscan cannot decode is
			// still one its publisher meant, and quite possibly one another
			// reader acts on. Leave it exactly as it is, and account for it.
			logf("  ! vex-out: %s: %s exists but could not be parsed; left untouched", prop.Product, loc)
			unparsable = append(unparsable, loc)
			continue
		}
		if doc == nil {
			doc = NewDoc(opts.Author, opts.Timestamp)
		}

		before := len(doc.Statements)
		added := mergeStatements(doc, prop, opts.Author, opts.Timestamp)
		if added == 0 {
			// Nothing new for this product: leave the index untouched even if
			// ensure would have added a key (it only does so for a product with
			// no document, which always yields added > 0, so this is a guard).
			continue
		}
		indexTouched = indexTouched || idxChanged

		content, err := doc.Marshal()
		if err != nil {
			return nil, err
		}
		changes = append(changes, FileChange{Path: loc, Content: content})
		stmtTotal += added
		productChgs = append(productChgs, ProductChange{
			Product: prop.Product,
			Vulns:   addedVulns(doc.Statements[before:]),
		})
	}

	if len(changes) == 0 {
		return &Plan{Skipped: skipped, Unparsable: unparsable}, nil
	}
	// A hub being bootstrapped has no index.json on disk yet, so it is written
	// even when no product was added to it -- otherwise the output would be a
	// tree of documents nothing points at.
	if indexTouched || opts.Hub == nil {
		idxContent, err := idx.marshal()
		if err != nil {
			return nil, err
		}
		changes = append(changes, FileChange{Path: "index.json", Content: idxContent})
	}

	return &Plan{
		Changes:    changes,
		Products:   productChgs,
		Statements: stmtTotal,
		Skipped:    skipped,
		Unparsable: unparsable,
	}, nil
}

// readDoc fetches and decodes the hub's existing document for a location.
//
// The three outcomes are distinct and the caller acts differently on each: a
// decoded document to merge into (doc != nil, ok), no document there at all
// (nil, ok), and a document that exists but does not decode (nil, !ok).
func readDoc(ctx context.Context, hub HubReader, loc string) (*Doc, bool, error) {
	if hub == nil {
		return nil, true, nil
	}
	raw, exists, err := hub.Raw(ctx, loc)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, true, nil
	}
	doc, ok := ParseDoc(raw)
	if !ok {
		return nil, false, nil
	}
	return doc, true, nil
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

// addedVulns lists the vulnerability names of a slice of statements, for the
// summary.
func addedVulns(sts []Statement) []string {
	out := make([]string, 0, len(sts))
	for _, s := range sts {
		out = append(out, s.Vulnerability.Name)
	}
	sort.Strings(out)
	return out
}
