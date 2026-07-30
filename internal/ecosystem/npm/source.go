package npm

import (
	"context"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/lockfile"
	"github.com/cwayne18/vexscan/internal/lockmode"
	"github.com/cwayne18/vexscan/internal/target"
)

// Methods for repo mode. See lockmode for what each one asserts.
const (
	// MethodLockfile: package-lock.json was read and nothing else.
	MethodLockfile = "npm-lockfile"
	// MethodDevOnly: the lock file marks the entry "dev": true, so `npm ci
	// --omit=dev` does not install it.
	MethodDevOnly = "npm-dev-only"
)

// lock is the repo-mode analyzer, configured for npm.
func (p *Plugin) lock() lockmode.Analyzer {
	return lockmode.Analyzer{Config: lockmode.Config{
		Owner:     p,
		Ecosystem: "npm",
		Format:    lockfile.FormatNPM,
		Prefix:    "npm",
		PURLType:  "npm",
		// No normalization: npm keys a package on its name verbatim, and OSV
		// follows. "@babel/core" and "babel-core" are different packages, and
		// case is significant to the registry even where it is not to a human.
		Normalize: func(s string) string { return s },
		PURL: func(name, version string) string {
			return purl(langdb.Package{Name: name, Version: version})
		},
		Logf: p.Logf,
	}}
}

// DetectSource implements ecosystem.InventorySourceAnalyzer.
func (p *Plugin) DetectSource(ctx context.Context, src *target.Source) (bool, error) {
	return p.lock().Detect(ctx, src)
}

// InventorySource implements ecosystem.InventorySourceAnalyzer.
func (p *Plugin) InventorySource(ctx context.Context, src *target.Source, subjects []ecosystem.Subject) ([]ecosystem.Component, error) {
	return p.lock().Inventory(ctx, src, subjects)
}

// AnalyzeSource implements ecosystem.InventorySourceAnalyzer.
//
// The signature deliberately differs from ecosystem.SourceAnalyzer's method of
// the same name, so this plugin cannot accidentally satisfy both. A lock file
// carries no advisories, so the orchestrator has to resolve them in between.
func (p *Plugin) AnalyzeSource(ctx context.Context, src *target.Source, items []ecosystem.WorkItem) ([]ecosystem.Finding, error) {
	return p.lock().Analyze(ctx, src, items)
}
