package pypi

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
	// MethodLockfile: the checkout's lock files were read and nothing else.
	MethodLockfile = "pypi-lockfile"
	// MethodDevOnly: the lock file declares the package in a development group.
	MethodDevOnly = "pypi-dev-only"
)

// lockmode is the repo-mode analyzer, configured for PyPI.
func (p *Plugin) lock() lockmode.Analyzer {
	return lockmode.Analyzer{Config: lockmode.Config{
		Owner:     p,
		Ecosystem: "PyPI",
		Format:    lockfile.FormatPyPI,
		Prefix:    "pypi",
		PURLType:  "pypi",
		Normalize: langdb.NormalizePyPI,
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
