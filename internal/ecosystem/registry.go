package ecosystem

import (
	"fmt"
	"sort"
	"strings"
)

// Registry holds the plugins available to a run.
type Registry struct {
	plugins []Plugin
}

// NewRegistry returns a registry over plugins, in the order given. Order is the
// order findings are produced in before the orchestrator's final sort, so it is
// worth keeping stable.
func NewRegistry(plugins ...Plugin) *Registry {
	return &Registry{plugins: append([]Plugin(nil), plugins...)}
}

// All returns every registered plugin.
func (r *Registry) All() []Plugin {
	return append([]Plugin(nil), r.plugins...)
}

// IDs returns every registered plugin's selector, sorted, for error messages
// and --help text.
func (r *Registry) IDs() []string {
	ids := make([]string, 0, len(r.plugins))
	for _, p := range r.plugins {
		ids = append(ids, p.ID())
	}
	sort.Strings(ids)
	return ids
}

// Select resolves --ecosystem selectors to plugins, preserving registration
// order and deduplicating. An empty selector list selects everything.
//
// An unrecognized selector is an error rather than an empty selection: silently
// scanning nothing because of a typo produces a clean-looking report, which is
// the one outcome this tool must never manufacture.
func (r *Registry) Select(selectors []string) ([]Plugin, error) {
	if len(selectors) == 0 {
		return r.All(), nil
	}

	var unknown []string
	keep := map[string]bool{}
	for _, sel := range selectors {
		sel = strings.TrimSpace(sel)
		if sel == "" {
			continue
		}
		matched := false
		for _, p := range r.plugins {
			if MatchEcosystem(p, sel) {
				keep[p.ID()] = true
				matched = true
			}
		}
		if !matched {
			unknown = append(unknown, sel)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown ecosystem %s (known: %s)",
			strings.Join(unknown, ", "), strings.Join(r.IDs(), ", "))
	}

	var out []Plugin
	for _, p := range r.plugins {
		if keep[p.ID()] {
			out = append(out, p)
		}
	}
	return out, nil
}

// ImageAnalyzers filters plugins to those that can analyze an image.
func ImageAnalyzers(plugins []Plugin) []ImageAnalyzer {
	var out []ImageAnalyzer
	for _, p := range plugins {
		if ia, ok := p.(ImageAnalyzer); ok {
			out = append(out, ia)
		}
	}
	return out
}

// SourceAnalyzers filters plugins to those that can analyze a source checkout.
func SourceAnalyzers(plugins []Plugin) []SourceAnalyzer {
	var out []SourceAnalyzer
	for _, p := range plugins {
		if sa, ok := p.(SourceAnalyzer); ok {
			out = append(out, sa)
		}
	}
	return out
}
