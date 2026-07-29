package analyze

import (
	"context"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
)

// miner fills work items with the symbols, sonames and filenames an advisory's
// prose names, for the ecosystems whose OSV records carry nothing checkable.
//
// It lives beside the LLM overlay rather than inside a plugin for the same
// reason the overlay does: the model must not be able to reach a status on its
// own. What it produces here is a *lead*, and the plugin that receives it is
// required to validate the lead against the image before letting it matter.
// See ospkg.checkSymbols for the two gates that enforce that.
//
// A nil miner is a working miner that mines nothing, which is what --llm
// without --mine-advisories gets you.
type miner struct {
	client *llm.Client
	logf   func(string, ...any)
}

// newMiner returns nil unless mining was asked for and there is a client.
//
// Mining costs one model round trip per (advisory, package) pair on a cold
// cache, which on a whole-image scan is hundreds. That is why it is opt-in
// rather than implied by --llm.
func newMiner(opts Options, client *llm.Client) *miner {
	if !opts.MineAdvisories || !opts.UseLLM || client == nil {
		return nil
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &miner{client: client, logf: logf}
}

// apply mines every advisory in every work item, in place.
//
// Nothing here is fatal. A hint that could not be obtained leaves the work
// item exactly as a run without --mine-advisories would, and the plugin
// reports that it had no hints to work with rather than pretending it did.
func (m *miner) apply(ctx context.Context, id string, items []ecosystem.WorkItem) {
	if m == nil {
		return
	}
	mined, failed := 0, 0
	for i := range items {
		w := &items[i]
		for advID, adv := range w.Advisories {
			if adv == nil {
				continue
			}
			h, err := m.mine(ctx, id, w.Component.Name, advID, adv)
			if err != nil {
				failed++
				m.logf("  ! could not mine %s: %v", advID, err)
				continue
			}
			if w.Hints == nil {
				w.Hints = map[string]*llm.Hints{}
			}
			w.Hints[advID] = h
			mined++
		}
	}
	if mined+failed > 0 {
		m.logf("  mined %d advisor%s for %s (%d failed)", mined, plural(mined), id, failed)
	}
}

func (m *miner) mine(ctx context.Context, eco, pkg, id string, adv *osv.Advisory) (*llm.Hints, error) {
	return m.client.Mine(ctx, llm.MineRequest{
		ID:        id,
		Ecosystem: eco,
		Package:   pkg,
		Summary:   adv.Summary,
		Details:   adv.Details,
	})
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
