package analyze

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/ecosystem/golang"
	"github.com/cwayne18/vexscan/internal/ecosystem/ospkg"
	"github.com/cwayne18/vexscan/internal/osv"
)

const okHints = `{"symbols":["SSL_free_buffers"],"sonames":["libssl.so.3"],"files":[],"note":""}`

// workItems is two packages sharing an advisory, which is the shape a
// whole-image scan produces.
func minableItems() []ecosystem.WorkItem {
	adv := &osv.Advisory{
		ID:      "CVE-2024-4741",
		Summary: "use after free",
		Details: "A flaw in SSL_free_buffers allows a buffer to be freed twice.",
	}
	return []ecosystem.WorkItem{
		{Component: ecosystem.Component{Name: "openssl"}, Advisories: map[string]*osv.Advisory{adv.ID: adv}},
		{Component: ecosystem.Component{Name: "curl"}, Advisories: map[string]*osv.Advisory{adv.ID: adv}},
	}
}

func TestMinerAttachesHintsToEveryWorkItem(t *testing.T) {
	client, rec := newLLMServer(t, http.StatusOK, okHints)
	m := newMiner(Options{UseLLM: true, MineAdvisories: true, Logf: func(string, ...any) {}}, client)

	items := minableItems()
	m.apply(context.Background(), "os", items)

	for _, w := range items {
		h := w.Hints["CVE-2024-4741"]
		if h == nil {
			t.Fatalf("%s got no hints", w.Component.Name)
		}
		if len(h.Symbols) != 1 || h.Symbols[0] != "SSL_free_buffers" {
			t.Errorf("%s: symbols = %v", w.Component.Name, h.Symbols)
		}
	}

	// One question per package, not one per advisory: the same advisory says
	// different things about different packages, and the cache is keyed to
	// match.
	if n := len(rec.questions()); n != 2 {
		t.Errorf("asked %d questions, want 2: %v", n, rec.questions())
	}
	for _, q := range rec.questions() {
		if !strings.Contains(q, "SSL_free_buffers") {
			t.Errorf("the advisory text was not sent: %q", q)
		}
	}
}

// Mining is opt-in twice over: --llm supplies the client, --mine-advisories
// decides whether to spend it. Neither alone does anything.
func TestMiningIsOptIn(t *testing.T) {
	client, rec := newLLMServer(t, http.StatusOK, okHints)

	for name, opts := range map[string]Options{
		"llm without mining": {UseLLM: true},
		"mining without llm": {MineAdvisories: true},
	} {
		items := minableItems()
		newMiner(opts, nil).apply(context.Background(), "os", items)
		newMiner(opts, client).apply(context.Background(), "os", items)
		for _, w := range items {
			if w.Hints != nil {
				t.Errorf("%s: hints were attached anyway: %v", name, w.Hints)
			}
		}
	}
	if n := len(rec.questions()); n != 0 {
		t.Errorf("the model was asked %d questions with mining off", n)
	}
}

// A model that will not answer must cost the run its leads and nothing else.
func TestMinerKeepsGoingWhenTheModelFails(t *testing.T) {
	client, _ := newLLMServer(t, http.StatusBadRequest, "")
	var logged int
	m := newMiner(Options{UseLLM: true, MineAdvisories: true,
		Logf: func(string, ...any) { logged++ }}, client)

	items := minableItems()
	m.apply(context.Background(), "os", items)

	for _, w := range items {
		if w.Hints != nil {
			t.Errorf("%s: hints survived a failed mine: %v", w.Component.Name, w.Hints)
		}
	}
	if logged == 0 {
		t.Error("the failure was silent")
	}
}

// Only a plugin that will validate what it receives gets mined for. The Go
// plugin has pclntab, so paying for symbol guesses on its behalf would buy an
// answer it discards.
func TestOnlyPluginsThatValidateHintsAreMined(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    ecosystem.Plugin
		want bool
	}{
		{"golang", golang.New(golang.Options{}), false},
		{"os without --mine-advisories", ospkg.New(ospkg.Options{}), false},
		{"os with --mine-advisories", ospkg.New(ospkg.Options{Mine: true}), true},
	} {
		if got := ecosystem.UsesHints(tc.p); got != tc.want {
			t.Errorf("%s: UsesHints = %v, want %v", tc.name, got, tc.want)
		}
	}
}
