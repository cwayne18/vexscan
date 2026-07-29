package ecosystem

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// fakePlugin implements Plugin, and optionally either analyzer interface.
type fakePlugin struct {
	id   string
	ecos []string
}

func (p fakePlugin) ID() string           { return p.id }
func (p fakePlugin) Ecosystems() []string { return p.ecos }

type imagePlugin struct{ fakePlugin }

func (imagePlugin) DetectImage(context.Context, *target.Image) (bool, error) { return true, nil }
func (imagePlugin) InventoryImage(context.Context, *target.Image, []Subject) ([]Component, error) {
	return nil, nil
}
func (imagePlugin) AnalyzeImage(context.Context, *target.Image, []WorkItem) ([]Finding, error) {
	return nil, nil
}

type sourcePlugin struct{ fakePlugin }

func (sourcePlugin) DetectSource(context.Context, *target.Source) (bool, error) { return true, nil }
func (sourcePlugin) AnalyzeSource(context.Context, *target.Source, []Subject, []string) ([]Finding, error) {
	return nil, nil
}

type bothPlugin struct {
	imagePlugin
	sourcePlugin
}

func (b bothPlugin) ID() string           { return b.imagePlugin.id }
func (b bothPlugin) Ecosystems() []string { return b.imagePlugin.ecos }

func TestMatchEcosystem(t *testing.T) {
	os := fakePlugin{id: "os", ecos: []string{"Debian", "Ubuntu", "Alpine", "Red Hat"}}
	golang := fakePlugin{id: "golang", ecos: []string{"Go"}}

	tests := []struct {
		name     string
		plugin   Plugin
		selector string
		want     bool
	}{
		{"by id", golang, "golang", true},
		{"id is case-insensitive", golang, "GoLang", true},
		{"by ecosystem", golang, "Go", true},
		{"family matches", os, "debian", true},
		// The user names a family; detection produces a versioned ecosystem.
		// Both spellings have to select the same plugin.
		{"versioned selector matches family", os, "Debian:12", true},
		{"unversioned selector matches family", os, "alpine", true},
		{"no match", golang, "npm", false},
		{"empty selector never matches", golang, "", false},
		{"whitespace is trimmed", golang, "  golang  ", true},
		// "go" must not match "golang" by accident: a prefix match on the id
		// would make --ecosystem go silently select something else too.
		{"partial id does not match", golang, "gol", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchEcosystem(tt.plugin, tt.selector); got != tt.want {
				t.Errorf("MatchEcosystem(%s, %q) = %v, want %v", tt.plugin.ID(), tt.selector, got, tt.want)
			}
		})
	}
}

func TestRegistrySelect(t *testing.T) {
	golang := fakePlugin{id: "golang", ecos: []string{"Go"}}
	osp := fakePlugin{id: "os", ecos: []string{"Debian", "Alpine"}}
	pypi := fakePlugin{id: "pypi", ecos: []string{"PyPI"}}
	reg := NewRegistry(golang, osp, pypi)

	ids := func(ps []Plugin) []string {
		out := make([]string, 0, len(ps))
		for _, p := range ps {
			out = append(out, p.ID())
		}
		return out
	}

	t.Run("empty selects everything", func(t *testing.T) {
		got := ids(mustSelect(t, reg, nil))
		if want := []string{"golang", "os", "pypi"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("selection preserves registration order, not argument order", func(t *testing.T) {
		got := ids(mustSelect(t, reg, []string{"pypi", "golang"}))
		if want := []string{"golang", "pypi"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("duplicates collapse", func(t *testing.T) {
		got := ids(mustSelect(t, reg, []string{"os", "debian", "alpine"}))
		if want := []string{"os"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("blank selectors are ignored", func(t *testing.T) {
		got := ids(mustSelect(t, reg, []string{"golang", "  "}))
		if want := []string{"golang"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	// A typo must not scan nothing and report a clean image.
	t.Run("unknown selector is an error", func(t *testing.T) {
		_, err := reg.Select([]string{"golang", "gloang"})
		if err == nil {
			t.Fatal("expected an error for an unknown ecosystem")
		}
		for _, want := range []string{"gloang", "golang", "os", "pypi"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should mention %q", err, want)
			}
		}
	})
}

func TestAnalyzerFiltering(t *testing.T) {
	img := imagePlugin{fakePlugin{id: "os"}}
	src := sourcePlugin{fakePlugin{id: "repoonly"}}
	both := bothPlugin{imagePlugin{fakePlugin{id: "golang"}}, sourcePlugin{fakePlugin{id: "golang"}}}
	plain := fakePlugin{id: "inert"}

	plugins := []Plugin{img, src, both, plain}

	if got := len(ImageAnalyzers(plugins)); got != 2 {
		t.Errorf("ImageAnalyzers = %d, want 2", got)
	}
	if got := len(SourceAnalyzers(plugins)); got != 2 {
		t.Errorf("SourceAnalyzers = %d, want 2", got)
	}
}

func TestComponentKey(t *testing.T) {
	a := Component{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"}
	b := Component{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1", Locations: []string{"/usr/bin/openssl"}}
	c := Component{Ecosystem: "Debian:11", Name: "openssl", Version: "3.0.11-1"}

	// Locations must not affect the key: the same package found in two places
	// is still one OSV lookup.
	if a.Key() != b.Key() {
		t.Errorf("locations changed the key: %q vs %q", a.Key(), b.Key())
	}
	if a.Key() == c.Key() {
		t.Error("different ecosystems must not share a key")
	}
}

func TestFindingAffected(t *testing.T) {
	tests := []struct {
		status Status
		want   bool
	}{
		{StatusLinked, true},
		{StatusReachable, true},
		{StatusNotPresent, false},
		{StatusNotInPath, false},
		{StatusUndetermined, false},
	}
	for _, tt := range tests {
		if got := (Finding{Status: tt.status}).Affected(); got != tt.want {
			t.Errorf("Affected(%s) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

// TestFindingJSONShape pins the published output. Findings become VEX
// statements, so a field that quietly changes name or disappears breaks
// consumers downstream of this tool.
func TestFindingJSONShape(t *testing.T) {
	// A Go finding as the orchestrator publishes it: the v1 spellings are still
	// there, with the ecosystem-neutral names carrying the same values.
	t.Run("go finding", func(t *testing.T) {
		notStripped := false
		f := Finding{
			Ecosystem:   "golang",
			ID:          "CVE-2023-39325",
			Package:     "golang.org/x/net",
			Location:    "/usr/bin/app",
			PURL:        "pkg:golang/golang.org%2Fx%2Fnet@v0.17.0",
			Binary:      "/usr/bin/app",
			Module:      "golang.org/x/net",
			Version:     "v0.17.0",
			CVE:         "CVE-2023-39325",
			GoID:        "GO-2023-2102",
			Packages:    []string{"golang.org/x/net/http2"},
			Granularity: "package",
			Stripped:    &notStripped,
			Status:      StatusLinked,
			LLM:         &llm.Verdict{Exploitable: "likely", Confidence: "high", Rationale: "why"},
			// Reachability feeds the LLM prompt and must stay out of the
			// serialized form.
			Reachability: "linked (symbols retained; reachability not asserted)",
		}
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"ecosystem":"golang","id":"CVE-2023-39325","package":"golang.org/x/net","location":"/usr/bin/app","purl":"pkg:golang/golang.org%2Fx%2Fnet@v0.17.0","binary":"/usr/bin/app","module":"golang.org/x/net","version":"v0.17.0","cve":"CVE-2023-39325","go_id":"GO-2023-2102","packages":["golang.org/x/net/http2"],"granularity":"package","stripped":false,"status":"linked","llm":{"exploitable":"likely","confidence":"high","rationale":"why"}}`
		if string(b) != want {
			t.Errorf("\n got: %s\nwant: %s", b, want)
		}
	})

	// An OS finding omits stripped entirely rather than publishing false. The
	// question does not apply to a shared library, and a hardcoded false reads
	// as an answer.
	t.Run("an os finding omits the go-only fields", func(t *testing.T) {
		b, err := json.Marshal(Finding{
			Ecosystem: "os", ID: "c", Package: "m",
			Module: "m", Version: "v", CVE: "c", Status: StatusNotPresent,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"ecosystem":"os","id":"c","package":"m","module":"m","version":"v","cve":"c","status":"not_present"}`
		if string(b) != want {
			t.Errorf("\n got: %s\nwant: %s", b, want)
		}
	})

	t.Run("evidence appears only when present", func(t *testing.T) {
		f := Finding{ID: "c", Package: "m", Module: "m", Version: "v", CVE: "c", Status: StatusLinked, Evidence: []Evidence{
			{Origin: "elf-needed-closure", Detail: "reachable from /usr/bin/app"},
			{Origin: "elf-needed-closure", Detail: "dlopen present", Blocking: true},
		}}
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"id":"c","package":"m","module":"m","version":"v","cve":"c","status":"linked","evidence":[{"origin":"elf-needed-closure","detail":"reachable from /usr/bin/app"},{"origin":"elf-needed-closure","detail":"dlopen present","blocking":true}]}`
		if string(b) != want {
			t.Errorf("\n got: %s\nwant: %s", b, want)
		}
	})
}

func TestSubjectMatchesAll(t *testing.T) {
	if !(Subject{Ecosystem: "os"}).MatchesAll() {
		t.Error("an ecosystem-only subject selects everything in that ecosystem")
	}
	if (Subject{Name: "openssl"}).MatchesAll() {
		t.Error("a named subject does not select everything")
	}
	if (Subject{PURL: "pkg:deb/debian/openssl@3.0.11-1"}).MatchesAll() {
		t.Error("a purl subject does not select everything")
	}
}

func mustSelect(t *testing.T, r *Registry, selectors []string) []Plugin {
	t.Helper()
	ps, err := r.Select(selectors)
	if err != nil {
		t.Fatalf("Select(%v): %v", selectors, err)
	}
	return ps
}

func TestWorkItemRequests(t *testing.T) {
	advA := &osv.Advisory{ID: "GO-2023-0001", Aliases: []string{"CVE-2023-0001"}}
	advB := &osv.Advisory{ID: "GO-2023-0002", Aliases: []string{"CVE-2023-0002"}}
	advMap := map[string]*osv.Advisory{
		"GO-2023-0001":  advA,
		"CVE-2023-0001": advA,
		"GO-2023-0002":  advB,
		"CVE-2023-0002": advB,
	}

	t.Run("filter mode keeps unmapped ids so they report as undetermined", func(t *testing.T) {
		got := WorkItem{Advisories: advMap, Requested: []string{"CVE-2023-0001", "CVE-9999-9999"}}.Requests()
		want := []Request{
			{ID: "CVE-2023-0001", Advisory: advA},
			{ID: "CVE-9999-9999", Advisory: nil},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Requests() = %+v, want %+v", got, want)
		}
	})

	t.Run("all mode dedupes aliases to one request per advisory, sorted by id", func(t *testing.T) {
		got := WorkItem{Advisories: advMap}.Requests()
		want := []Request{
			{ID: "GO-2023-0001", Advisory: advA},
			{ID: "GO-2023-0002", Advisory: advB},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Requests() = %+v, want %+v", got, want)
		}
	})
}
