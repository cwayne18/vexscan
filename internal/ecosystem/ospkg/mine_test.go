package ospkg

import (
	"context"
	"debug/elf"
	"strings"
	"sync"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// fakeSyms is an elfgraph.SymbolReader over a map. Which bytes of an object
// hold its dynamic symbols is internal/elfgraph's problem; what this file
// tests is what the plugin does once it has them.
type fakeSyms struct {
	mu    sync.Mutex
	tab   map[string]syms
	reads map[string]int
}

type syms struct{ defined, undefined []string }

func newSyms(tab map[string]syms) *fakeSyms {
	return &fakeSyms{tab: tab, reads: map[string]int{}}
}

func (f *fakeSyms) read(_ target.RootFS, name string) (defined, undefined []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads[name]++
	s, ok := f.tab[name]
	if !ok {
		return nil, nil, elfgraph.ErrNotELF
	}
	return s.defined, s.undefined, nil
}

// minedImage is the fixture every test here shares: an entrypoint that links
// libssl, and one package that owns it.
func minedImage(t *testing.T) *target.Image {
	t.Helper()
	return debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "libssl3", version: "3.0.11-1", source: "openssl",
			files: []string{"/usr/lib/libssl.so.3"}}},
		map[string]string{"/usr/bin/app": ""})
}

func minedELF() fakeELF {
	return fakeELF{
		"/usr/bin/app":         exe("libssl.so.3"),
		"/usr/lib/libssl.so.3": lib("libssl.so.3"),
	}
}

// mined runs the plugin over one advisory carrying one set of hints, and
// returns the finding for the openssl component.
func mined(t *testing.T, p *Plugin, img *target.Image, adv *osv.Advisory, hints *llm.Hints) ecosystem.Finding {
	t.Helper()
	ctx := context.Background()

	if ok, err := p.DetectImage(ctx, img); err != nil || !ok {
		t.Fatalf("DetectImage: %v %v", ok, err)
	}
	components, err := p.InventoryImage(ctx, img, []ecosystem.Subject{{Raw: ""}})
	if err != nil {
		t.Fatal(err)
	}

	items := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		w := ecosystem.WorkItem{
			Component:  c,
			Advisories: map[string]*osv.Advisory{adv.ID: adv},
			Requested:  []string{adv.ID},
		}
		if hints != nil {
			w.Hints = map[string]*llm.Hints{adv.ID: hints}
		}
		items = append(items, w)
	}

	findings, err := p.AnalyzeImage(ctx, img, items)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Module == "openssl" {
			return f
		}
	}
	t.Fatal("no finding for openssl")
	return ecosystem.Finding{}
}

// advisory is prose naming a function, which is the only place a mined symbol
// is allowed to have come from.
func advisory(text string) *osv.Advisory {
	return &osv.Advisory{ID: "CVE-2024-4741", Summary: "use after free", Details: text}
}

// evidenceFrom collects the details of every evidence line from one origin.
func evidenceFrom(f ecosystem.Finding, origin string) []string {
	var out []string
	for _, e := range f.Evidence {
		if e.Origin == origin {
			out = append(out, e.Detail)
		}
	}
	return out
}

// The row the whole mining layer exists for: the advisory names a function,
// the library is from the right software, and the function is not in this
// build.
func TestASymbolTheLibraryDoesNotExportIsNotPresent(t *testing.T) {
	p := New(Options{
		Mine:    true,
		ReadELF: minedELF().read,
		ReadSymbols: newSyms(map[string]syms{
			// The right namespace, without the function itself: this build
			// predates it, which is exactly the fact being asserted.
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free", "SSL_read"}},
			"/usr/bin/app":         {undefined: []string{"SSL_new"}},
		}).read,
	})

	f := mined(t, p, minedImage(t),
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status != ecosystem.StatusNotPresent {
		t.Errorf("status = %s, want not_present", f.Status)
	}
	if f.Justification != "vulnerable_code_not_present" || f.Method != MethodDynsymAbsent {
		t.Errorf("justification/method = %s/%s", f.Justification, f.Method)
	}
	why := strings.Join(evidenceFrom(f, MethodMined), " ")
	if !strings.Contains(why, "SSL_free_buffers") || !strings.Contains(why, "exported by nothing") {
		t.Errorf("evidence does not explain the conclusion: %q", why)
	}
}

// The containment rule's first gate. A symbol the advisory never mentions was
// invented, and its absence from a library means nothing whatsoever.
func TestAnInventedSymbolChangesNothing(t *testing.T) {
	p := New(Options{
		Mine:    true,
		ReadELF: minedELF().read,
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free"}},
		}).read,
	})

	f := mined(t, p, minedImage(t),
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_process_the_widget"}})

	if f.Status != ecosystem.StatusLinked || f.Method != MethodClosure {
		t.Errorf("status/method = %s/%s, want linked/%s", f.Status, f.Method, MethodClosure)
	}
	why := strings.Join(evidenceFrom(f, MethodMined), " ")
	if !strings.Contains(why, "invented rather than extracted") {
		t.Errorf("the rejection was not recorded: %q", why)
	}
}

// The second gate. The name really is in the advisory, but it belongs to other
// software -- advisories cross-reference each other constantly -- so this
// package failing to export it says nothing about this package.
func TestASymbolFromTheWrongSoftwareChangesNothing(t *testing.T) {
	p := New(Options{
		Mine:    true,
		ReadELF: minedELF().read,
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free"}},
		}).read,
	})

	f := mined(t, p, minedImage(t),
		advisory("Similar to the png_handle_iCCP flaw, a buffer is freed twice."),
		&llm.Hints{Symbols: []string{"png_handle_iCCP"}})

	if f.Status != ecosystem.StatusLinked || f.Method != MethodClosure {
		t.Errorf("status/method = %s/%s, want linked/%s", f.Status, f.Method, MethodClosure)
	}
	why := strings.Join(evidenceFrom(f, MethodMined), " ")
	if !strings.Contains(why, "shares a namespace") {
		t.Errorf("the rejection was not recorded: %q", why)
	}
}

// A validated symbol that is present, and reached. Mining has nothing to add
// beyond confirming the function is really in this build.
func TestAnExportedAndImportedSymbolStaysLinked(t *testing.T) {
	p := New(Options{
		Mine:    true,
		ReadELF: minedELF().read,
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free_buffers"}},
			"/usr/bin/app":         {undefined: []string{"SSL_free_buffers"}},
		}).read,
	})

	f := mined(t, p, minedImage(t),
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status != ecosystem.StatusLinked || f.Method != MethodClosure {
		t.Errorf("status/method = %s/%s, want linked/%s", f.Status, f.Method, MethodClosure)
	}
	if got := evidenceFrom(f, MethodImportAbsent); len(got) != 0 {
		t.Errorf("something claims nothing imports the symbol: %v", got)
	}
}

// Nobody imports it, which is worth recording and not worth acting on: the
// vulnerable function is usually called from inside the library that defines
// it, where no relocation records the call.
func TestAnUnimportedSymbolIsEvidenceOnlyByDefault(t *testing.T) {
	elfTab := newSyms(map[string]syms{
		"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free_buffers"}},
		"/usr/bin/app":         {undefined: []string{"SSL_new"}},
	})
	adv := advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice.")
	hints := &llm.Hints{Symbols: []string{"SSL_free_buffers"}}

	off := New(Options{Mine: true, ReadELF: minedELF().read, ReadSymbols: elfTab.read})
	f := mined(t, off, minedImage(t), adv, hints)
	if f.Status != ecosystem.StatusLinked || f.Method != MethodClosure {
		t.Errorf("status/method = %s/%s, want linked/%s", f.Status, f.Method, MethodClosure)
	}
	if got := evidenceFrom(f, MethodImportAbsent); len(got) != 1 {
		t.Errorf("the observation was not recorded: %v", got)
	}

	on := New(Options{Mine: true, TrustImportAbsence: true, ReadELF: minedELF().read, ReadSymbols: elfTab.read})
	f = mined(t, on, minedImage(t), adv, hints)
	if f.Status != ecosystem.StatusNotInPath {
		t.Errorf("status = %s, want not_in_execute_path", f.Status)
	}
	if f.Justification != "vulnerable_code_not_in_execute_path" || f.Method != MethodImportAbsent {
		t.Errorf("justification/method = %s/%s", f.Justification, f.Method)
	}
}

// A statically linked entrypoint carries its own copy of whatever it uses, so
// the package's export table is no longer an account of what is in the image.
func TestABlockingTaintPreventsTheDynsymConclusion(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "libssl3", version: "3.0.11-1", source: "openssl",
			files: []string{"/usr/lib/libssl.so.3"}}},
		map[string]string{"/usr/bin/app": ""})

	static := minedELF()
	static["/usr/bin/app"] = &elfgraph.Info{
		Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC,
	}

	p := New(Options{
		Mine:    true,
		ReadELF: static.read,
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free"}},
		}).read,
	})

	f := mined(t, p, img,
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %s, want linked", f.Status)
	}
	// The observation is still on the record; it is just not the answer.
	why := strings.Join(evidenceFrom(f, MethodMined), " ")
	if !strings.Contains(why, "exported by nothing") {
		t.Errorf("the observation was dropped rather than recorded: %q", why)
	}
}

// Without --mine-advisories nothing is asked and nothing is said: a run with
// mining off must produce exactly what it produced before mining existed.
func TestNoHintsMeansNoMinedEvidence(t *testing.T) {
	p := New(Options{ReadELF: minedELF().read})

	f := mined(t, p, minedImage(t),
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."), nil)

	if f.Status != ecosystem.StatusLinked || f.Method != MethodClosure {
		t.Errorf("status/method = %s/%s, want linked/%s", f.Status, f.Method, MethodClosure)
	}
	for _, e := range f.Evidence {
		if e.Origin == MethodMined || e.Origin == MethodImportAbsent {
			t.Errorf("mining was off but left evidence behind: %q", e.Detail)
		}
	}
}

// An advisory the model could read but found nothing in is different from one
// it was never shown, and the evidence has to say which happened.
func TestAnEmptyHintIsRecordedAsSuch(t *testing.T) {
	p := New(Options{Mine: true, ReadELF: minedELF().read})

	f := mined(t, p, minedImage(t),
		advisory("A remote attacker can crash the server."),
		&llm.Hints{Note: "the advisory names no function"})

	why := strings.Join(evidenceFrom(f, MethodMined), " ")
	if !strings.Contains(why, "no symbol could be mined") {
		t.Errorf("evidence = %q", why)
	}
}

// glibc exports thousands of symbols and the importer scan walks every
// reachable object, so the same table must not be parsed once per package.
func TestSymbolTablesAreReadOnce(t *testing.T) {
	tab := newSyms(map[string]syms{
		"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free"}},
		"/usr/bin/app":         {undefined: []string{"SSL_new"}},
	})
	p := New(Options{Mine: true, ReadELF: minedELF().read, ReadSymbols: tab.read})

	img := minedImage(t)
	adv := advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice.")
	hints := &llm.Hints{Symbols: []string{"SSL_free_buffers"}}
	for range 3 {
		mined(t, p, img, adv, hints)
	}

	if len(tab.reads) == 0 {
		t.Fatal("no symbol table was read at all, so this proves nothing")
	}
	for path, n := range tab.reads {
		if n != 1 {
			t.Errorf("%s was read %d times, want 1", path, n)
		}
	}
}

func TestNamespaceIsTheLibraryPrefix(t *testing.T) {
	for sym, want := range map[string]string{
		"SSL_free_buffers": "SSL_",
		"png_handle_iCCP":  "png_",
		"xmlParseDoc":      "xmlP",
		"_init":            "_ini", // no prefix before the underscore, so fall back
		"ab":               "",     // too short to namespace anything
		"abc":              "abc",
	} {
		if got := namespace(sym); got != want {
			t.Errorf("namespace(%q) = %q, want %q", sym, got, want)
		}
	}
}
