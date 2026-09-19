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

// fakeStatic is a staticReader over a map, so the cgo static-symbol discharge
// can be exercised against a chosen symbol table without compiling a cgo binary
// that carries one. An entry the map does not name reads as stripped, which is
// the conservative default an unreadable entrypoint would take.
type fakeStatic map[string]staticEntry

func (f fakeStatic) read(_ target.RootFS, path string) (defined []string, stripped, cgo bool, err error) {
	e, ok := f[path]
	if !ok {
		return nil, true, false, nil
	}
	return e.defined, e.stripped, e.cgo, e.err
}

// TestCgoStaticSymbolDischarge is the gap #24 left: a cgo, statically linked
// entrypoint that the CGO_ENABLED=0 discharge cannot touch, cleared instead by
// proof from its own symbol table.
//
// The fixture is a static entrypoint that references nothing, and a libssl the
// package installs that sits unreferenced on disk -- the exact shape that makes
// the static-elf taint block. The advisory names SSL_free_buffers, and libssl
// exports the SSL_ namespace, so the symbol validates. Whether the taint is
// discharged then turns entirely on what the entrypoint's own table holds.
func TestCgoStaticSymbolDischarge(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "libssl3", version: "3.0.11-1", source: "openssl",
			files: []string{"/usr/lib/libssl.so.3"}}},
		map[string]string{"/usr/bin/app": ""})

	// A static entrypoint: ET_EXEC with no PT_INTERP and nothing needed, so the
	// closure sees it carry its libraries inside itself and libssl on disk goes
	// unreferenced.
	staticExe := &elfgraph.Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC}
	elves := fakeELF{
		"/usr/bin/app":         staticExe,
		"/usr/lib/libssl.so.3": lib("libssl.so.3"),
	}

	for _, tc := range []struct {
		name       string
		entry      staticEntry
		wantStatus ecosystem.Status
		discharge  bool
	}{
		// The namespace is linked in (SSL_new) and the vulnerable function is
		// not, so the build provably lacks it: discharged, and the package's
		// own tables not exporting it then reads as not_present.
		{"namespace present, symbol absent", staticEntry{defined: []string{"SSL_new", "SSL_read"}, cgo: true}, ecosystem.StatusNotPresent, true},
		// The vulnerable function is right there in the table: the code is
		// linked in, so nothing is discharged.
		{"vulnerable symbol present", staticEntry{defined: []string{"SSL_new", "SSL_free_buffers"}, cgo: true}, ecosystem.StatusLinked, false},
		// No symbol table to reason over. Absence from a table that was thrown
		// away is not absence from the binary. The symbols here are the ones
		// that would discharge if the table were whole, so the stripped flag is
		// the only thing left that can decline.
		{"stripped", staticEntry{defined: []string{"SSL_new", "SSL_read"}, stripped: true, cgo: true}, ecosystem.StatusLinked, false},
		// The family is nowhere in the table, so the binary does not visibly
		// use openssl at all -- which is not proof it is absent, only that it is
		// invisible. Stays blocking.
		{"namespace absent entirely", staticEntry{defined: []string{"main.main", "runtime.main"}, cgo: true}, ecosystem.StatusLinked, false},
		// Not known to be a cgo build, so this discharge does not apply -- the
		// CGO_ENABLED=0 path is the only other one, and it already ran.
		{"cgo unknown", staticEntry{defined: []string{"SSL_new"}, cgo: false}, ecosystem.StatusLinked, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Options{
				Mine:    true,
				ReadELF: elves.read,
				ReadSymbols: newSyms(map[string]syms{
					"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free", "SSL_read"}},
				}).read,
				readStatic: fakeStatic{"/usr/bin/app": tc.entry}.read,
			})

			f := mined(t, p, img,
				advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
				&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

			if f.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s", f.Status, tc.wantStatus)
			}
			got := evidenceFrom(f, MethodStaticSymbolAbsent)
			if (len(got) > 0) != tc.discharge {
				t.Errorf("static-symbol discharge evidence = %v, want present=%v", got, tc.discharge)
			}
			if tc.discharge {
				why := strings.Join(got, " ")
				if !strings.Contains(why, "SSL_free_buffers") || !strings.Contains(why, "cgo binary") {
					t.Errorf("discharge evidence does not explain itself: %q", why)
				}
			}
		})
	}
}

// What the discharge proves is that one named binary does not carry one named
// function. An image runs more than one program, and the proof does not travel:
// clearing the binary that was read must leave the binary that was not read
// blocking, or the discharge would launder every other static root in the image
// through the one it happened to understand.
func TestStaticDischargeOnlyClearsTheBinaryItProved(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "libssl3", version: "3.0.11-1", source: "openssl",
			files: []string{"/usr/lib/libssl.so.3"}}},
		map[string]string{"/usr/bin/app": "", "/usr/bin/other": ""})

	static := &elfgraph.Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC}
	elves := fakeELF{
		"/usr/bin/app":         static,
		"/usr/bin/other":       static,
		"/usr/lib/libssl.so.3": lib("libssl.so.3"),
	}

	p := New(Options{
		Mine: true,
		// --roots names the second program, so both are executed and both
		// raise a blocking static-elf taint.
		Roots:   []string{"/usr/bin/other"},
		ReadELF: elves.read,
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free", "SSL_read"}},
		}).read,
		readStatic: fakeStatic{
			"/usr/bin/app":   {defined: []string{"SSL_new", "SSL_read"}, cgo: true},
			"/usr/bin/other": {defined: []string{"SSL_new", "SSL_free_buffers"}, cgo: true},
		}.read,
	})

	f := mined(t, p, img,
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	// The proof about /usr/bin/app is real and is still reported: the finding
	// stays blocking because of the other binary, not because nothing was
	// proved.
	if got := evidenceFrom(f, MethodStaticSymbolAbsent); len(got) != 1 || !strings.Contains(got[0], "/usr/bin/app") {
		t.Fatalf("discharge evidence = %v, want exactly the proof about /usr/bin/app", got)
	}
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %s, want %s: /usr/bin/other was never read and still carries the code",
			f.Status, ecosystem.StatusLinked)
	}
}

// The discharge is a claim about named functions, so with no function to name
// it has nothing to prove. Without this gate the absence test runs over an
// empty list, every loop passes vacuously, and every finding against an image
// with a static cgo entrypoint clears on no evidence at all -- the exact false
// removal this whole discharge is built to refuse.
func TestStaticDischargeNeedsAValidatedSymbol(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "libssl3", version: "3.0.11-1", source: "openssl",
			files: []string{"/usr/lib/libssl.so.3"}}},
		map[string]string{"/usr/bin/app": ""})

	elves := fakeELF{
		"/usr/bin/app":         {Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC},
		"/usr/lib/libssl.so.3": lib("libssl.so.3"),
	}

	for _, tc := range []struct {
		name  string
		hints *llm.Hints
	}{
		// Mining never ran, so nothing was mined and nothing can be absent.
		{"no mining", nil},
		// Mining ran and found nothing to name.
		{"nothing mined", &llm.Hints{Note: "the advisory describes a protocol flaw"}},
		// A symbol that is not in the advisory's own text was invented, and an
		// invented name is absent from every binary ever built.
		{"symbol not in the advisory text", &llm.Hints{Symbols: []string{"SSL_invented_by_a_model"}}},
		// A real name from the text that the package does not export: its
		// absence from the entrypoint says nothing either.
		{"symbol outside the package's namespace", &llm.Hints{Symbols: []string{"EVP_PKEY_new"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Options{
				Mine:    true,
				ReadELF: elves.read,
				ReadSymbols: newSyms(map[string]syms{
					"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free", "SSL_read"}},
				}).read,
				// A table that would discharge, if there were anything to
				// look up in it.
				readStatic: fakeStatic{"/usr/bin/app": {defined: []string{"SSL_new", "SSL_read"}, cgo: true}}.read,
			})

			f := mined(t, p, img,
				advisory("A flaw in SSL_free_buffers, reached through EVP_PKEY_new, frees a buffer twice."),
				tc.hints)

			if got := evidenceFrom(f, MethodStaticSymbolAbsent); len(got) > 0 {
				t.Errorf("discharged with nothing validated: %v", got)
			}
			if f.Status != ecosystem.StatusLinked {
				t.Errorf("status = %s, want %s", f.Status, ecosystem.StatusLinked)
			}
		})
	}
}

// dlopenELF is the shape every test below shares: an entrypoint that links
// libssl and also calls dlopen, so the image carries a global blocking dlopen
// taint while the package's own objects are still perfectly readable.
func dlopenELF() fakeELF {
	caller := exe("libssl.so.3")
	caller.Dlopen = true
	return fakeELF{
		"/usr/bin/app":         caller,
		"/usr/lib/libssl.so.3": lib("libssl.so.3"),
	}
}

// blockingEvidence reports the details of the evidence lines that are marked as
// blocking, which is what a caller has to count to know whether a conclusion was
// withheld.
func blockingEvidence(f ecosystem.Finding) []string {
	var out []string
	for _, e := range f.Evidence {
		if e.Blocking {
			out = append(out, e.Detail)
		}
	}
	return out
}

// The whole point of splitting presence from reachability. A dlopen call
// somewhere in the image says the closure is a lower bound on what loads. It
// does not say the package's symbol tables are lying, and "the advisory's
// function is exported by nothing this package installs" is read out of exactly
// those tables -- so it is still answerable, and before this split it was not.
//
// This is not a niche shape. Every Debian and RHEL base layer ships between
// fifteen and thirty dlopen callers, and one surviving caller was enough to
// withhold every mined not_present in the image.
func TestDlopenDoesNotWithholdTheSymbolAbsenceAnswer(t *testing.T) {
	p := New(Options{
		Mine:    true,
		ReadELF: dlopenELF().read,
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free", "SSL_read"}},
		}).read,
	})

	f := mined(t, p, minedImage(t),
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status != ecosystem.StatusNotPresent || f.Method != MethodDynsymAbsent {
		t.Fatalf("status = %s via %s, want %s via %s",
			f.Status, f.Method, ecosystem.StatusNotPresent, MethodDynsymAbsent)
	}
	if got := blockingEvidence(f); len(got) > 0 {
		t.Errorf("a conclusion was reached with blocking evidence still attached: %v", got)
	}

	// Reached, but not by pretending the image is closed. The dlopen call is
	// still in the report, because an image with a runtime loader in it and one
	// without must not produce the same evidence.
	var mentioned bool
	for _, e := range f.Evidence {
		if strings.Contains(e.Detail, "calls dlopen") {
			mentioned = true
		}
	}
	if !mentioned {
		t.Error("the dlopen call was dropped from the evidence rather than recorded as not bearing on the answer")
	}
}

// The other half of the split, and the one that keeps it honest. Reachability
// is what dlopen actually threatens, so the closure's own answer stays
// withheld: the package is unreferenced on disk, and without knowing what the
// dlopen call opens that is not the same as unreachable.
func TestDlopenStillWithholdsTheClosureAnswer(t *testing.T) {
	// An entrypoint that needs nothing, so libssl sits on disk unreferenced,
	// and that calls dlopen, so it might open it anyway.
	caller := exe()
	caller.Dlopen = true
	elves := fakeELF{
		"/usr/bin/app":         caller,
		"/usr/lib/libssl.so.3": lib("libssl.so.3"),
	}

	p := New(Options{
		Mine:    true,
		ReadELF: elves.read,
		ReadSymbols: newSyms(map[string]syms{
			// This build does export the function, so the presence question is
			// answered the other way and only the closure is left to ask.
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free_buffers"}},
		}).read,
	})

	f := mined(t, p, minedImage(t),
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %s, want %s: an unreferenced library in an image with a dlopen call in it is not a library that will not load",
			f.Status, ecosystem.StatusLinked)
	}
	if got := blockingEvidence(f); len(got) == 0 {
		t.Error("the answer was withheld without saying what withheld it")
	}
}

// The exemption is specific to the taints that cannot hide code. A static
// entrypoint can: it carries its libraries inside itself, so the package's
// export tables are not a complete account of what is in the image, and the
// presence question goes back to being unanswerable.
func TestAStaticEntrypointStillWithholdsTheSymbolAbsenceAnswer(t *testing.T) {
	static := &elfgraph.Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC, Dlopen: true}
	elves := fakeELF{
		"/usr/bin/app":         static,
		"/usr/lib/libssl.so.3": lib("libssl.so.3"),
	}

	p := New(Options{
		Mine:    true,
		ReadELF: elves.read,
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free", "SSL_read"}},
		}).read,
		// Nothing can account for what is inside it: not a cgo build the symbol
		// table could be read from, and not a pure-Go one.
		readStatic: fakeStatic{"/usr/bin/app": {stripped: true, cgo: true}}.read,
	})

	f := mined(t, p, minedImage(t),
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %s, want %s: the entrypoint may hold a copy of the code the package's tables do not describe",
			f.Status, ecosystem.StatusLinked)
	}
}

// The import-absent answer is the other reachability claim, and it has to stay
// on the full blockers for the same reason the closure's does. "Nothing the
// closure reaches imports this function" is a statement about what the closure
// reaches, and an unresolved dlopen call is precisely the reason the closure is
// not the whole story -- whatever it opens could be the importer.
func TestDlopenStillWithholdsTheImportAbsentAnswer(t *testing.T) {
	p := New(Options{
		Mine:               true,
		TrustImportAbsence: true,
		ReadELF:            dlopenELF().read,
		ReadSymbols: newSyms(map[string]syms{
			// The function is in this build, and the entrypoint that links the
			// library does not call it -- so the only thing between here and
			// not_in_path is the dlopen call.
			"/usr/lib/libssl.so.3": {defined: []string{"SSL_new", "SSL_free_buffers"}},
			"/usr/bin/app":         {undefined: []string{"SSL_new"}},
		}).read,
	})

	f := mined(t, p, minedImage(t),
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status == ecosystem.StatusNotInPath {
		t.Errorf("status = %s: the closure is not a complete account of what imports what while a dlopen call in it is unresolved",
			f.Status)
	}
	if got := blockingEvidence(f); len(got) == 0 {
		t.Error("the answer was withheld without saying what withheld it")
	}
}
