package ospkg

import (
	"context"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// deepScan drives a metadata-only (--rpm) scan the way --rpm-deep would: the
// package's ELF objects are readable (a fake symbol table stands in for the
// extracted tree) and one advisory carries mined hints. It is the supplied-mode
// twin of mine's helper, which only exists for installed images.
func deepScan(t *testing.T, p *Plugin, adv *osv.Advisory, hints *llm.Hints) ecosystem.Finding {
	t.Helper()
	ctx := context.Background()
	// The tree is empty on disk: the fake ReadSymbols keys on the object path
	// and never touches the filesystem, which is exactly the seam --rpm-deep
	// fills by writing those objects where the reader looks for them.
	img := &target.Image{Ref: "--rpm /tmp/repo", FS: target.NewDirFS(t.TempDir())}

	if ok, err := p.DetectImage(ctx, img); err != nil || !ok {
		t.Fatalf("DetectImage: %v %v", ok, err)
	}
	components, err := p.InventoryImage(ctx, img, []ecosystem.Subject{{Raw: "all"}})
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
		if f.Module == "openssl-libs" {
			return f
		}
	}
	t.Fatal("no finding for openssl-libs")
	return ecosystem.Finding{}
}

// shipsELF is a supplied rpm whose header listed an ELF object, the input
// --rpm-deep exists to look inside.
func shipsELF() Supplied {
	s := rocky("openssl-libs", "1:3.5.5-2.el9_8")
	s.Package.Files = []string{"/usr/lib64/libssl.so.3", "/usr/share/doc/openssl-libs/CHANGES"}
	s.Meta.ELF = []string{"/usr/lib64/libssl.so.3"}
	return s
}

// The row --rpm-deep is for: the advisory names a function, the package's own
// library is from the right software, and the function is not in this build. An
// installed scan calls that not_present; a deep --rpm scan reaches the same
// verdict without installing.
func TestDeepRPMDynsymAbsentIsNotPresent(t *testing.T) {
	p := New(Options{
		Mine:     true,
		Packages: []Supplied{shipsELF()},
		ReadSymbols: newSyms(map[string]syms{
			// The SSL_ namespace, without the vulnerable function itself.
			"/usr/lib64/libssl.so.3": {defined: []string{"SSL_new", "SSL_free", "SSL_read"}},
		}).read,
	})

	f := deepScan(t, p,
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status != ecosystem.StatusNotPresent {
		t.Fatalf("status = %s, want not_present", f.Status)
	}
	if f.Justification != "vulnerable_code_not_present" || f.Method != MethodDynsymAbsent {
		t.Errorf("justification/method = %s/%s, want vulnerable_code_not_present/%s", f.Justification, f.Method, MethodDynsymAbsent)
	}
	why := strings.Join(evidenceFrom(f, MethodDynsymAbsent), " ")
	if !strings.Contains(why, "SSL_free_buffers") {
		t.Errorf("evidence does not name the symbol: %q", why)
	}
}

// When the package DOES export the vulnerable function, deep mode must not
// upgrade the row: the code is present, and whether it can run is exactly the
// question no --rpm scan can answer. The honest verdict is undetermined, not a
// guess in either direction.
func TestDeepRPMKeepsUndeterminedWhenTheSymbolIsPresent(t *testing.T) {
	p := New(Options{
		Mine:     true,
		Packages: []Supplied{shipsELF()},
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib64/libssl.so.3": {defined: []string{"SSL_new", "SSL_free_buffers"}},
		}).read,
	})

	f := deepScan(t, p,
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})

	if f.Status != ecosystem.StatusUndetermined {
		t.Fatalf("status = %s via %s, want undetermined -- the vulnerable code is present and reachability cannot be tested", f.Status, f.Method)
	}
	if f.Reason != ReasonNoReachabilityTest {
		t.Errorf("reason = %q, want %q", f.Reason, ReasonNoReachabilityTest)
	}
}

// Deep mode is never allowed to reach a reachability verdict. Even with the
// objects in hand, there is no entrypoint and no closure, so linked and
// not_in_execute_path stay impossible -- the guarantee the whole mode rests on.
func TestDeepRPMNeverClaimsReachability(t *testing.T) {
	p := New(Options{
		Mine:     true,
		Packages: []Supplied{shipsELF()},
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib64/libssl.so.3": {defined: []string{"SSL_new", "SSL_free_buffers"}},
		}).read,
	})
	f := deepScan(t, p,
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		&llm.Hints{Symbols: []string{"SSL_free_buffers"}})
	if f.Status == ecosystem.StatusLinked || f.Status == ecosystem.StatusNotInPath {
		t.Fatalf("status = %s; --rpm-deep must never assert what the linker would load", f.Status)
	}
}

// Without hints -- --rpm-deep on but --mine-advisories off -- there is no symbol
// to look for, so the extracted objects change nothing and the row stays
// undetermined. This is the case the command-line warning is about.
func TestDeepRPMWithoutHintsStaysUndetermined(t *testing.T) {
	p := New(Options{
		Mine:     true,
		Packages: []Supplied{shipsELF()},
		ReadSymbols: newSyms(map[string]syms{
			"/usr/lib64/libssl.so.3": {defined: []string{"SSL_new", "SSL_free"}},
		}).read,
	})
	f := deepScan(t, p,
		advisory("A flaw in SSL_free_buffers allows a buffer to be freed twice."),
		nil)
	if f.Status != ecosystem.StatusUndetermined {
		t.Fatalf("status = %s via %s, want undetermined without a mined symbol", f.Status, f.Method)
	}
}
