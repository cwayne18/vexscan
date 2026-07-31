package maven

import (
	"context"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// log4shell is the real advisory's shape: it names the class, and it names it
// bare. GHSA-jfh8-c2jp-5v3q never writes the package the class lives in, which
// is why a simple name has to be checkable at all.
var log4shell = &osv.Advisory{
	ID:      "CVE-2021-44228",
	Summary: "Remote code execution in Apache Log4j2",
	Details: "JNDI features used in configuration, log messages, and parameters do not " +
		"protect against attacker controlled LDAP. From version 2.16.0, this functionality " +
		"has been completely removed. Note that this vulnerability is specific to log4j-core " +
		"and does not affect log4net. Users may remove the JndiLookup class from the classpath.",
}

// findingsWithHints runs the whole plugin over one advisory with the mined
// hints the orchestrator would have attached to it.
func findingsWithHints(t *testing.T, img *target.Image, adv *osv.Advisory, hints *llm.Hints) []ecosystem.Finding {
	t.Helper()
	ctx := context.Background()
	p := New(Options{Mine: true})

	if !ecosystem.UsesHints(p) {
		t.Fatal("the plugin did not opt into mining")
	}
	components, err := p.InventoryImage(ctx, img, all)
	if err != nil {
		t.Fatalf("InventoryImage: %v", err)
	}

	items := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		item := ecosystem.WorkItem{
			Component:  c,
			Advisories: map[string]*osv.Advisory{adv.ID: adv},
			Requested:  []string{adv.ID},
		}
		if hints != nil {
			item.Hints = map[string]*llm.Hints{adv.ID: hints}
		}
		items = append(items, item)
	}

	findings, err := p.AnalyzeImage(ctx, img, items)
	if err != nil {
		t.Fatalf("AnalyzeImage: %v", err)
	}
	return findings
}

// mine runs the whole plugin with mining on, keying the findings by artifact.
func mine(t *testing.T, img *target.Image, adv *osv.Advisory, hints *llm.Hints) map[string]ecosystem.Finding {
	t.Helper()
	out := map[string]ecosystem.Finding{}
	for _, f := range findingsWithHints(t, img, adv, hints) {
		out[f.Module] = f
	}
	return out
}

// shadedLog4j is what maven-shade-plugin leaves behind: the same class, under a
// package the advisory has never heard of.
func shadedLog4j(t *testing.T) string {
	t.Helper()
	name, body := pom("com.example", "uber", "1.0")
	return jarBytes(t, map[string]string{
		name:                          body,
		"com/example/uber/Main.class": "",
		"com/example/uber/shaded/org/apache/logging/log4j/core/lookup/JndiLookup.class": "",
	})
}

// The case the ecosystem exists for, both ways round: the artifact is still
// log4j-core 2.14.1 after the published mitigation, so every version scanner
// still reports it, and the class list is what settles it.
func TestLog4ShellClassPresenceDecidesIt(t *testing.T) {
	hints := &llm.Hints{Symbols: []string{"JndiLookup"}}

	for _, tc := range []struct {
		name          string
		withClass     bool
		status        ecosystem.Status
		justification string
		method        string
	}{
		{"class still in the jar", true, ecosystem.StatusLinked, "", MethodInventory},
		{"class deleted per the mitigation", false, ecosystem.StatusNotPresent, "vulnerable_code_not_present", MethodClassAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := javaImage(t, map[string]string{
				"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, tc.withClass),
			})
			f, ok := mine(t, img, log4shell, hints)["org.apache.logging.log4j:log4j-core"]
			if !ok {
				t.Fatal("no finding")
			}
			detail, _ := evidence(f)
			if f.Status != tc.status || f.Justification != tc.justification || f.Method != tc.method {
				t.Fatalf("got %s/%s/%s, want %s/%s/%s%s",
					f.Status, f.Justification, f.Method, tc.status, tc.justification, tc.method, detail)
			}
			if !strings.Contains(detail, "JndiLookup") {
				t.Errorf("the evidence never mentions the class it turned on:%s", detail)
			}
		})
	}
}

// A relocated copy is loadable exactly as well as an original, so the absence
// test has to look under every package spelling -- and say so when that is the
// only thing standing between the artifact and not_present.
func TestRelocatedClassIsNotAbsent(t *testing.T) {
	img := javaImage(t, map[string]string{"/app/uber.jar": shadedLog4j(t)})

	f, ok := mine(t, img, log4shell, &llm.Hints{
		Symbols: []string{"JndiLookup"},
	})["com.example:uber"]
	if !ok {
		t.Fatal("no finding")
	}
	detail, _ := evidence(f)
	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("a shaded copy of the class read as %s, want linked:%s", f.Status, detail)
	}
	if !strings.Contains(detail, "com/example/uber/shaded/org/apache/logging/log4j/core/lookup/JndiLookup.class") {
		t.Errorf("the evidence does not name the entry the class was found at:%s", detail)
	}
}

// The same jar, mined with the fully qualified name the advisory would have to
// have written for the relocation to be visible as a relocation.
func TestRelocationIsFlaggedAgainstAQualifiedName(t *testing.T) {
	adv := &osv.Advisory{
		ID:      "CVE-2021-44228",
		Summary: "Remote code execution in Apache Log4j2",
		Details: "Remove org.apache.logging.log4j.core.lookup.JndiLookup from the classpath.",
	}
	img := javaImage(t, map[string]string{"/app/uber.jar": shadedLog4j(t)})

	f, ok := mine(t, img, adv, &llm.Hints{
		Symbols: []string{"org.apache.logging.log4j.core.lookup.JndiLookup"},
	})["com.example:uber"]
	if !ok {
		t.Fatal("no finding")
	}
	detail, blocking := evidence(f)
	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("got %s, want linked:%s", f.Status, detail)
	}
	if !blocking {
		t.Errorf("the advisory's own path is empty and only a relocated copy saved it; that should block:%s", detail)
	}
	if !strings.Contains(detail, "com/example/uber/shaded/") {
		t.Errorf("the evidence does not name the relocated entry:%s", detail)
	}
}

// A class the JVM loads in preference to the base copy is a class the artifact
// ships.
func TestMultiReleaseClassCounts(t *testing.T) {
	name, body := pom("org.apache.logging.log4j", "log4j-core", "2.14.1")
	img := javaImage(t, map[string]string{
		"/opt/lib/log4j-core-2.14.1.jar": jarBytes(t, map[string]string{
			name: body,
			"org/apache/logging/log4j/core/Logger.class":                                "",
			"META-INF/versions/9/org/apache/logging/log4j/core/lookup/JndiLookup.class": "",
		}),
	})

	f := mine(t, img, log4shell, &llm.Hints{Symbols: []string{"JndiLookup"}})["org.apache.logging.log4j:log4j-core"]
	detail, _ := evidence(f)
	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("a multi-release class read as %s, want linked:%s", f.Status, detail)
	}
}

// Every gate, each shown rejecting on its own. A rejected hint is an
// observation and never a reason: the status is whatever the deterministic
// layer already decided.
func TestGatesRejectWithoutChangingTheStatus(t *testing.T) {
	// The jar does not hold JndiLookup, so each of these would be
	// not_present/jar-class-absent if the gate let it through.
	clean := map[string]string{"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, false)}

	for _, tc := range []struct {
		name  string
		files map[string]string
		adv   *osv.Advisory
		hints *llm.Hints
		want  string
	}{
		{
			name:  "a class the advisory never wrote",
			files: clean,
			adv:   log4shell,
			hints: &llm.Hints{Symbols: []string{"JndiManager"}},
			want:  "invented rather than extracted",
		},
		{
			name:  "a method name is not a class",
			files: clean,
			// Written so the method name passes the literal gate and has to be
			// stopped by the shape gate: there is no doLookup.class, and
			// concluding absence from its absence would be a plain lie.
			adv: &osv.Advisory{
				ID:      log4shell.ID,
				Summary: "Remote code execution in Apache Log4j2",
				Details: "The doLookup method resolves attacker controlled JNDI URIs.",
			},
			hints: &llm.Hints{Symbols: []string{"doLookup"}},
			want:  "not shaped like a class name",
		},
		{
			name:  "the model was asked and named nothing",
			files: clean,
			adv:   log4shell,
			hints: &llm.Hints{Note: "the advisory names no class"},
			want:  "no class could be mined",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := javaImage(t, tc.files)
			f := mine(t, img, tc.adv, tc.hints)["org.apache.logging.log4j:log4j-core"]
			detail, _ := evidence(f)
			if f.Status != ecosystem.StatusLinked || f.Method != MethodInventory {
				t.Fatalf("a rejected hint changed the finding to %s/%s:%s", f.Status, f.Method, detail)
			}
			if !strings.Contains(detail, tc.want) {
				t.Errorf("the record does not say why the hint was rejected, want %q:%s", tc.want, detail)
			}
		})
	}
}

// Gate 4. The coordinates of a jar with no metadata are a guess, and "this
// artifact ships no such class" about an artifact we only think this jar is
// stacks a second guess on the first.
func TestReconstructedCoordinatesCannotSupportAbsence(t *testing.T) {
	img := javaImage(t, map[string]string{
		// No META-INF at all: the coordinate comes from the file name and the
		// class layout, so CoordsKnown is false.
		"/opt/lib/log4j-core-2.14.1.jar": jarBytes(t, map[string]string{
			"org/apache/logging/log4j/core/Logger.class": "",
		}),
	})

	found := mine(t, img, log4shell, &llm.Hints{Symbols: []string{"JndiLookup"}})
	var f ecosystem.Finding
	for _, got := range found {
		f = got
	}
	detail, blocking := evidence(f)
	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("a guessed coordinate produced %s/%s, want linked:%s", f.Status, f.Justification, detail)
	}
	if !blocking {
		t.Errorf("refusing to conclude should be recorded as blocking:%s", detail)
	}
	if !strings.Contains(detail, "coordinates were reconstructed") {
		t.Errorf("the evidence does not say which gate stopped it:%s", detail)
	}
}

// Gate 5, driven through the evaluator directly: an archive whose central
// directory could not be read holds nothing as far as this code can see, and
// that failure must never render as an answer.
func TestIncompleteListingCannotSupportAbsence(t *testing.T) {
	st := &state{pkgs: []langdb.Package{{
		Name:        "org.apache.logging.log4j:log4j-core",
		Version:     "2.14.1",
		Dir:         "/opt/lib/log4j-core-2.14.1.jar",
		Files:       []string{"org/apache/logging/log4j/core/Logger.class"},
		FilesKnown:  false,
		CoordsKnown: true,
	}}}
	c := ecosystem.Component{Ecosystem: "Maven", Name: st.pkgs[0].Name, Version: "2.14.1"}

	f := evaluator{st: st}.evaluate(c, ecosystem.Request{
		ID:       log4shell.ID,
		Advisory: log4shell,
		Hints:    &llm.Hints{Symbols: []string{"JndiLookup"}},
	})
	detail, blocking := evidence(f)
	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("an unlistable archive produced %s, want linked:%s", f.Status, detail)
	}
	if !blocking || !strings.Contains(detail, "archive listing is incomplete") {
		t.Errorf("the evidence does not record the missing listing as a blocker:%s", detail)
	}
}

// Without --mine-advisories there are no hints, and the layer has to be silent
// rather than reporting that it found nothing: "never asked" and "asked and got
// nothing" are different facts.
func TestNoHintsLeavesNoTrace(t *testing.T) {
	img := javaImage(t, map[string]string{
		"/opt/lib/log4j-core-2.14.1.jar": log4jJar(t, false),
	})

	f := mine(t, img, log4shell, nil)["org.apache.logging.log4j:log4j-core"]
	detail, _ := evidence(f)
	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("got %s, want linked:%s", f.Status, detail)
	}
	for _, e := range f.Evidence {
		if e.Origin == MethodMined {
			t.Errorf("the mining layer spoke without having been asked:%s", detail)
		}
	}
}
