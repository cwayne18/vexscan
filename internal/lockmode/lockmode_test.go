package lockmode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/lockfile"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// fakePlugin stands in for the real ecosystem plugin, which lockmode only needs
// for ecosystem.MatchEcosystem.
type fakePlugin struct {
	id  string
	eco string
}

func (f fakePlugin) ID() string           { return f.id }
func (f fakePlugin) Ecosystems() []string { return []string{f.eco} }

func npmAnalyzer() Analyzer {
	return Analyzer{Config: Config{
		Owner:     fakePlugin{id: "npm", eco: "npm"},
		Ecosystem: "npm",
		Format:    lockfile.FormatNPM,
		Prefix:    "npm",
		PURLType:  "npm",
		Normalize: func(s string) string { return s },
		PURL:      func(n, v string) string { return "pkg:npm/" + n + "@" + v },
	}}
}

func pypiAnalyzer() Analyzer {
	return Analyzer{Config: Config{
		Owner:     fakePlugin{id: "pypi", eco: "PyPI"},
		Ecosystem: "PyPI",
		Format:    lockfile.FormatPyPI,
		Prefix:    "pypi",
		PURLType:  "pypi",
		Normalize: langdb.NormalizePyPI,
		PURL:      func(n, v string) string { return "pkg:pypi/" + n + "@" + v },
	}}
}

// checkout builds a throwaway source tree.
func checkout(t *testing.T, files map[string]string) *target.Source {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &target.Source{Ref: "example/repo", Dir: root, Subdir: ".", FS: target.NewDirFS(root)}
}

// decide runs all three phases and returns the findings, with one advisory
// standing in for whatever OSV would have said.
func decide(t *testing.T, a Analyzer, src *target.Source, subjects []ecosystem.Subject) []ecosystem.Finding {
	t.Helper()
	ctx := context.Background()

	components, err := a.Inventory(ctx, src, subjects)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	items := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		items = append(items, ecosystem.WorkItem{
			Component:  c,
			Advisories: map[string]*osv.Advisory{"CVE-2024-0001": {ID: "CVE-2024-0001"}},
			Targeted:   targeted(subjects),
		})
	}
	findings, err := a.Analyze(ctx, src, items)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}

// targeted mirrors the orchestrator's rule: a bare subject is an enumeration,
// anything named is a targeted ask.
func targeted(subjects []ecosystem.Subject) bool {
	for _, s := range subjects {
		if s.MatchesAll() {
			return false
		}
	}
	return true
}

func only(t *testing.T, findings []ecosystem.Finding) ecosystem.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("want exactly one finding, got %d: %+v", len(findings), findings)
	}
	return findings[0]
}

func forPackage(t *testing.T, findings []ecosystem.Finding, name string) ecosystem.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Module == name {
			return f
		}
	}
	t.Fatalf("no finding for %q in %+v", name, findings)
	return ecosystem.Finding{}
}

func hasBlocking(f ecosystem.Finding) bool {
	for _, e := range f.Evidence {
		if e.Blocking {
			return true
		}
	}
	return false
}

func named(name string) []ecosystem.Subject {
	return []ecosystem.Subject{{Ecosystem: "npm", Name: name, Raw: "npm:" + name}}
}

// all is what plan() builds for --all: one bare subject that matches
// everything. The subject list is never empty in a real run.
func all() []ecosystem.Subject {
	return []ecosystem.Subject{{Raw: "--all"}}
}

func TestAPackageMissingFromTheLockFileIsNotPresent(t *testing.T) {
	src := checkout(t, map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"node_modules/react":{"version":"18.2.0"}}}`,
	})
	f := only(t, decide(t, npmAnalyzer(), src, named("qs")))

	if f.Status != ecosystem.StatusNotPresent {
		t.Errorf("status = %q, want not_present", f.Status)
	}
	if f.Justification != "component_not_present" {
		t.Errorf("justification = %q", f.Justification)
	}
	if f.Method != "npm-lockfile" {
		t.Errorf("method = %q", f.Method)
	}
}

func TestADevOnlyPackageIsNotInTheExecutePath(t *testing.T) {
	src := checkout(t, map[string]string{
		"package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/eslint": {"version": "8.57.0", "dev": true}
  }
}`,
	})
	f := only(t, decide(t, npmAnalyzer(), src, named("eslint")))

	if f.Status != ecosystem.StatusNotInPath {
		t.Errorf("status = %q, want not_in_execute_path", f.Status)
	}
	if f.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("justification = %q", f.Justification)
	}
	if f.Method != "npm-dev-only" {
		t.Errorf("method = %q", f.Method)
	}
}

func TestARuntimePackageIsLinkedAndSaysNoGraphWasResolved(t *testing.T) {
	src := checkout(t, map[string]string{
		"package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {"": {}, "node_modules/qs": {"version": "6.5.2"}}
}`,
	})
	f := only(t, decide(t, npmAnalyzer(), src, named("qs")))

	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("status = %q, want linked", f.Status)
	}
	if f.Method != "npm-lockfile" {
		t.Errorf("method = %q", f.Method)
	}
	if hasBlocking(f) {
		t.Error("a pinned runtime dependency has nothing blocking it")
	}
	// The absence of a graph has to be stated. A reader who only sees "linked"
	// cannot tell repo mode's answer from image mode's much stronger one.
	if !strings.Contains(f.Reachability, "no import graph") {
		t.Errorf("reachability = %q, want it to say no graph was resolved", f.Reachability)
	}
	if f.PURL != "pkg:npm/qs@6.5.2" {
		t.Errorf("purl = %q", f.PURL)
	}
}

func TestAnUnpinnedRequirementBlocksTheRangeCheck(t *testing.T) {
	// requirements.txt says flask is present but not which version, so the
	// advisory matched on the name alone. Reporting that as an ordinary linked
	// finding would imply an affected range had been compared against
	// something.
	src := checkout(t, map[string]string{"requirements.txt": "flask\n"})
	f := only(t, decide(t, pypiAnalyzer(), src, []ecosystem.Subject{
		{Ecosystem: "pypi", Name: "flask", Raw: "pypi:flask"},
	}))

	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("status = %q, want linked", f.Status)
	}
	if !hasBlocking(f) {
		t.Fatalf("an unpinned requirement must carry blocking evidence: %+v", f.Evidence)
	}
	var detail string
	for _, e := range f.Evidence {
		if e.Blocking {
			detail = e.Detail
		}
	}
	if !strings.Contains(detail, "no version is pinned") || !strings.Contains(detail, "requirements.txt") {
		t.Errorf("blocking evidence = %q", detail)
	}
}

func TestRequirementsTxtCannotProduceADevOnlyAnswer(t *testing.T) {
	// The file carries no development partition, so nothing here is entitled
	// to a not_in_execute_path -- not even when the file is called
	// requirements-dev.txt.
	src := checkout(t, map[string]string{"requirements-dev.txt": "pytest==8.0.0\n"})
	f := only(t, decide(t, pypiAnalyzer(), src, []ecosystem.Subject{
		{Ecosystem: "pypi", Name: "pytest", Raw: "pypi:pytest"},
	}))

	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %q, want linked: a file name is not a declaration", f.Status)
	}
}

func TestPoetryDevGroupsProduceTheSameAnswerAsNPM(t *testing.T) {
	src := checkout(t, map[string]string{
		"poetry.lock": `[[package]]
name = "black"
version = "24.1.0"
groups = ["dev"]

[[package]]
name = "requests"
version = "2.31.0"
groups = ["main"]
`,
	})
	findings := decide(t, pypiAnalyzer(), src, all())

	if got := forPackage(t, findings, "black"); got.Status != ecosystem.StatusNotInPath || got.Method != "pypi-dev-only" {
		t.Errorf("black = %q via %q, want not_in_execute_path via pypi-dev-only", got.Status, got.Method)
	}
	if got := forPackage(t, findings, "requests"); got.Status != ecosystem.StatusLinked {
		t.Errorf("requests = %q, want linked", got.Status)
	}
}

func TestScanningEverythingEnumeratesTheWholeLockFile(t *testing.T) {
	src := checkout(t, map[string]string{
		"package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/qs": {"version": "6.5.2"},
    "node_modules/tar": {"version": "6.1.11"},
    "node_modules/tar/node_modules/minipass": {"version": "3.3.6"}
  }
}`,
	})
	findings := decide(t, npmAnalyzer(), src, all())
	if len(findings) != 3 {
		t.Fatalf("want one finding per locked package, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Status != ecosystem.StatusLinked {
			t.Errorf("%s = %q, want linked", f.Module, f.Status)
		}
	}
}

func TestASubjectForAnotherEcosystemIsNotAnswered(t *testing.T) {
	// A bare --module names a Go module. Answering component_not_present for
	// every module path against every checkout would be noise
	// indistinguishable from a real result.
	src := checkout(t, map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"node_modules/qs":{"version":"6.5.2"}}}`,
	})
	findings := decide(t, npmAnalyzer(), src, []ecosystem.Subject{
		{Name: "github.com/gin-gonic/gin", Raw: "github.com/gin-gonic/gin"},
	})
	if len(findings) != 0 {
		t.Errorf("want no findings, got %+v", findings)
	}
}

func TestAPURLSubjectSelectsAScopedPackage(t *testing.T) {
	src := checkout(t, map[string]string{
		"package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {"": {}, "node_modules/@babel/core": {"version": "7.24.0"}}
}`,
	})
	f := only(t, decide(t, npmAnalyzer(), src, []ecosystem.Subject{
		{PURL: "pkg:npm/%40babel/core@7.24.0", Raw: "pkg:npm/%40babel/core@7.24.0"},
	}))
	if f.Module != "@babel/core" {
		t.Errorf("module = %q, want @babel/core", f.Module)
	}
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %q, want linked", f.Status)
	}
}

func TestDetectSaysNoWithoutALockFile(t *testing.T) {
	src := checkout(t, map[string]string{"go.mod": "module example.com/x\n"})
	for _, a := range []Analyzer{npmAnalyzer(), pypiAnalyzer()} {
		ok, err := a.Detect(context.Background(), src)
		if err != nil {
			t.Fatalf("%s: %v", a.Prefix, err)
		}
		if ok {
			t.Errorf("%s claimed a checkout with no lock file", a.Prefix)
		}
	}
}

func TestDetectReadsTheRequestedSubdirectory(t *testing.T) {
	src := checkout(t, map[string]string{
		"package-lock.json":             `{"lockfileVersion":3,"packages":{"":{},"node_modules/root-only":{"version":"1.0.0"}}}`,
		"services/api/requirements.txt": "django==5.0.1\n",
	})
	src.Subdir = "services/api"

	ok, err := npmAnalyzer().Detect(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("the root lock file is outside the requested subdirectory")
	}

	findings := decide(t, pypiAnalyzer(), src, all())
	f := forPackage(t, findings, "django")
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("django = %q, want linked", f.Status)
	}
	if len(f.Evidence) == 0 || !strings.Contains(f.Evidence[0].Detail, "services/api/requirements.txt") {
		t.Errorf("evidence should name the file it read: %+v", f.Evidence)
	}
}

func TestEvidenceNamesOnlyTheDeclaringFiles(t *testing.T) {
	// A repo with several requirements files gets all of them read, but
	// "requirements_test.txt declares certifi" is a claim about that file and
	// is false unless the file says so. Naming every file consulted was what a
	// real home-assistant/core scan did.
	src := checkout(t, map[string]string{
		"requirements.txt":      "certifi==2024.2.2\n",
		"requirements_all.txt":  "certifi==2024.2.2\n",
		"requirements_test.txt": "pytest==8.0.0\n",
	})
	f := forPackage(t, decide(t, pypiAnalyzer(), src, all()), "certifi")

	detail := f.Evidence[0].Detail
	if !strings.Contains(detail, "requirements.txt") || !strings.Contains(detail, "requirements_all.txt") {
		t.Errorf("evidence should name both declaring files: %q", detail)
	}
	if strings.Contains(detail, "requirements_test.txt") {
		t.Errorf("requirements_test.txt does not declare certifi: %q", detail)
	}
	// Locations feed the rendered output and must agree with the prose.
	components, err := pypiAnalyzer().Inventory(context.Background(), src, all())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range components {
		if c.Name != "certifi" {
			continue
		}
		if got := strings.Join(c.Locations, ","); got != "requirements.txt,requirements_all.txt" {
			t.Errorf("locations = %q", got)
		}
	}
}

func TestAbsenceEvidenceNamesEveryFileRead(t *testing.T) {
	// The mirror image: here the claim is about what all of them failed to
	// say, so every file consulted belongs in the sentence.
	src := checkout(t, map[string]string{
		"requirements.txt":      "certifi==2024.2.2\n",
		"requirements_test.txt": "pytest==8.0.0\n",
	})
	f := only(t, decide(t, pypiAnalyzer(), src, []ecosystem.Subject{
		{Ecosystem: "pypi", Name: "flask", Raw: "pypi:flask"},
	}))

	if f.Status != ecosystem.StatusNotPresent {
		t.Fatalf("status = %q, want not_present", f.Status)
	}
	detail := f.Evidence[0].Detail
	for _, want := range []string{"requirements.txt", "requirements_test.txt"} {
		if !strings.Contains(detail, want) {
			t.Errorf("evidence should name %s: %q", want, detail)
		}
	}
}

func TestLockFilesCountsPastTwo(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, "this checkout"},
		{[]string{"requirements.txt"}, "requirements.txt"},
		{[]string{"b.txt", "a.txt"}, "a.txt and b.txt"},
		{[]string{"d.txt", "a.txt", "c.txt", "b.txt"}, "a.txt, b.txt and 2 other files"},
	} {
		if got := lockFiles(tc.in); got != tc.want {
			t.Errorf("lockFiles(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParsePURL(t *testing.T) {
	for _, tc := range []struct {
		in        string
		name, typ string
		ok        bool
	}{
		{"pkg:npm/qs@6.5.2", "qs", "npm", true},
		{"pkg:npm/%40babel/core@7.24.0", "@babel/core", "npm", true},
		{"pkg:npm/@babel/core", "@babel/core", "npm", true},
		{"pkg:pypi/pyyaml@6.0.3", "pyyaml", "pypi", true},
		{"pkg:pypi/django?arch=any", "django", "pypi", true},
		{"pyyaml", "", "", false},
		{"pkg:npm", "", "", false},
	} {
		name, typ, ok := ParsePURL(tc.in)
		if name != tc.name || typ != tc.typ || ok != tc.ok {
			t.Errorf("ParsePURL(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, name, typ, ok, tc.name, tc.typ, tc.ok)
		}
	}
}
