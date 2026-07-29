package ecosystem

import (
	"strings"
	"testing"
)

func TestParseSubject(t *testing.T) {
	tests := []struct {
		raw  string
		want Subject
	}{
		{"openssl", Subject{Name: "openssl", Raw: "openssl"}},
		{"golang:golang.org/x/net", Subject{Ecosystem: "golang", Name: "golang.org/x/net", Raw: "golang:golang.org/x/net"}},
		{"deb:openssl", Subject{Ecosystem: "os", Name: "openssl", Raw: "deb:openssl"}},
		{"APK:musl", Subject{Ecosystem: "os", Name: "musl", Raw: "APK:musl"}},
		{"os:openssl", Subject{Ecosystem: "os", Name: "openssl", Raw: "os:openssl"}},
		{"go:stdlib", Subject{Ecosystem: "golang", Name: "stdlib", Raw: "go:stdlib"}},
		{"  deb:openssl  ", Subject{Ecosystem: "os", Name: "openssl", Raw: "  deb:openssl  "}},
		{
			"pkg:golang/golang.org%2Fx%2Fnet@v0.17.0",
			Subject{PURL: "pkg:golang/golang.org%2Fx%2Fnet@v0.17.0", Raw: "pkg:golang/golang.org%2Fx%2Fnet@v0.17.0"},
		},
		// A module path never contains a colon, but a name that does would
		// have its slashes first. Treating that as an ecosystem prefix would
		// silently rewrite the user's selector.
		{"example.com/a:b", Subject{Name: "example.com/a:b", Raw: "example.com/a:b"}},
	}

	for _, tt := range tests {
		got, err := ParseSubject(tt.raw)
		if err != nil {
			t.Errorf("ParseSubject(%q): %v", tt.raw, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseSubject(%q)\n got: %+v\nwant: %+v", tt.raw, got, tt.want)
		}
	}
}

func TestParseSubjectRejectsNonsense(t *testing.T) {
	for _, raw := range []string{"", "   ", "deb:", "golang:  "} {
		if _, err := ParseSubject(raw); err == nil {
			t.Errorf("ParseSubject(%q) = nil error, want one", raw)
		}
	}
}

// A subject nothing can answer must be an error. Left alone it produces an
// empty inventory, which renders as a clean report.
func TestSubjectsRejectAnEcosystemNoPluginHandles(t *testing.T) {
	plugins := []Plugin{stubPlugin{id: "golang", ecos: []string{"Go"}}}

	if _, err := Subjects(plugins, []string{"golang:golang.org/x/net"}); err != nil {
		t.Fatalf("a subject aimed at a selected plugin is fine: %v", err)
	}

	_, err := Subjects(plugins, []string{"deb:openssl"})
	if err == nil {
		t.Fatal("expected an error when no selected plugin handles the ecosystem")
	}
	if !strings.Contains(err.Error(), "golang") {
		t.Errorf("the error should name what is selected, got: %v", err)
	}
}

// A bare name has no ecosystem to check, so it passes through to whichever
// inventory turns out to contain it.
func TestSubjectsAcceptABareName(t *testing.T) {
	got, err := Subjects([]Plugin{stubPlugin{id: "os", ecos: []string{"Debian"}}}, []string{"openssl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "openssl" || got[0].Ecosystem != "" {
		t.Errorf("got %+v, want one unqualified openssl subject", got)
	}
}

type stubPlugin struct {
	id   string
	ecos []string
}

func (p stubPlugin) ID() string           { return p.id }
func (p stubPlugin) Ecosystems() []string { return p.ecos }
