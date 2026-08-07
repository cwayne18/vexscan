package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/target"
)

// ansi matches any escape sequence the palette can emit, and is how the tests
// strip a coloured report back to the report it is meant to be.
var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansi.ReplaceAllString(s, "") }

// The zero palette is the whole of --color never: no branch, no escapes.
func TestTheZeroPaletteWritesNothing(t *testing.T) {
	var p palette
	for _, got := range []string{
		p.severity("CRITICAL"),
		p.status(analyze.StatusLinked, "linked"),
		p.heading("AFFECTED (3)"),
		p.bold("x"),
		p.banners("INCOMPLETE: something\n"),
	} {
		if strings.Contains(got, "\x1b") {
			t.Errorf("the zero palette emitted an escape: %q", got)
		}
	}
}

// An empty cell must stay empty. A cell of nothing but escapes has no width on
// screen and four bytes in a diff, and writeTable would be padding a column for
// a value that is not there.
func TestAnEmptyCellIsNotColoured(t *testing.T) {
	p := palette{on: true}
	if got := p.severity(""); got != "" {
		t.Errorf("severity(\"\") = %q, want empty", got)
	}
	if got := p.status(analyze.StatusLinked, ""); got != "" {
		t.Errorf("status(\"\") = %q, want empty", got)
	}
}

// Colour must be additive: stripping the escapes back out has to reproduce the
// uncoloured text exactly, or the two reports have diverged into two documents.
func TestColourAddsNothingButEscapes(t *testing.T) {
	p := palette{on: true}
	cases := []struct{ coloured, plain string }{
		{p.severity("CRITICAL"), "CRITICAL"},
		{p.severity("UNKNOWN"), "UNKNOWN"},
		{p.status(analyze.StatusNotPresent, "not_present"), "not_present"},
		{p.heading("AFFECTED (12)"), "AFFECTED (12)"},
		{p.banners("INCOMPLETE: a\nNOTE: b\n  continued\n"), "INCOMPLETE: a\nNOTE: b\n  continued\n"},
	}
	for _, tc := range cases {
		if !strings.Contains(tc.coloured, "\x1b") {
			t.Errorf("%q was not coloured at all", tc.plain)
		}
		if got := stripANSI(tc.coloured); got != tc.plain {
			t.Errorf("stripped = %q, want %q", got, tc.plain)
		}
	}
}

// Only a prefix at the start of a line is a banner. The same word inside a
// sentence is prose, and bolding it mid-line would look like a rendering fault.
func TestBannersOnlyBoldsLineOpenings(t *testing.T) {
	p := palette{on: true}
	got := p.banners("NOTE: real\n  see the NOTE: above\n")
	lines := strings.Split(got, "\n")
	if !strings.HasPrefix(lines[0], ansiBold) {
		t.Errorf("the opening banner was not bolded: %q", lines[0])
	}
	if strings.Contains(lines[1], "\x1b") {
		t.Errorf("a mid-line mention was bolded: %q", lines[1])
	}
}

func TestVisibleWidth(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"CRITICAL", 8},
		{ansiRed + "HIGH" + ansiReset, 4},
		{ansiBold + ansiRed + "CRITICAL" + ansiReset, 8},
		{"…", 1}, // the truncation marker is one column, three bytes
		{ansiDim + "" + ansiReset, 0},
	}
	for _, tc := range cases {
		if got := visibleWidth(tc.in); got != tc.want {
			t.Errorf("visibleWidth(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// The alignment guard, and the reason visibleWidth exists: a coloured table and
// a plain one must put every column in the same place. Escapes are runes that
// occupy no columns, so measuring them shifts every column to their right.
func TestColouredAndPlainTablesAlignIdentically(t *testing.T) {
	p := palette{on: true}
	plain := [][]string{
		{"SEVERITY", "PACKAGE"},
		{"CRITICAL", "libssl3"},
		{"LOW", "zlib1g"},
	}
	coloured := [][]string{
		{"SEVERITY", "PACKAGE"},
		{p.severity("CRITICAL"), "libssl3"},
		{p.severity("LOW"), "zlib1g"},
	}
	var a, c strings.Builder
	writeTable(&a, plain)
	writeTable(&c, coloured)
	if got := stripANSI(c.String()); got != a.String() {
		t.Errorf("stripping a coloured table did not reproduce the plain one:\n%q\nwant:\n%q", got, a.String())
	}
}

// The same guard over a whole report, which is where a shifted column actually
// gets noticed -- and which also proves nothing outside the palette started
// writing escapes of its own.
func TestAColouredReportStripsBackToThePlainOne(t *testing.T) {
	res := []*analyze.Result{
		{
			SchemaVersion: analyze.SchemaVersion,
			Target:        "debian:12",
			Mode:          "image",
			Findings:      gccTrio,
			Unreadable:    &target.Unreadable{Count: 1, Paths: []string{"/root/.ssh"}},
		},
	}
	plain := renderText(res, renderOpts{details: true})
	coloured := renderText(res, renderOpts{details: true, pal: palette{on: true}})

	if !strings.Contains(coloured, "\x1b") {
		t.Fatal("the coloured report has no escapes in it")
	}
	if strings.Contains(plain, "\x1b") {
		t.Fatal("the plain report has escapes in it")
	}
	if got := stripANSI(coloured); got != plain {
		t.Errorf("the coloured report does not strip back to the plain one:\n%s", diffFirstLine(got, plain))
	}
}

// The fix plan is a second document over the same findings, and its tables are
// coloured by the same palette, so it gets the same guard.
func TestAColouredFixPlanStripsBackToThePlainOne(t *testing.T) {
	res := []*analyze.Result{
		{
			SchemaVersion: analyze.SchemaVersion,
			Target:        "debian:12",
			Mode:          "image",
			Ecosystems:    []ecosystem.EcosystemResult{{ID: "os", Ecosystems: []string{"Debian:12"}}},
			Findings:      fixableTrio(),
		},
	}
	plain := renderFixPlan(res, renderOpts{})
	coloured := renderFixPlan(res, renderOpts{pal: palette{on: true}})
	if !strings.Contains(coloured, "\x1b") {
		t.Fatal("the coloured fix plan has no escapes in it")
	}
	if got := stripANSI(coloured); got != plain {
		t.Errorf("the coloured fix plan does not strip back to the plain one:\n%s", diffFirstLine(got, plain))
	}
}

// fixableTrio is the gcc trio with a published fix, so the plan has an UPGRADE
// table to colour rather than only a NO FIX YET one.
func fixableTrio() []analyze.Finding {
	out := make([]analyze.Finding, len(gccTrio))
	copy(out, gccTrio)
	for i := range out {
		out[i].FixedVersion = "12.2.0-14+deb12u2"
	}
	return out
}

// diffFirstLine names where two renderings part company, because a byte-for-byte
// failure over a 60-line report is unreadable otherwise.
func diffFirstLine(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) && i < len(w); i++ {
		if g[i] != w[i] {
			return "first difference at line " + itoa(i+1) + ":\n got: " + g[i] + "\nwant: " + w[i]
		}
	}
	return "one is a prefix of the other: " + itoa(len(g)) + " lines vs " + itoa(len(w))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func TestParseColor(t *testing.T) {
	for _, mode := range []string{"auto", "always", "never"} {
		if _, err := parseColor(mode); err != nil {
			t.Errorf("parseColor(%q): %v", mode, err)
		}
	}
	// Strict, like --severity and --fail-on: a misspelling that quietly meant
	// "auto" is a setting the user believes they changed.
	for _, mode := range []string{"", "allways", "yes", "1", "AUTO"} {
		if _, err := parseColor(mode); err == nil {
			t.Errorf("parseColor(%q) = nil error, want one", mode)
		}
	}
}

// The destinations that must never receive escapes, and the one flag that
// overrides the terminal check but not the JSON one.
func TestColourIsOffForEveryStoredDestination(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	auto, _ := parseColor("auto")
	always, _ := parseColor("always")
	never, _ := parseColor("never")

	cases := []struct {
		name   string
		policy colorPolicy
		dest   destination
		want   bool
	}{
		// emit writes the same string to the file, and uploadGist sends that
		// same string on afterwards.
		{"auto to a file", auto, destination{file: true}, false},
		{"auto to a gist", auto, destination{gist: true}, false},
		{"always to a file", always, destination{file: true}, true},

		// JSON is the one always does not override: escapes there are not ugly,
		// they are unparseable.
		{"auto to json", auto, destination{json: true}, false},
		{"always to json", always, destination{json: true}, false},

		{"never, always", never, destination{}, false},
		{"always, nowhere in particular", always, destination{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.palette(tc.dest).on; got != tc.want {
				t.Errorf("palette().on = %v, want %v", got, tc.want)
			}
		})
	}
}

// https://no-color.org: set and non-empty turns colour off, whatever the value.
// --color always still overrides it, because that is a user asking twice.
func TestNoColorIsHonoured(t *testing.T) {
	auto, _ := parseColor("auto")
	always, _ := parseColor("always")

	t.Setenv("NO_COLOR", "1")
	if auto.palette(destination{}).on {
		t.Error("auto coloured with NO_COLOR=1")
	}
	if !always.palette(destination{}).on {
		t.Error("--color always did not override NO_COLOR")
	}

	// Unset and empty both mean "not set", so a stray NO_COLOR= in an
	// environment file does not silently disable colour.
	t.Setenv("NO_COLOR", "")
	if auto.palette(destination{file: true}).on {
		t.Error("an empty NO_COLOR should leave the other checks in charge")
	}
}
