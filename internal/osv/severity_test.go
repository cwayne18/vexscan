package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cwayne18/vexscan/internal/cvss"
)

// serve returns a client pointed at a server that answers every query with body.
func serve(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := NewClient()
	c.BaseURL = srv.URL
	return c
}

func queryOne(t *testing.T, body string, ref Ref, id string) *Advisory {
	t.Helper()
	m, err := serve(t, body).Query(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	adv, ok := m[id]
	if !ok {
		t.Fatalf("advisory %s missing from %v", id, keysOf(m))
	}
	return adv
}

func keysOf(m map[string]*Advisory) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

var debianRef = Ref{Ecosystem: "Debian:12", Name: "zlib1g"}

// The bodies below are trimmed from the real API responses for these ids, and
// the shapes are the ones actually in the wild: a Debian record with a vector
// and no label, a GHSA with both plus a CVSS 4.0 entry alongside, and a record
// with neither.
func TestSeverityFromAVectorAlone(t *testing.T) {
	body := `{"vulns":[{"id":"DEBIAN-CVE-2023-45853",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}`
	adv := queryOne(t, body, debianRef, "DEBIAN-CVE-2023-45853")

	if adv.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("vector = %q", adv.CVSSVector)
	}
	if adv.PublisherSeverity != "" {
		t.Errorf("PublisherSeverity = %q, the record carries no label", adv.PublisherSeverity)
	}
	if got := adv.Severity(); got != cvss.Critical {
		t.Errorf("Severity() = %s, want %s", got, cvss.Critical)
	}
	if score, ok := adv.CVSSScore(); !ok || score != 9.8 {
		t.Errorf("CVSSScore() = %.1f, %v; want 9.8, true", score, ok)
	}
}

func TestSeverityFromALabelAlone(t *testing.T) {
	body := `{"vulns":[{"id":"GHSA-labelled","database_specific":{"severity":"MODERATE"}}]}`
	adv := queryOne(t, body, debianRef, "GHSA-labelled")

	if adv.CVSSVector != "" {
		t.Errorf("vector = %q, the record carries none", adv.CVSSVector)
	}
	// GitHub's spelling is preserved on the field and normalised on the way out.
	if adv.PublisherSeverity != "MODERATE" {
		t.Errorf("PublisherSeverity = %q, want the publisher's own spelling", adv.PublisherSeverity)
	}
	if got := adv.Severity(); got != cvss.Medium {
		t.Errorf("Severity() = %s, want %s", got, cvss.Medium)
	}
	if _, ok := adv.CVSSScore(); ok {
		t.Error("CVSSScore() claimed a score with no vector")
	}
}

func TestNoSeverityAtAllIsUnknown(t *testing.T) {
	body := `{"vulns":[{"id":"DEBIAN-CVE-2010-4756","summary":"old"}]}`
	adv := queryOne(t, body, debianRef, "DEBIAN-CVE-2010-4756")

	if got := adv.Severity(); got != cvss.Unknown {
		t.Errorf("Severity() = %s, want %s -- a record with no rating must not read as low",
			got, cvss.Unknown)
	}
}

// A CVSS 4.0 vector is deliberately not scored, and a record carrying only one
// must report UNKNOWN rather than being run through the v3 formula.
func TestCVSS4OnlyIsNotScored(t *testing.T) {
	body := `{"vulns":[{"id":"DEBIAN-CVE-2026-56391",
	  "severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}]}`
	adv := queryOne(t, body, debianRef, "DEBIAN-CVE-2026-56391")

	if adv.CVSSVector != "" {
		t.Errorf("CVSSVector = %q, a 4.0 vector must not be stored as scorable", adv.CVSSVector)
	}
	if got := adv.Severity(); got != cvss.Unknown {
		t.Errorf("Severity() = %s, want %s", got, cvss.Unknown)
	}
}

// The v3 vector must be found even when a 4.0 entry is listed first, which is
// the ordering GHSA records actually use.
func TestV3IsPickedOutOfAMixedSeverityList(t *testing.T) {
	body := `{"vulns":[{"id":"GHSA-mixed","severity":[
	  {"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"},
	  {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}]}]}`
	adv := queryOne(t, body, debianRef, "GHSA-mixed")

	if score, ok := adv.CVSSScore(); !ok || score != 5.3 {
		t.Errorf("CVSSScore() = %.1f, %v; want 5.3, true", score, ok)
	}
}

// The vector string's own prefix decides the version, not the entry's type
// field, so a 4.0 vector mislabelled as CVSS_V3 cannot be scored with the v3
// formula.
func TestTheVectorPrefixWinsOverTheDeclaredType(t *testing.T) {
	body := `{"vulns":[{"id":"GHSA-mistyped","severity":[
	  {"type":"CVSS_V3","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}]}`
	adv := queryOne(t, body, debianRef, "GHSA-mistyped")

	if adv.CVSSVector != "" {
		t.Errorf("CVSSVector = %q, want empty", adv.CVSSVector)
	}
}

// TestSeverityTakesTheMoreSevereSource pins the merge rule. The two sources
// disagree in both directions in the real data, so this covers both.
func TestSeverityTakesTheMoreSevereSource(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		label  string
		want   string
	}{
		{
			// GHSA-23hp-3jrh-7fpw: the vector scores 7.5, GitHub says CRITICAL.
			name:   "label is harsher than the vector",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			label:  "CRITICAL",
			want:   cvss.Critical,
		},
		{
			// GHSA-2f9x-5v75-3qv4: the vector scores 5.3, GitHub says LOW.
			name:   "vector is harsher than the label",
			vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
			label:  "LOW",
			want:   cvss.Medium,
		},
		{
			name:   "they agree",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			label:  "CRITICAL",
			want:   cvss.Critical,
		},
		{
			// An unscorable vector must not drag a real label down to UNKNOWN.
			name:   "only the label is usable",
			vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			label:  "HIGH",
			want:   cvss.High,
		},
		{
			// ...nor may an unrecognised label drag down a real vector.
			name:   "only the vector is usable",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			label:  "SEVERE",
			want:   cvss.Critical,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adv := &Advisory{CVSSVector: tc.vector, PublisherSeverity: tc.label}
			if got := adv.Severity(); got != tc.want {
				t.Errorf("Severity() = %s, want %s (vector %q, label %q)",
					got, tc.want, tc.vector, tc.label)
			}
		})
	}
}

// TestSeverityIsBorrowedAcrossAliasedRecords is the Go case, and the reason
// borrowSeverity exists. OSV answers a golang.org/x/net query with both a GO-
// record -- import paths, no rating -- and the GHSA record aliased to it, which
// has the rating and no import paths. The import-path preference picks the GO
// record, so without the borrow every Go finding would report UNKNOWN while the
// answer sat in a record fetched in the same call.
func TestSeverityIsBorrowedAcrossAliasedRecords(t *testing.T) {
	body := `{"vulns":[
	  {"id":"GO-2023-2102","aliases":["CVE-2023-39325","GHSA-4374-p667-p6c8"],
	   "affected":[{"package":{"name":"golang.org/x/net"},
	     "ecosystem_specific":{"imports":[{"path":"golang.org/x/net/http2"}]}}]},
	  {"id":"GHSA-4374-p667-p6c8","aliases":["CVE-2023-39325","GO-2023-2102"],
	   "database_specific":{"severity":"HIGH"},
	   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
	   "affected":[{"package":{"name":"golang.org/x/net"}}]}
	]}`
	m, err := serve(t, body).Query(context.Background(), goRef("golang.org/x/net", "0.10.0"))
	if err != nil {
		t.Fatal(err)
	}

	adv := m["GO-2023-2102"]
	if adv == nil {
		t.Fatalf("GO-2023-2102 missing from %v", keysOf(m))
	}
	// The import paths must still come from the GO record: the borrow adds
	// severity, it does not change which record won.
	if len(adv.Pkgs) != 1 || adv.Pkgs[0] != "golang.org/x/net/http2" {
		t.Errorf("Pkgs = %v, the import-path preference was disturbed", adv.Pkgs)
	}
	if adv.PublisherSeverity != "HIGH" {
		t.Errorf("PublisherSeverity = %q, want HIGH borrowed from the GHSA record", adv.PublisherSeverity)
	}
	if got := adv.Severity(); got != cvss.High {
		t.Errorf("Severity() = %s, want %s", got, cvss.High)
	}
	// Every alias of the same vulnerability must answer the same way.
	for _, key := range []string{"CVE-2023-39325", "GHSA-4374-p667-p6c8"} {
		if m[key] == nil || m[key].Severity() != cvss.High {
			t.Errorf("%s: severity did not follow the alias", key)
		}
	}
}

// A record that states its own rating keeps it; the borrow only fills gaps.
func TestBorrowDoesNotOverwriteAStatedSeverity(t *testing.T) {
	body := `{"vulns":[
	  {"id":"GO-1","aliases":["CVE-1"],"database_specific":{"severity":"LOW"},
	   "affected":[{"package":{"name":"example.com/m"},
	     "ecosystem_specific":{"imports":[{"path":"example.com/m/pkg"}]}}]},
	  {"id":"GHSA-1","aliases":["CVE-1"],"database_specific":{"severity":"CRITICAL"},
	   "affected":[{"package":{"name":"example.com/m"}}]}
	]}`
	m, err := serve(t, body).Query(context.Background(), goRef("example.com/m", "1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if got := m["GO-1"].PublisherSeverity; got != "LOW" {
		t.Errorf("PublisherSeverity = %q, want the record's own LOW", got)
	}
}
