package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// queryFixture serves body from /v1/query and returns what the ref resolved to
// along with everything the client set aside.
func queryFixture(t *testing.T, ref Ref, body string) (map[string]*Advisory, []Correction) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	var got []Correction
	c := NewClient()
	c.BaseURL = srv.URL
	c.OnCorrection = func(corr Correction) { got = append(got, corr) }

	m, err := c.Query(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return m, got
}

// degradedRecord is the shape rancher/rancher advisories actually arrive in:
// review_status UNREVIEWED, a standard range open at the top because the
// versions are "+incompatible" ones the importer would not assert, and the real
// answer parked in custom_ranges.
const degradedRecord = `{
  "vulns": [
    {
      "id": "GO-2025-3625",
      "aliases": ["CVE-2025-23388", "GHSA-xxxx-yyyy-zzzz"],
      "database_specific": {"review_status": "UNREVIEWED"},
      "affected": [
        {
          "package": {"name": "github.com/rancher/rancher", "ecosystem": "Go"},
          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
          "ecosystem_specific": {
            "custom_ranges": [{"type": "ECOSYSTEM", "events": [
              {"introduced": "2.10.0"}, {"fixed": "2.10.11"},
              {"introduced": "2.11.0"}, {"fixed": "2.11.13"}
            ]}]
          }
        }
      ]
    }
  ]
}`

func TestDegradedGoRecordIsCorrectedByItsOwnRanges(t *testing.T) {
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), degradedRecord)

	if len(m) != 0 {
		t.Fatalf("expected the advisory to be set aside, got %v", keysOf(m))
	}
	if len(corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(corrections))
	}
	c := corrections[0]
	if c.Advisory != "GO-2025-3625" {
		t.Errorf("advisory = %q", c.Advisory)
	}
	if c.Package != "github.com/rancher/rancher" || c.Version != "v2.15.0" {
		t.Errorf("package/version = %q@%q", c.Package, c.Version)
	}
	// The rendered ranges are the whole justification for the drop, so they have
	// to name the real intervals rather than the degraded one.
	if want := "2.10.0-2.10.11, 2.11.0-2.11.13"; c.Ranges != want {
		t.Errorf("ranges = %q, want %q", c.Ranges, want)
	}
	if !strings.Contains(c.String(), "does not apply to github.com/rancher/rancher@v2.15.0") {
		t.Errorf("String() = %q", c.String())
	}
}

func TestVersionInsideACustomRangeIsStillReported(t *testing.T) {
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.11.2"), degradedRecord)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("2.11.2 is inside 2.11.0-2.11.13 and must be reported, got %v", keysOf(m))
	}
	if len(corrections) != 0 {
		t.Errorf("expected no corrections, got %v", corrections)
	}
}

// A version below every introduced event is outside the ranges just as surely
// as one above every fix, and the sweep has to say so.
func TestVersionBelowEveryCustomRangeIsCorrected(t *testing.T) {
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.9.4"), degradedRecord)

	if len(m) != 0 {
		t.Errorf("expected the advisory to be set aside, got %v", keysOf(m))
	}
	if len(corrections) != 1 {
		t.Errorf("expected 1 correction, got %d", len(corrections))
	}
}

// The correction exists because UNREVIEWED means the database could not say. A
// curated record's ranges are the curated answer, so custom_ranges does not get
// to overrule them even when it disagrees.
func TestAReviewedRecordIsNotCorrected(t *testing.T) {
	body := strings.Replace(degradedRecord, `"review_status": "UNREVIEWED"`, `"review_status": "REVIEWED"`, 1)
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("a REVIEWED record must be matched on its own ranges, got %v", keysOf(m))
	}
	if len(corrections) != 0 {
		t.Errorf("expected no corrections, got %v", corrections)
	}
}

// A record with no review_status at all is not the Go database's degraded
// shape, and is left alone for the same reason.
func TestARecordWithNoReviewStatusIsNotCorrected(t *testing.T) {
	body := strings.Replace(degradedRecord, `"database_specific": {"review_status": "UNREVIEWED"},`, "", 1)
	m, _ := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("expected the advisory to survive, got %v", keysOf(m))
	}
}

// The trigger is a standard range that cannot close, not merely one that
// disagrees. A record stating where the flaw stops was matched on its merits.
func TestAStandardRangeWithAFixIsNotCorrected(t *testing.T) {
	body := strings.Replace(degradedRecord,
		`"events": [{"introduced": "0"}]`,
		`"events": [{"introduced": "0"}, {"fixed": "3.0.0"}]`, 1)
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("a bounded standard range must decide, got %v", keysOf(m))
	}
	if len(corrections) != 0 {
		t.Errorf("expected no corrections, got %v", corrections)
	}
}

func TestALastAffectedStandardRangeIsNotCorrected(t *testing.T) {
	body := strings.Replace(degradedRecord,
		`"events": [{"introduced": "0"}]`,
		`"events": [{"introduced": "0"}, {"last_affected": "2.20.0"}]`, 1)
	m, _ := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("a bounded standard range must decide, got %v", keysOf(m))
	}
}

// The corroboration gate, in the shape that produced it: OSV matches every
// returned record against the same package and version, so at v2.14.0 the
// aliased GHSA comes back too -- reached through its own ranges -- and it
// disagrees with custom_ranges. Two sources beat one reinterpreted record.
const corroboratedRecords = `{
  "vulns": [
    {
      "id": "GO-2025-3625",
      "aliases": ["CVE-2025-23388", "GHSA-xxxx-yyyy-zzzz"],
      "database_specific": {"review_status": "UNREVIEWED"},
      "affected": [
        {
          "package": {"name": "github.com/rancher/rancher", "ecosystem": "Go"},
          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
          "ecosystem_specific": {
            "custom_ranges": [{"type": "ECOSYSTEM", "events": [
              {"introduced": "2.10.0"}, {"fixed": "2.10.11"}
            ]}]
          }
        }
      ]
    },
    {
      "id": "GHSA-xxxx-yyyy-zzzz",
      "aliases": ["CVE-2025-23388"],
      "affected": [
        {
          "package": {"name": "github.com/rancher/rancher", "ecosystem": "Go"},
          "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "2.0.0+incompatible"}, {"fixed": "2.14.1+incompatible"}
          ]}]
        }
      ]
    }
  ]
}`

func TestACorroboratedRecordSurvivesItsOwnCustomRanges(t *testing.T) {
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.14.0"), corroboratedRecords)

	if len(corrections) != 0 {
		t.Fatalf("a second record for the same vulnerability must block the drop, got %v", corrections)
	}
	for _, key := range []string{"GO-2025-3625", "GHSA-xxxx-yyyy-zzzz", "CVE-2025-23388"} {
		if _, ok := m[key]; !ok {
			t.Errorf("expected key %q, got %v", key, keysOf(m))
		}
	}
}

// The pair that made the corroboration gate need a qualifier. GO-2024-2929 and
// GO-2024-3220 are real: aliases of each other, both UNREVIEWED, both open at
// the top, both carrying custom_ranges that end well below 2.15.0. Neither
// asserts an upper bound, so neither can vouch for the other -- and if they
// could, every such pair would be permanently uncorrectable.
const degradedPair = `{
  "vulns": [
    {
      "id": "GO-2024-2929",
      "aliases": ["CVE-2023-32196", "GO-2024-3220"],
      "database_specific": {"review_status": "UNREVIEWED"},
      "affected": [
        {
          "package": {"name": "github.com/rancher/rancher", "ecosystem": "Go"},
          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
          "ecosystem_specific": {"custom_ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "2.7.0"}, {"fixed": "2.7.14"}
          ]}]}
        }
      ]
    },
    {
      "id": "GO-2024-3220",
      "aliases": ["CVE-2023-32196", "GO-2024-2929"],
      "database_specific": {"review_status": "UNREVIEWED"},
      "affected": [
        {
          "package": {"name": "github.com/rancher/rancher", "ecosystem": "Go"},
          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
          "ecosystem_specific": {"custom_ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "2.7.0"}, {"fixed": "2.8.9"}
          ]}]}
        }
      ]
    }
  ]
}`

func TestTwoDegradedRecordsDoNotCorroborateEachOther(t *testing.T) {
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), degradedPair)

	if len(corrections) != 2 {
		t.Fatalf("expected both records corrected, got %v", corrections)
	}
	if len(m) != 0 {
		t.Errorf("expected an empty map, got %v", keysOf(m))
	}
}

// A record with an open range and no custom_ranges cannot be corrected -- it
// offers nothing better -- and for the same reason it cannot corroborate. It
// never said where the flaw ends.
func TestADegradedRecordWithNoCustomRangesSurvivesAndDoesNotCorroborate(t *testing.T) {
	body := strings.Replace(degradedPair,
		`"ecosystem_specific": {"custom_ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "2.7.0"}, {"fixed": "2.8.9"}
          ]}]}`, `"ecosystem_specific": {}`, 1)
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)

	if len(corrections) != 1 || corrections[0].Advisory != "GO-2024-2929" {
		t.Fatalf("expected only GO-2024-2929 corrected, got %v", corrections)
	}
	// It offers no better data, so it stays -- which is the direction this whole
	// mechanism is allowed to be wrong in.
	if _, ok := m["GO-2024-3220"]; !ok {
		t.Errorf("expected GO-2024-3220 to survive, got %v", keysOf(m))
	}
}

// custom_ranges is the Go database's field. Elsewhere its absence means
// nothing, and an open range is an ordinary open range.
func TestNonGoRecordsAreNeverCorrected(t *testing.T) {
	body := strings.ReplaceAll(degradedRecord, "github.com/rancher/rancher", "openssl")
	ref := Ref{Ecosystem: "Debian:12", Name: "openssl", Version: "2.15.0"}
	m, corrections := queryFixture(t, ref, body)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("expected the advisory to survive, got %v", keysOf(m))
	}
	if len(corrections) != 0 {
		t.Errorf("expected no corrections, got %v", corrections)
	}
}

// A version that cannot be ordered is not evidence of anything. Reading half
// the boundaries could place a version outside a range it is really inside, so
// an unreadable custom range abandons the correction rather than guessing.
func TestAnUnparseableCustomRangeAbandonsTheCorrection(t *testing.T) {
	body := strings.Replace(degradedRecord, `{"fixed": "2.11.13"}`, `{"fixed": "2.11.13-rancher~1+patch"}`, 1)
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("expected the advisory to survive, got %v", keysOf(m))
	}
	if len(corrections) != 0 {
		t.Errorf("expected no corrections, got %v", corrections)
	}
}

func TestAnUnparseableQueriedVersionAbandonsTheCorrection(t *testing.T) {
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "(devel)"), degradedRecord)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("expected the advisory to survive, got %v", keysOf(m))
	}
	if len(corrections) != 0 {
		t.Errorf("expected no corrections, got %v", corrections)
	}
}

// A custom range with no fix is the degraded shape twice over: it says the flaw
// starts somewhere and never closes, which excludes nothing above it.
func TestAnOpenCustomRangeStillReports(t *testing.T) {
	body := strings.Replace(degradedRecord,
		`{"introduced": "2.11.0"}, {"fixed": "2.11.13"}`, `{"introduced": "2.11.0"}`, 1)
	m, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)

	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("2.15.0 is inside an open range from 2.11.0, got %v", keysOf(m))
	}
	if len(corrections) != 0 {
		t.Errorf("expected no corrections, got %v", corrections)
	}
}

func TestCustomRangeVersionsAreComparedNumerically(t *testing.T) {
	// String ordering would put "2.9.0" after "2.11.13" and read 2.15.0 as
	// inside an open range starting at 2.9.0.
	body := strings.Replace(degradedRecord,
		`{"introduced": "2.10.0"}, {"fixed": "2.10.11"}`,
		`{"introduced": "2.9.0"}, {"fixed": "2.9.5"}`, 1)
	_, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)

	if len(corrections) != 1 {
		t.Fatalf("expected 1 correction, got %v", corrections)
	}
	if want := "2.9.0-2.9.5, 2.11.0-2.11.13"; corrections[0].Ranges != want {
		t.Errorf("ranges = %q, want %q", corrections[0].Ranges, want)
	}
}

func TestCustomRangeLastAffectedIsInclusive(t *testing.T) {
	body := strings.Replace(degradedRecord,
		`{"introduced": "2.11.0"}, {"fixed": "2.11.13"}`,
		`{"introduced": "2.11.0"}, {"last_affected": "2.15.0"}`, 1)

	// The bound is inclusive, so the version it names is still affected.
	m, _ := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.0"), body)
	if _, ok := m["GO-2025-3625"]; !ok {
		t.Errorf("last_affected names an affected version, got %v", keysOf(m))
	}

	_, corrections := queryFixture(t, goRef("github.com/rancher/rancher", "v2.15.1"), body)
	if len(corrections) != 1 {
		t.Fatalf("expected 1 correction past last_affected, got %v", corrections)
	}
	if want := "2.10.0-2.10.11, 2.11.0-2.15.0"; corrections[0].Ranges != want {
		t.Errorf("ranges = %q, want %q", corrections[0].Ranges, want)
	}
}

// The queried version arrives with a "v" the custom ranges never carry, and
// real Go versions of a v2+ module without a /vN path carry "+incompatible" on
// top. Neither spelling may change the arithmetic.
func TestVersionSpellingsCompareEqual(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"v2.15.0", "2.15.0", 0},
		{"2.15.0+incompatible", "2.15.0", 0},
		{"v2.15.0+incompatible", "2.15.0", 0},
		{"2.9.0", "2.11.0", -1},
		{"2.15.0", "2.11.13", 1},
	} {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
