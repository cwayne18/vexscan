package analyze

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// The false-negative corpus is the tool's central safety guarantee stated as a
// test: for a component that is genuinely present -- installed on disk, with a
// readable manifest -- a known advisory against it must never come back as a
// clean verdict.
//
// A clean here (not_present or not_in_execute_path) would be a false negative:
// the one error the whole tool exists to avoid, a real CVE silently dropped.
// linked, reachable and undetermined are all acceptable outcomes for the corpus
// -- the assertion is only that the code was not declared absent or unreachable
// when it was neither.
//
// The cases run end to end through Run over a synthetic rootfs, against a served
// set of advisories, so they exercise the real inventory, evaluate and
// false-clean guard rather than a hand-built Finding. They are hermetic: no
// image is pulled and no network is touched, so this gate runs on every CI
// build. Its live counterpart, which pulls real known-vulnerable images, is
// TestFalseNegativeCorpus_Live.
//
// The corpus is deliberately additive. Every CVE a real scan is ever found to
// be wrong about belongs here as a row, so the regression is caught by go test
// rather than in production.
func TestFalseNegativeCorpus_Hermetic(t *testing.T) {
	for _, tc := range corpus {
		t.Run(tc.name, func(t *testing.T) {
			srv := corpusOSV(t, tc.advisories)
			root := writeTree(t, tc.tree)

			results, err := Run(context.Background(), Options{
				RootFS:     root,
				All:        true,
				Ecosystems: tc.ecosystems,
				OSVBaseURL: srv,
				Logf:       t.Logf,
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			res := results[0]
			matched := 0
			for _, f := range res.Findings {
				if f.CVE != tc.cve {
					continue
				}
				matched++
				if f.Status == ecosystem.StatusNotPresent || f.Status == ecosystem.StatusNotInPath {
					t.Errorf("FALSE NEGATIVE: %s / %s came back %q; the component is present, so a clean verdict is a dropped CVE\nevidence: %+v",
						f.Package, f.CVE, f.Status, f.Evidence)
				}
			}
			if matched == 0 {
				t.Fatalf("corpus case produced no finding for %s; the scan did not exercise the vulnerable component at all", tc.cve)
			}
		})
	}
}

// corpusCase is one known-exploitable target: a filesystem tree that installs a
// vulnerable component, the advisories the OSV mirror should return for it, and
// the CVE whose finding must not be clean.
type corpusCase struct {
	name       string
	tree       map[string]string
	ecosystems []string
	advisories map[string][]corpusAdvisory // "<ecosystem>/<name>" -> advisories
	cve        string
}

type corpusAdvisory struct {
	ID      string
	Aliases []string
}

// corpus is the seed set.
//
// pypi and maven are the first ecosystems because their fixtures need no
// compiled artifact: a dist-info with a real RECORD manifest, and a jar (a zip
// built in memory). Neither language removes dead code and the rootfs has no
// entrypoint to prove anything unreachable, so a present component is linked --
// not clean -- which is exactly the property under test. OS-package and Go
// entries, which need real ELF objects on disk to behave faithfully, are
// covered by the live corpus rather than forced into a text fixture that would
// make the tool answer not_present for want of a binary.
var corpus = []corpusCase{
	{
		// requests is installed with a real RECORD, so filesKnown is true and
		// the code is on disk. Nothing rules it out, so the verdict is linked.
		name: "pypi requests present is never clean",
		tree: map[string]string{
			"/etc/os-release": "ID=debian\nVERSION_ID=\"12\"\n",
			"/usr/lib/python3.12/site-packages/requests-2.20.0.dist-info/METADATA": "Name: requests\nVersion: 2.20.0\n",
			"/usr/lib/python3.12/site-packages/requests-2.20.0.dist-info/RECORD":   "requests/__init__.py,sha256=x,1\nrequests/sessions.py,sha256=x,1\n",
			"/usr/lib/python3.12/site-packages/requests/__init__.py":               "",
			"/usr/lib/python3.12/site-packages/requests/sessions.py":               "",
		},
		ecosystems: []string{"pypi"},
		advisories: map[string][]corpusAdvisory{
			"PyPI/requests": {{ID: "CVE-2018-18074"}},
		},
		cve: "CVE-2018-18074",
	},
	{
		// The canonical case the whole tool cites: an artifact that ships the
		// vulnerable class is still that artifact, and a version scanner is
		// right to flag it. A clean verdict here would be Log4Shell going
		// unreported.
		name: "maven log4j-core present is never clean",
		tree: map[string]string{
			"/etc/os-release":                "ID=debian\nVERSION_ID=\"12\"\n",
			"/opt/app/log4j-core-2.14.1.jar": log4jJar(),
		},
		ecosystems: []string{"maven"},
		advisories: map[string][]corpusAdvisory{
			"Maven/org.apache.logging.log4j:log4j-core": {{ID: "CVE-2021-44228"}},
		},
		cve: "CVE-2021-44228",
	},
}

// log4jJar builds a minimal log4j-core 2.14.1 jar: the maven coordinate
// descriptor that names it, and the class the Log4Shell advisory is about. The
// bytes are handed to writeTree as file content, so the jar lands on the rootfs
// exactly as a real one would.
func log4jJar() string {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	add := func(name, body string) {
		f, err := w.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			panic(err)
		}
	}
	add("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
		"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n")
	add("org/apache/logging/log4j/core/lookup/JndiLookup.class", "\xca\xfe\xba\xbe")
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.String()
}

// TestFalseNegativeCorpus_Live is the corpus against real images. It pulls
// public, known-vulnerable images and asserts the tool never returns a clean
// verdict for the CVE each is famous for. It is the guarantee the hermetic
// corpus approximates: a synthetic rootfs proves the evaluate logic is sound,
// but only a real image proves the inventory, extraction and closure agree with
// it on the artifacts people actually ship.
//
// Opt-in because it needs the network and a working image pull, matching the
// VEXSCAN_LIVE_* convention the rest of the tree uses:
//
//	VEXSCAN_LIVE_CORPUS=1 go test ./internal/analyze/ -run TestFalseNegativeCorpus_Live -v
//
// It queries the real OSV API (no OSVBaseURL override), so a CVE that OSV has
// re-keyed will surface here as a matched==0 failure -- which is the point: a
// corpus row that stops matching is a row that has stopped protecting anything.
func TestFalseNegativeCorpus_Live(t *testing.T) {
	if os.Getenv("VEXSCAN_LIVE_CORPUS") == "" {
		t.Skip("set VEXSCAN_LIVE_CORPUS=1 to pull real images and scan them")
	}
	cases := []struct {
		name      string
		image     string
		ecosystem string
		cve       string
	}{
		{
			name:      "log4shell demo image ships the vulnerable class",
			image:     "ghcr.io/christophetd/log4shell-vulnerable-app:latest",
			ecosystem: "maven",
			cve:       "CVE-2021-44228",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results, err := Run(context.Background(), Options{
				Image:      tc.image,
				All:        true,
				Ecosystems: []string{tc.ecosystem},
				Logf:       t.Logf,
			})
			if err != nil {
				t.Fatalf("Run(%s): %v", tc.image, err)
			}
			res := results[0]
			matched := 0
			for _, f := range res.Findings {
				if f.CVE != tc.cve {
					continue
				}
				matched++
				if f.Status == ecosystem.StatusNotPresent || f.Status == ecosystem.StatusNotInPath {
					t.Errorf("FALSE NEGATIVE: %s / %s came back %q on %s\nevidence: %+v",
						f.Package, f.CVE, f.Status, tc.image, f.Evidence)
				}
			}
			if matched == 0 {
				t.Fatalf("no finding for %s on %s; the corpus row is no longer exercising the vulnerable component (OSV re-key, or the image changed)", tc.cve, tc.image)
			}
		})
	}
}

// corpusOSV stands up an OSV mirror that answers /query, /querybatch and
// /vulns/{id} from the case's advisory table, and returns its base URL. It is a
// self-contained sibling of analyze_test.go's osvFake, kept separate so the
// corpus is not coupled to that test's assertions about query counts.
func corpusOSV(t *testing.T, table map[string][]corpusAdvisory) string {
	t.Helper()

	record := func(id string) map[string]any {
		var aliases []string
		for _, advs := range table {
			for _, a := range advs {
				if a.ID == id {
					aliases = a.Aliases
				}
			}
		}
		return map[string]any{"id": id, "aliases": aliases, "summary": id + " (corpus)"}
	}

	type q struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Version string `json:"version"`
	}
	idsFor := func(key string) []map[string]any {
		out := []map[string]any{}
		for _, a := range table[key] {
			out = append(out, map[string]any{"id": a.ID})
		}
		return out
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/querybatch"):
			var req struct {
				Queries []q `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			results := make([]map[string]any, 0, len(req.Queries))
			for _, query := range req.Queries {
				results = append(results, map[string]any{"vulns": idsFor(query.Package.Ecosystem + "/" + query.Package.Name)})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})

		case strings.HasSuffix(r.URL.Path, "/query"):
			var query q
			_ = json.NewDecoder(r.Body).Decode(&query)
			recs := []map[string]any{}
			for _, a := range table[query.Package.Ecosystem+"/"+query.Package.Name] {
				recs = append(recs, record(a.ID))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"vulns": recs})

		default: // /vulns/{id}
			_ = json.NewEncoder(w).Encode(record(path.Base(r.URL.Path)))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
