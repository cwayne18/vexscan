package suse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/cwayne18/vexscan/internal/distrofeed"
	"github.com/cwayne18/vexscan/internal/rpmver"
)

// csafDocument is the slice of a CSAF-VEX document this provider reads.
type csafDocument struct {
	ProductTree     csafProductTree     `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafProductTree struct {
	Branches []csafBranch `json:"branches"`
}

// csafBranch is a node in the product tree. A node either names a product (with
// a CPE helper this provider joins on) or nests further branches.
type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}

type csafProduct struct {
	ProductID string `json:"product_id"`
	Helper    struct {
		CPE string `json:"cpe"`
	} `json:"product_identification_helper"`
}

type csafVulnerability struct {
	CVE           string            `json:"cve"`
	ProductStatus csafProductStatus `json:"product_status"`
}

// csafProductStatus is the per-product verdict lists. Each entry is a composite
// "<product>:<package-ref>" product id.
type csafProductStatus struct {
	KnownAffected    []string `json:"known_affected"`
	KnownNotAffected []string `json:"known_not_affected"`
	Recommended      []string `json:"recommended"`
}

// fetchAll fetches and parses the document for each CVE, bounded to maxParallel
// concurrent requests. It returns every advisory it could read keyed by
// uppercase CVE id, plus a joined error for the ones it could not. A 404 is not
// an error: it means SUSE has no record for that CVE, which is a silent decline,
// not a failure.
func (p *Provider) fetchAll(ctx context.Context, cves []string) (map[string]*advisory, error) {
	type result struct {
		cve string
		adv *advisory
		err error
	}
	results := make(chan result, len(cves))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for _, cve := range cves {
		wg.Add(1)
		go func(cve string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- result{cve: cve, err: ctx.Err()}
				return
			}
			adv, err := p.fetchOne(ctx, cve)
			results <- result{cve: cve, adv: adv, err: err}
		}(cve)
	}
	go func() { wg.Wait(); close(results) }()

	docs := map[string]*advisory{}
	var errs []error
	for r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.cve, r.err))
			continue
		}
		if r.adv != nil {
			docs[strings.ToUpper(r.cve)] = r.adv
		}
	}
	if len(errs) > 0 {
		return docs, fmt.Errorf("suse: %d advisory fetch(es) failed: %w", len(errs), errors.Join(errs...))
	}
	return docs, nil
}

// fetchOne fetches and parses one CVE's document. A 404 returns (nil, nil): no
// record is a decline, not a failure.
func (p *Provider) fetchOne(ctx context.Context, cve string) (*advisory, error) {
	url := p.docURL(cve)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", url, resp.Status)
	}
	return parseDocument(resp.Body, url)
}

// parseDocument decodes a CSAF-VEX document into the reduced advisory form,
// requiring a single well-formed JSON object and nothing after it so a truncated
// or trailing-garbage response is rejected rather than half-trusted.
func parseDocument(r io.Reader, url string) (*advisory, error) {
	dec := json.NewDecoder(r)
	var doc csafDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", url, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse %s: unexpected trailing data", url)
		}
		return nil, fmt.Errorf("parse %s: %w", url, err)
	}

	adv := &advisory{
		url:           url,
		cpeToProducts: map[string][]string{},
		vulns:         map[string]*vulnStatus{},
	}
	collectCPEs(doc.ProductTree.Branches, adv.cpeToProducts)
	for _, v := range doc.Vulnerabilities {
		if v.CVE == "" {
			continue
		}
		adv.vulns[strings.ToUpper(v.CVE)] = buildVulnStatus(v.ProductStatus)
	}
	return adv, nil
}

// collectCPEs walks the product tree and records, for every product that carries
// a CPE helper, the CPE to the product name(s) that use it.
func collectCPEs(branches []csafBranch, out map[string][]string) {
	for _, b := range branches {
		if b.Product != nil && b.Product.Helper.CPE != "" && b.Product.ProductID != "" {
			cpe := b.Product.Helper.CPE
			out[cpe] = append(out[cpe], b.Product.ProductID)
		}
		if len(b.Branches) > 0 {
			collectCPEs(b.Branches, out)
		}
	}
}

// buildVulnStatus indexes one vulnerability's product-status lists by
// (product, package) for O(1) lookup during classification.
func buildVulnStatus(ps csafProductStatus) *vulnStatus {
	vs := &vulnStatus{
		notAffected: map[string]map[string]bool{},
		affected:    map[string]map[string]bool{},
		fixed:       map[string]map[string]string{},
	}
	for _, pid := range ps.KnownNotAffected {
		product, pkg, ok := splitProductPkg(pid)
		if !ok {
			continue
		}
		addBool(vs.notAffected, product, pkg)
	}
	for _, pid := range ps.KnownAffected {
		product, pkg, ok := splitProductPkg(pid)
		if !ok {
			continue
		}
		addBool(vs.affected, product, pkg)
	}
	for _, pid := range ps.Recommended {
		product, ref, ok := splitProductPkg(pid)
		if !ok {
			continue
		}
		// The recommended package ref is a full name-version-release; the fix is
		// its version-release, and the name is what a finding is keyed by.
		name, evr := splitNVR(ref)
		if name == "" || evr == "" {
			continue
		}
		if vs.fixed[product] == nil {
			vs.fixed[product] = map[string]string{}
		}
		// Keep the highest fixed version when a product lists several for one
		// package. The installed version must reach the fix to clear, so the
		// highest is the safe threshold: a lower one could clear a package that
		// has not actually received the later fix.
		if cur, ok := vs.fixed[product][name]; !ok || rpmverGreater(evr, cur) {
			vs.fixed[product][name] = evr
		}
	}
	return vs
}

func addBool(m map[string]map[string]bool, product, pkg string) {
	if m[product] == nil {
		m[product] = map[string]bool{}
	}
	m[product][pkg] = true
}

// splitProductPkg splits a CSAF product id "<product>:<package-ref>" on its
// first colon. A product name carries no colon, so the first is the boundary.
func splitProductPkg(pid string) (product, pkg string, ok bool) {
	i := strings.IndexByte(pid, ':')
	if i <= 0 || i == len(pid)-1 {
		return "", "", false
	}
	return pid[:i], pid[i+1:], true
}

// splitNVR splits an rpm "name-version-release" into its name and its
// version-release, by taking the last two dash-separated fields as version and
// release. An rpm version and release never contain a dash, so this is exactly
// rpm's own boundary and correctly keeps a dashed name like
// "libopenssl1_1-32bit" whole.
func splitNVR(s string) (name, evr string) {
	last := strings.LastIndexByte(s, '-')
	if last <= 0 {
		return "", ""
	}
	prev := strings.LastIndexByte(s[:last], '-')
	if prev <= 0 {
		return "", ""
	}
	return s[:prev], s[prev+1:]
}

// uniqueCVEs is the set of CVE ids across all queried packages, upper-cased and
// filtered to real CVE ids -- the only thing SUSE's per-CVE feed is keyed by, so
// OSV aliases like GHSA ids are dropped rather than fetched to a certain 404.
func uniqueCVEs(pkgs []distrofeed.PkgRef) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range pkgs {
		for _, id := range p.CVEs {
			up := strings.ToUpper(strings.TrimSpace(id))
			if !cveRE.MatchString(up) || seen[up] {
				continue
			}
			seen[up] = true
			out = append(out, up)
		}
	}
	return out
}

func rpmverGreater(a, b string) bool { return rpmver.Compare(a, b) > 0 }

func (p *Provider) docURL(cve string) string {
	return p.base() + "/" + strings.ToLower(cve) + ".json"
}

func (p *Provider) base() string {
	if p.BaseURL != "" {
		return strings.TrimRight(p.BaseURL, "/")
	}
	return DefaultBaseURL
}

func (p *Provider) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return http.DefaultClient
}
