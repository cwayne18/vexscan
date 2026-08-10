package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
)

// This file answers advisory queries from OSV's published data export instead
// of from its API, so a scan can run on a host with no route to the internet.
//
// The export is the same records the API serves -- gs://osv-vulnerabilities,
// laid out as <ECOSYSTEM>/<ID>.json with an all.zip beside them -- which is the
// whole reason it is the right offline source. Every field the analysis depends
// on survives: Upstream for the distro-feed join, Pkgs for Go package
// granularity, Fixed for the fix plan, both severity fields. Nothing is
// translated, so nothing can be lost in translation, and buildMap below is
// literally the same function the API path calls.
//
// One thing does not survive, and it is the thing to understand before trusting
// an offline report: version matching moves. Against the API, osv.dev decides
// which records apply to openssl 3.0.11-1~deb12u2 and vexscan reads the verdict.
// Against an export there is nobody to ask, so that arithmetic happens here,
// against comparators this repository owns -- debver, rpmver, apkver, pep440,
// mavenver and semver. See compare.go, which has one for every ecosystem
// vexscan inventories.
//
// Where no comparator can order an ecosystem's versions, a record matches. That
// direction is not a coin toss. An over-matched advisory costs a reader a row
// they can dismiss; an under-matched one is a vulnerability the report says
// nothing about, which is the one failure this tool must never produce quietly.
// Every such match is counted and named in Notes, and the report prints it.

// Local is a read-only index over a local copy of OSV's data export.
//
// It satisfies the same two lookups Client does. Build one with OpenLocal.
type Local struct {
	// recs holds every decoded record once, deduplicated by OSV id -- the
	// export ships all.zip alongside the per-ecosystem copies of the same
	// advisories, so a naive walk sees most records twice.
	recs []vuln
	// byPkg indexes recs by the ecosystem family and package name an affected
	// entry names, which is how a query arrives. Family, not the full
	// ecosystem, because "Debian:12" and "Debian:13" records sit together and
	// the release is settled per-entry by affectedInScope.
	byPkg map[string]map[string][]int

	src string

	onCorrection func(Correction)

	// mu guards the counters, which are written from QueryBatch's callers on
	// whatever goroutine the scan is using and read once at the end.
	mu sync.Mutex
	// unordered counts records matched only because their versions could not be
	// ordered, keyed by ecosystem. See the file comment.
	unordered map[string]int
	// unorderedIDs keeps a few examples per ecosystem so the note can name
	// something a reader can go and look at.
	unorderedIDs map[string][]string
}

// maxNamedExamples bounds how many advisory ids a note lists before it stops.
// A reader needs a handle on the problem, not a second copy of the table.
const maxNamedExamples = 3

// OpenLocal reads an OSV data export into memory.
//
// path is either a directory laid out the way the bucket is:
//
//	gsutil -m rsync -r gs://osv-vulnerabilities /var/lib/osv
//
// or a single zip holding the same JSON records (the bucket's all.zip, or one
// ecosystem's). A directory is walked whole, so an export holding only the
// ecosystems a site actually scans works and is very much smaller.
//
// The whole export is held in memory. That is a deliberate trade: the records
// for the ecosystems one image needs are tens of megabytes, every query after
// the first is free, and the alternative -- a disk index -- is a database
// format to maintain for a lookup that is already fast enough.
func OpenLocal(path string, onCorrection func(Correction), logf func(string, ...any)) (*Local, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}

	l := &Local{
		src:          abs,
		onCorrection: onCorrection,
		byPkg:        map[string]map[string][]int{},
		unordered:    map[string]int{},
		unorderedIDs: map[string][]string{},
	}

	seen := map[string]bool{}
	var files, skipped, withdrawn int
	add := func(name string, data []byte) {
		var v vuln
		if err := json.Unmarshal(data, &v); err != nil || v.ID == "" {
			skipped++
			return
		}
		files++
		if seen[v.ID] {
			return
		}
		seen[v.ID] = true
		if v.Withdrawn != "" {
			// The publisher retracted this record. The API drops it and never
			// says so; the bucket keeps shipping it, so dropping it here is what
			// makes the two sources agree rather than a judgement of our own.
			//
			// Dropped at load and not at match time because a withdrawn record
			// is not an advisory that failed to apply -- it is one that no longer
			// exists, and nothing downstream should be able to see it.
			withdrawn++
			return
		}
		l.recs = append(l.recs, v)
	}

	if info.IsDir() {
		err = l.walkDir(abs, add)
	} else {
		err = readZip(abs, add)
	}
	if err != nil {
		return nil, err
	}

	if len(l.recs) == 0 {
		// An empty index would answer every query "no advisories", which is
		// indistinguishable from a clean image and is exactly the reading this
		// tool must never invite. Refuse to start instead.
		if withdrawn > 0 {
			return nil, fmt.Errorf("%s holds %d OSV record(s) and every one of them is withdrawn; there is nothing left to scan against", abs, withdrawn)
		}
		return nil, fmt.Errorf("%s holds no OSV records; expected <ECOSYSTEM>/<ID>.json files or a zip of them", abs)
	}

	l.index()
	logf("  advisory source: %d OSV record(s) from %s", len(l.recs), abs)
	if withdrawn > 0 {
		// Logged rather than carried into the report's caveats: these are records
		// the API would not have served either, so a note about them would be a
		// note the online scan never prints, about advisories that were retracted.
		logf("  %d withdrawn record(s) ignored, as the OSV API would have", withdrawn)
	}
	if skipped > 0 {
		// Not silent: a truncated download leaves unparseable files behind, and
		// the resulting scan would simply find less.
		logf("  ! %d file(s) under %s were not readable OSV records and were ignored", skipped, abs)
	}
	return l, nil
}

// walkDir reads every JSON record under root, and every zip in a directory that
// held none.
//
// The two-pass shape per directory is what keeps a bucket rsync from being read
// twice: the export ships Go/all.zip beside Go/GO-2021-0001.json, and the loose
// files are the cheaper of the two to decode. Deduplication by id makes this an
// optimisation rather than a correctness requirement.
func (l *Local) walkDir(root string, add func(string, []byte)) error {
	var zips []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			add(path, data)
		case ".zip":
			zips = append(zips, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Sorted so a run is reproducible: with duplicate ids across zips the first
	// read wins, and "first" has to mean something stable.
	sort.Strings(zips)
	for _, z := range zips {
		if err := readZip(z, add); err != nil {
			return fmt.Errorf("%s: %w", z, err)
		}
	}
	return nil
}

func readZip(path string, add func(string, []byte)) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		const maxJSON = 50 << 20 // 50 MiB
		lr := &io.LimitedReader{R: rc, N: maxJSON + 1}
		data, err := io.ReadAll(lr)
		rc.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if lr.N <= 0 {
			return fmt.Errorf("%s: JSON record too large (>%d bytes)", f.Name, maxJSON)
		}
		add(f.Name, data)
	}
	return nil
}

// index files every record under each package name it names.
//
// The key comes from the record's own affected entries rather than from the
// directory it was found in. The directory is where the export happened to put
// the file; the entry is the record stating what it is about, and it is the only
// one of the two that survives being read out of an all.zip.
func (l *Local) index() {
	for i := range l.recs {
		for _, aff := range l.recs[i].Affected {
			name := aff.Package.Name
			if name == "" {
				continue
			}
			fam := family(aff.Package.Ecosystem)
			byName := l.byPkg[fam]
			if byName == nil {
				byName = map[string][]int{}
				l.byPkg[fam] = byName
			}
			// A record with several entries for one package (one per release)
			// must be listed once, or it would be matched and decoded twice.
			if n := len(byName[name]); n > 0 && byName[name][n-1] == i {
				continue
			}
			byName[name] = append(byName[name], i)
		}
	}
}

// family is the part of an OSV ecosystem before the release suffix: "Debian:12"
// is "Debian", "Alpine:v3.19" is "Alpine", "Go" is "Go". It is the granularity
// the export's directories use and the granularity a comparator is chosen at.
func family(ecosystem string) string {
	if i := strings.IndexByte(ecosystem, ':'); i >= 0 {
		return ecosystem[:i]
	}
	return ecosystem
}

// Describe names this source for the report's provenance line.
func (l *Local) Describe() string { return "local OSV export " + l.src }

// Query returns advisory-id -> Advisory for ref, the same map the API path
// builds and keyed the same way.
func (l *Local) Query(_ context.Context, ref Ref) (map[string]*Advisory, error) {
	advs, corrections := buildMap(ref, l.match(ref))
	l.report(corrections)
	return advs, nil
}

// QueryBatch resolves many refs. There is no round trip to amortise here, so it
// is Query in a loop -- the batching on the API path exists to avoid thousands
// of HTTP requests, not because the matching benefits from being done together.
func (l *Local) QueryBatch(ctx context.Context, refs []Ref) ([]map[string]*Advisory, error) {
	out := make([]map[string]*Advisory, len(refs))
	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		advs, err := l.Query(ctx, ref)
		if err != nil {
			return nil, err
		}
		out[i] = advs
	}
	return out, nil
}

func (l *Local) report(corrections []Correction) {
	if l.onCorrection == nil {
		return
	}
	for _, c := range corrections {
		l.onCorrection(c)
	}
}

// match is the half osv.dev does on the API path: which of the records naming
// this package actually apply to this version.
func (l *Local) match(ref Ref) []vuln {
	byName := l.byPkg[family(ref.Ecosystem)]
	if byName == nil {
		return nil
	}
	var out []vuln
	for _, i := range byName[ref.Name] {
		v := l.recs[i]
		if l.applies(ref, v) {
			out = append(out, v)
		}
	}
	return out
}

func (l *Local) applies(ref Ref, v vuln) bool {
	for _, aff := range v.Affected {
		if aff.Package.Name != ref.Name {
			continue
		}
		// The same rule advisoryFor reads fixed versions under, so a Debian:13
		// entry cannot answer a Debian:12 query here either.
		if !affectedInScope(ref, aff.Package.Ecosystem) {
			continue
		}
		if l.versionAffected(ref, v, aff) {
			return true
		}
	}
	return false
}

func (l *Local) versionAffected(ref Ref, v vuln, aff affected) bool {
	version := normalizeVersion(ref)
	if version == "" {
		// A ref with no version asks for every advisory against the package,
		// which is a question the export can answer exactly.
		return true
	}
	// An entry that states neither an enumeration nor a range is the record
	// saying the package is affected outright. OSV's schema means it that way,
	// and it is also the reading that cannot lose a finding.
	if len(aff.Versions) == 0 && len(aff.Ranges) == 0 {
		return true
	}
	// The enumeration needs no comparator, so it is tried first and its answer
	// is exact. Both spellings are checked because normalizeVersion trims a Go
	// module's "v" and the enumeration may or may not carry it.
	if slices.Contains(aff.Versions, version) || slices.Contains(aff.Versions, ref.Version) {
		return true
	}

	for _, rng := range aff.Ranges {
		if strings.EqualFold(rng.Type, "GIT") {
			// GIT ranges bound commits, not releases. There is no ordering
			// between a commit hash and 3.0.11 to get wrong, so this is not a
			// comparator failure and is not counted as one: a record whose only
			// ranges are GIT falls through to its enumeration or to no match,
			// exactly as it would on the API.
			continue
		}
		cmp := comparatorFor(rng.Type, ref.Ecosystem)
		if cmp == nil {
			l.noteUnordered(ref, v, "no version comparator")
			return true
		}
		events, ok := sortEvents(rng, cmp)
		if !ok {
			l.noteUnordered(ref, v, "unorderable versions in the record")
			return true
		}
		if sweep(version, events, cmp) {
			return true
		}
	}
	return false
}

// noteUnordered records that a match was made without being able to do the
// arithmetic. See the file comment for why this direction, and Notes for what
// becomes of it.
func (l *Local) noteUnordered(ref Ref, v vuln, why string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := ref.Ecosystem + " (" + why + ")"
	l.unordered[key]++
	if ids := l.unorderedIDs[key]; len(ids) < maxNamedExamples && !slices.Contains(ids, v.ID) {
		l.unorderedIDs[key] = append(ids, v.ID)
	}
}

// Notes is what the report has to say about this source beyond its name: the
// matches it could not decide on their merits.
//
// It is a separate optional method rather than part of the advisory-source
// interface because it is a property of matching locally, and the API path has
// nothing to say here -- osv.dev did the arithmetic and did not report on it.
func (l *Local) Notes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.unordered) == 0 {
		return nil
	}
	keys := make([]string, 0, len(l.unordered))
	for k := range l.unordered {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		note := fmt.Sprintf("%d advisory match(es) for %s were kept without checking the installed version: %s.",
			l.unordered[k], k, "matching offline errs toward reporting")
		if ids := l.unorderedIDs[k]; len(ids) > 0 {
			note += " For example " + strings.Join(ids, ", ") + "."
		}
		out = append(out, note)
	}
	return out
}

// comparator orders two versions. ok is false when it cannot -- an unparseable
// version, or a scheme this one does not implement -- and a false there must
// never be read as "equal", because callers act on the ordering.
type comparator func(a, b string) (result int, ok bool)

// sortEvents flattens a range's events into version order.
//
// OSV does not promise the events in a range are listed in order, and the sweep
// below depends on it. ok is false if any version in the range cannot be
// ordered: a partial reading of the boundaries could place a version outside a
// range it is really inside, which is the losing direction.
func sortEvents(rng versionRange, cmp comparator) ([]event, bool) {
	var events []event
	for _, ev := range rng.Events {
		for _, pair := range []struct {
			raw  string
			kind eventKind
		}{
			{ev.Introduced, introduced},
			{ev.Fixed, fixed},
			{ev.LastAffected, lastAffected},
		} {
			if pair.raw == "" {
				continue
			}
			// "0" is OSV's spelling of "from the beginning of time". It is not
			// necessarily a version any comparator can parse -- an rpm EVR of
			// "0" is fine, a semver "v0" is not -- and it needs no comparison
			// anyway, since everything is at or above it.
			if pair.raw != zeroVersion {
				if _, ok := cmp(pair.raw, pair.raw); !ok {
					return nil, false
				}
			}
			events = append(events, event{version: pair.raw, kind: pair.kind})
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		c, ok := compareBoundary(events[i].version, events[j].version, cmp)
		if !ok {
			return false
		}
		if c != 0 {
			return c < 0
		}
		// Ties put an introduced before the event that closes it, so a range of
		// a single version is still a range.
		return events[i].kind < events[j].kind
	})
	return events, true
}

// zeroVersion is OSV's open-at-the-bottom introduced event.
const zeroVersion = "0"

func compareBoundary(a, b string, cmp comparator) (int, bool) {
	switch {
	case a == zeroVersion && b == zeroVersion:
		return 0, true
	case a == zeroVersion:
		return -1, true
	case b == zeroVersion:
		return 1, true
	}
	return cmp(a, b)
}

// sweep applies OSV's range semantics: walk the boundaries in version order and
// whichever one the version last passed decides. It is affectedByEvents with a
// comparator that is not hard-coded to semver.
func sweep(version string, events []event, cmp comparator) bool {
	var hit bool
	for _, ev := range events {
		c, ok := compareBoundary(version, ev.version, cmp)
		if !ok {
			// Reached only if a boundary became uncomparable after sortEvents
			// vetted it. Treating it as passed keeps the finding.
			return true
		}
		switch ev.kind {
		case introduced:
			if c >= 0 {
				hit = true
			}
		case fixed:
			if c >= 0 {
				hit = false
			}
		case lastAffected:
			if c > 0 {
				hit = false
			}
		}
	}
	return hit
}
