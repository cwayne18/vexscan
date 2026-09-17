// Package haul reads a haul: the portable archive hauler builds to carry
// images, charts and files across an airgap.
//
// A haul is an OCI image layout. hauler stores every artifact it collects as
// an OCI artifact under a store directory, and `hauler store save` tars that
// directory -- each entry mapped to its base name, so index.json, oci-layout
// and blobs/ land at the archive root -- and compresses it with zstd. Nothing
// in here parses a hauler-specific container format, because there isn't one:
// this reads index.json and classifies what it finds.
//
// That matters more than it sounds. An OCI layout is a transport skopeo
// already speaks, so an image inside a haul can be extracted and scanned
// without a registry, which is the entire reason someone built a haul in the
// first place. The alternative -- reading a haul only to recover a list of
// references and then pulling them -- would need exactly the network the haul
// exists to do without.
//
// What this package will not do is guess. A haul carries charts and files
// alongside its images, and a chart is not something vexscan can scan; a store
// entry whose kind cannot be established is not quietly assumed to be
// uninteresting. Everything found is returned and classified, including the
// things the caller will have to decline, so the caller can say what it is not
// scanning instead of returning a smaller number with no explanation.
package haul

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Annotation keys hauler writes on a store entry.
//
// Only the first is an OCI standard. The other three are hauler's, and the
// reason to care about them is that the standard one is not enough: hauler
// parses store names with an empty default registry on purpose (see its
// pkg/reference), so AnnotationRefName has had the registry stripped and reads
// "rancher/hardened-kubernetes:v1.31.0" for an image whose real name is
// "docker.io/rancher/hardened-kubernetes:v1.31.0".
//
// Scanning under the stripped name would be a quiet correctness bug rather
// than a cosmetic one. The reference is what names the target in the report,
// what becomes the product purl in a VEX document, and what a hub index is
// keyed on -- so a haul scan and a registry scan of the same image would
// disagree about what they had looked at, and the hub would accumulate two
// products for one thing. annOriginalRef is hauler's own record of the
// reference an artifact was added under, and annContainerdName the fully
// qualified name it writes for containerd; either one recovers the registry.
const (
	annRefName        = "org.opencontainers.image.ref.name"
	annOriginalRef    = "hauler.dev/original-ref"
	annContainerdName = "io.containerd.image.name"
	annKind           = "kind"
)

// Kind annotation values hauler writes. The referrers kind carries the
// referring manifest's digest after the prefix, so it is matched as one.
const (
	kindImage      = "dev.hauler/image"
	kindImageIndex = "dev.hauler/imageIndex"
	kindSigs       = "dev.hauler/sigs"
	kindAtts       = "dev.hauler/atts"
	kindSboms      = "dev.hauler/sboms"
	kindReferrers  = "dev.hauler/referrers"
)

// Media types, enough to tell an image from a chart from a file when the kind
// annotation is absent -- which it is on anything a hauler v1 wrote.
const (
	mtOCIIndex        = "application/vnd.oci.image.index.v1+json"
	mtDockerList      = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	mtDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	mtDockerConfig    = "application/vnd.docker.container.image.v1+json"
	mtOCIConfig       = "application/vnd.oci.image.config.v1+json"
	mtChartConfig     = "application/vnd.cncf.helm.config.v1+json"
	mtFileConfigLocal = "application/vnd.content.hauler.file.local.config.v1+json"
	mtFileConfigDir   = "application/vnd.content.hauler.file.directory.config.v1+json"
	mtFileConfigHTTP  = "application/vnd.content.hauler.file.http.config.v1+json"
	mtSigstoreBundle  = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// Type is what a store entry holds.
type Type string

const (
	// TypeImage is a container image, the only kind vexscan can scan.
	TypeImage Type = "image"
	// TypeChart is a Helm chart: a packaged tarball, not a filesystem.
	TypeChart Type = "chart"
	// TypeFile is an arbitrary file hauler was asked to carry.
	TypeFile Type = "file"
	// TypeAttached is a signature, attestation, SBOM or OCI referrer hanging
	// off another entry. Not a scan target and not a gap in one either.
	TypeAttached Type = "attached"
	// TypeUnknown is an entry this package could not classify. It is a
	// distinct type rather than a silent omission, because a haul full of
	// artifacts a newer hauler understands and this does not must read as
	// "3 entries were not recognised", never as three fewer images.
	TypeUnknown Type = "unknown"
)

// Artifact is one entry in a haul's index.
type Artifact struct {
	// Ref is what the artifact is called: the fully qualified reference when
	// the haul recorded one, and the store's own registryless name when it
	// did not. This is what a scan of it is reported under.
	Ref string
	// StoreRef is the name the layout files it under -- the value of
	// org.opencontainers.image.ref.name -- which is what addresses it in the
	// oci: transport. Usually not equal to Ref; see the annotation block.
	StoreRef string
	// Qualified says whether Ref carries a registry. False means the haul
	// recorded no fully qualified name for this entry, so Ref is the stripped
	// store name and the caller has to decide whether that is good enough.
	Qualified bool
	Type      Type
	// Detail explains a TypeUnknown, so the caller's warning can name the
	// reason rather than just the count.
	Detail string
}

// Haul is an opened haul: an OCI layout on disk and what its index says is in
// it.
type Haul struct {
	// Dir is the layout root -- the directory holding index.json, oci-layout
	// and blobs. It is what the oci: transport addresses.
	Dir string
	// Artifacts is every indexed entry, in index order.
	Artifacts []Artifact
	// Extracted is true when Dir is a temporary unpack of an archive and
	// Close will remove it, false when the caller pointed at a store
	// directory that was already on disk.
	Extracted bool
	// Skipped counts archive entries that were not regular files or
	// directories. See unpack: they cannot hide an artifact, because the
	// index is what decides what is here, but they are worth a word.
	Skipped int
}

// Close removes the unpacked copy, if this haul is one.
func (h *Haul) Close() error {
	if h == nil || !h.Extracted || h.Dir == "" {
		return nil
	}
	return os.RemoveAll(h.Dir)
}

// Images returns the entries that can be scanned.
func (h *Haul) Images() []Artifact {
	var out []Artifact
	for _, a := range h.Artifacts {
		if a.Type == TypeImage {
			out = append(out, a)
		}
	}
	return out
}

// Count returns how many entries are of the given type.
func (h *Haul) Count(t Type) int {
	n := 0
	for _, a := range h.Artifacts {
		if a.Type == t {
			n++
		}
	}
	return n
}

// Open reads the haul at path: a .tar.zst archive, an uncompressed tar, or a
// store directory that is already unpacked.
//
// An archive is unpacked in full, because zstd is a stream and there is no
// seeking into one to fetch the four blobs a particular image needs. That
// costs a second copy of the haul on disk for the life of the scan, which is
// why pointing at an already-extracted store directory is supported and
// cheaper: nothing is copied and Close removes nothing.
func Open(ctx context.Context, path string, logf func(string, ...any)) (*Haul, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	h := &Haul{}
	if info.IsDir() {
		h.Dir = path
	} else {
		dir, err := os.MkdirTemp("", "vexscan-haul-")
		if err != nil {
			return nil, err
		}
		h.Dir, h.Extracted = dir, true
		logf("Unpacking haul %s...", path)
		skipped, err := unpack(ctx, path, dir)
		if err != nil {
			h.Close()
			return nil, fmt.Errorf("unpack haul: %w", err)
		}
		h.Skipped = skipped
	}

	root, err := layoutRoot(h.Dir)
	if err != nil {
		h.Close()
		return nil, err
	}
	h.Dir = root

	arts, err := readIndex(root)
	if err != nil {
		h.Close()
		return nil, err
	}
	h.Artifacts = arts
	return h, nil
}

// layoutRoot finds the directory holding the layout index.
//
// The root of a `hauler store save` archive is the layout itself: save maps
// every store entry to its base name, so index.json is at the top. Other
// things that reach this function are not so tidy -- a haul someone tarred by
// hand from its parent directory, or an extracted tree with the store
// directory still wrapped around it -- so one level down is searched too,
// which covers the conventional "store/" without guessing at the name.
func layoutRoot(dir string) (string, error) {
	if hasIndex(dir) {
		return dir, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() && hasIndex(filepath.Join(dir, e.Name())) {
			found = append(found, filepath.Join(dir, e.Name()))
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("%s is not an OCI layout: no index.json in it or one level below", dir)
	default:
		// Two layouts in one tree is not something to pick between: choosing
		// either would scan half a haul and report it as the whole one.
		names := make([]string, len(found))
		for i, f := range found {
			names[i] = filepath.Base(f)
		}
		return "", fmt.Errorf("%s holds more than one OCI layout (%s); point --haul at one of them",
			dir, strings.Join(names, ", "))
	}
}

func hasIndex(dir string) bool {
	for _, name := range []string{indexSidecar, indexFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

const (
	indexFile = "index.json"
	// indexSidecar is hauler's full-fidelity index, and it is read in
	// preference to index.json wherever it exists.
	//
	// `hauler store save --containerd` writes a deliberately incomplete
	// index.json -- non-image artifacts are filtered out of it so containerd
	// can import the tarball directly -- and preserves the real one here.
	// hauler's own `store load` prefers this file for that reason. A reader
	// that trusted index.json on a --containerd haul would silently see fewer
	// artifacts than are in it, on precisely the hauls most likely to be
	// sitting in an airgap.
	indexSidecar = "hauler-index.json"
)

// ociIndex is the part of an OCI image index this package reads.
type ociIndex struct {
	Manifests []struct {
		MediaType   string            `json:"mediaType"`
		Digest      string            `json:"digest"`
		Annotations map[string]string `json:"annotations"`
	} `json:"manifests"`
}

// ociManifest is the part of a manifest this package reads: enough to see what
// its config says it is.
type ociManifest struct {
	Config struct {
		MediaType string `json:"mediaType"`
	} `json:"config"`
	ArtifactType string `json:"artifactType"`
}

// readIndex turns the layout index into artifacts.
func readIndex(root string) ([]Artifact, error) {
	name := indexFile
	if _, err := os.Stat(filepath.Join(root, indexSidecar)); err == nil {
		name = indexSidecar
	}
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		return nil, err
	}
	var idx ociIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}

	var out []Artifact
	for _, m := range idx.Manifests {
		// An entry with no ref name is not addressable in the oci: transport
		// and is not what hauler calls an artifact either -- its own store
		// walk skips exactly these. They are the index's internal plumbing,
		// not a missing image.
		storeRef := m.Annotations[annRefName]
		if storeRef == "" {
			continue
		}
		a := Artifact{StoreRef: storeRef}
		a.Ref, a.Qualified = qualify(m.Annotations, storeRef)
		a.Type, a.Detail = classify(root, m.MediaType, m.Digest, m.Annotations)
		out = append(out, a)
	}
	return out, nil
}

// qualify recovers the fully qualified reference for a store entry.
//
// hauler.dev/original-ref is the one to trust: hauler documents it as the
// reference the artifact was first added under, preserved whether or not a
// --rewrite has since overwritten the other names. io.containerd.image.name
// is the fallback, being the qualified name hauler writes for containerd's
// benefit. Neither is guaranteed: hauler v1 wrote no original-ref, and there
// is a v2 window where the containerd name was lost on the OCI import path
// (hauler's own #744). When both are missing the store name is all there is,
// and the caller is told so rather than being handed a guess -- inventing
// docker.io for a registryless name is how an image from a private registry
// ends up filed under the wrong product.
func qualify(ann map[string]string, storeRef string) (string, bool) {
	for _, key := range []string{annOriginalRef, annContainerdName} {
		v := strings.TrimSpace(ann[key])
		// A chart's original-ref is "repoURL|repo:tag", which is hauler's own
		// encoding and not a reference; it is never an image's.
		if v == "" || strings.Contains(v, "|") {
			continue
		}
		return v, true
	}
	return storeRef, false
}

// classify decides what a store entry holds.
//
// The kind annotation is checked first because it is unambiguous and cheap,
// then the descriptor's own media type, and only then the manifest's config
// media type -- which means reading a blob, and is what a hauler v1 haul
// needs to tell a chart from an image.
func classify(root, mediaType, digest string, ann map[string]string) (Type, string) {
	switch kind := ann[annKind]; {
	case kind == kindImage, kind == kindImageIndex:
		return TypeImage, ""
	case kind == kindSigs, kind == kindAtts, kind == kindSboms:
		return TypeAttached, ""
	case strings.HasPrefix(kind, kindReferrers):
		return TypeAttached, ""
	}

	// A manifest list is an image whatever else is true of it; there is
	// nothing else hauler stores behind one.
	if mediaType == mtOCIIndex || mediaType == mtDockerList {
		return TypeImage, ""
	}
	// The docker manifest type is only ever an image. The OCI one is what
	// charts, files and images all use, so it settles nothing.
	if mediaType == mtDockerManifest {
		return TypeImage, ""
	}
	if mediaType != mtOCIManifest {
		return TypeUnknown, fmt.Sprintf("unrecognised manifest media type %s", mediaType)
	}

	m, err := readManifest(root, digest)
	if err != nil {
		// Unreadable, so unknown. Not skipped: a blob missing from a haul is
		// a broken haul, and the caller has to hear about it.
		return TypeUnknown, fmt.Sprintf("manifest %s could not be read: %v", short(digest), err)
	}
	switch m.Config.MediaType {
	case mtOCIConfig, mtDockerConfig:
		return TypeImage, ""
	case mtChartConfig:
		return TypeChart, ""
	case mtFileConfigLocal, mtFileConfigDir, mtFileConfigHTTP:
		return TypeFile, ""
	}
	if m.ArtifactType == mtSigstoreBundle {
		return TypeAttached, ""
	}
	return TypeUnknown, fmt.Sprintf("unrecognised config media type %s", m.Config.MediaType)
}

// readManifest reads one manifest blob out of the layout.
func readManifest(root, digest string) (*ociManifest, error) {
	p, err := blobPath(root, digest)
	if err != nil {
		return nil, err
	}
	// A manifest is small; the cap is only here so a corrupt or hostile
	// descriptor cannot point this at a multi-gigabyte layer blob.
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var m ociManifest
	dec := json.NewDecoder(&limitedReader{r: f, n: maxManifestBytes})
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// maxManifestBytes caps a manifest read. Real manifests are kilobytes; an
// image index listing a hundred platforms is still well inside this.
const maxManifestBytes = 4 << 20

// blobPath maps a "sha256:<hex>" digest to its file in the layout.
//
// The algorithm and the hex are both checked before they are joined into a
// path, because a descriptor is untrusted input and "../../etc/passwd" is a
// perfectly well-formed JSON string.
func blobPath(root, digest string) (string, error) {
	alg, hex, ok := strings.Cut(digest, ":")
	if !ok || alg == "" || hex == "" {
		return "", fmt.Errorf("malformed digest %q", digest)
	}
	if !isLowerHex(hex) || !isBlobSegment(alg) {
		return "", fmt.Errorf("malformed digest %q", digest)
	}
	return filepath.Join(root, "blobs", alg, hex), nil
}

func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func isBlobSegment(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '+' && r != '-' && r != '.' && r != '_' {
			return false
		}
	}
	return true
}

func short(digest string) string {
	if _, hex, ok := strings.Cut(digest, ":"); ok && len(hex) > 12 {
		return hex[:12]
	}
	return digest
}

// limitedReader is io.LimitedReader with an error instead of a silent EOF, so
// a manifest that is too large fails the read rather than arriving truncated
// and unparseable-for-the-wrong-reason.
type limitedReader struct {
	r interface{ Read([]byte) (int, error) }
	n int64
}

var errTooLarge = errors.New("blob exceeds the manifest size limit")

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}
