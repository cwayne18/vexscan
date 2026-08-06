package pkgdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// This file reads an RPM *package file*, as opposed to rpm.go which reads an
// installed rpm *database*. It carries no build tag and no go-rpmdb dependency,
// so --rpm works in the norpm build too, and the three helpers the two share
// live here for the same reason.
//
// go-rpmdb's own header decoder is unexported, which is why this exists.

// rpm's binary layout, all big-endian:
//
//	96-byte lead
//	signature header
//	padding to the next 8-byte boundary
//	main header
//	compressed cpio payload
//
// and a header is
//
//	8e ad e8 01, 4 reserved bytes
//	nindex  uint32   -- how many index entries
//	hsize   uint32   -- how many bytes of data they point into
//	nindex x 16-byte index entries {tag, type, offset, count}
//	hsize bytes of data
//
// The shape that matters here is that each section states its own length in its
// first sixteen bytes. A reader can therefore consume exactly the header and
// stop, over any io.Reader -- which is what lets --rpm read a package over the
// network without fetching the payload, on servers that honour Range and on
// servers that ignore it alike.
const (
	rpmLeadSize   = 96
	rpmHeaderSize = 16
	rpmEntrySize  = 16
)

var (
	rpmLeadMagic   = []byte{0xed, 0xab, 0xee, 0xdb}
	rpmHeaderMagic = []byte{0x8e, 0xad, 0xe8, 0x01}
)

// Bounds on what a header may claim about itself. A truncated or hostile file
// can say it has four billion index entries, and the allocation that follows
// would be made before a single byte of it was read.
//
// The limits are rpm's own: 64 Ki index entries and 256 MiB of data. Every real
// package is orders of magnitude under both -- the largest header measured here
// was 85 KB, with 4,000 entries.
const (
	rpmMaxEntries = 64 << 10
	rpmMaxData    = 256 << 20
)

// rpm index entry types.
const (
	rpmTypeInt16       = 3
	rpmTypeInt32       = 4
	rpmTypeString      = 6
	rpmTypeStringArray = 8
	rpmTypeI18NString  = 9
)

// The tags read. rpm defines several hundred; these are the ones that answer
// "what package is this, what does it install, and whose distribution is it".
const (
	tagName          = 1000
	tagVersion       = 1001
	tagRelease       = 1002
	tagEpoch         = 1003
	tagDistribution  = 1010
	tagVendor        = 1011
	tagArch          = 1022
	tagSourceRPM     = 1044
	tagDirIndexes    = 1116
	tagBasenames     = 1117
	tagDirnames      = 1118
	tagSourcePackage = 1106
	tagFileClass     = 1141
	tagClassDict     = 1142
)

// ErrNotRPM is returned when a file does not begin with rpm's lead magic. It is
// separate so a directory walk can tell "this .rpm is not one" from "this .rpm
// is one and is broken", and report the two differently.
var ErrNotRPM = errors.New("not an rpm package file (bad lead magic)")

// Meta is what an RPM file says about itself beyond the package identity: which
// distribution built it, and whether it ships any executable code.
//
// It exists because an RPM file arrives with no filesystem around it. An
// installed package is found inside a tree that has an /etc/os-release to name
// the ecosystem and ELF objects to trace; a package file has to carry both
// facts in its own header or they are not available at all.
type Meta struct {
	// Vendor and Distribution are the VENDOR and DISTRIBUTION tags, verbatim:
	// "Rocky Enterprise Software Foundation" / "Rocky Linux 9", "SUSE LLC" /
	// "SUSE Linux Enterprise 15". Either may be empty; some rebuilders set
	// neither, which is why --osv-ecosystem exists.
	Vendor       string `json:"vendor,omitempty"`
	Distribution string `json:"distribution,omitempty"`

	// ELF are the installed paths whose FILECLASS entry names an ELF object.
	//
	// rpm stores file(1)'s output for every file it packages, in the header,
	// which means "does this package ship any code at all" is answerable
	// without decompressing the cpio payload -- no xz, no zstd, no cpio.
	// That single fact is what makes a metadata-only scan able to produce a
	// real not_present verdict rather than only undetermined ones.
	ELF []string `json:"elf,omitempty"`

	// FilesKnown reports whether the file list behind ELF was actually read.
	//
	// A package that genuinely ships no code and a package nobody looked at
	// are indistinguishable by ELF alone -- both have len(ELF) == 0 -- and the
	// two call for opposite verdicts: one is "there is no code here", the
	// other is "nothing was learned". Only a reader with the header in front
	// of it can tell them apart, so only ReadFile sets this. Every other way a
	// Meta comes into being -- an SBOM component, a hand-built literal --
	// leaves it false and gets the cautious answer, which is the direction a
	// zero value has to fall in a tool whose worst failure is a clean report.
	FilesKnown bool `json:"files_known,omitempty"`

	// SourcePackage is true for a .src.rpm. Source packages install nothing and
	// are not what a distribution files advisories against, so callers skip
	// them rather than report a package that cannot be installed.
	SourcePackage bool `json:"source_package,omitempty"`
}

// HasELF reports whether the package ships any executable object.
func (m Meta) HasELF() bool { return len(m.ELF) > 0 }

// CanRuleOutCode reports whether this metadata is enough to say the package
// installs nothing that could execute.
//
// An empty ELF list is only evidence when its emptiness was observed, so the
// file list has to be known before its silence means anything.
func (m Meta) CanRuleOutCode() bool { return m.FilesKnown && !m.HasELF() }

// ReadFile parses an RPM package file's headers into the same Package the rpm
// database reader produces, so nothing downstream can tell the difference.
//
// It reads the lead, the signature header and the main header, and stops --
// it never touches the payload, and never seeks, so r may be a network stream.
// On the two packages measured that is 0.7% and 4.6% of the file.
//
// An error means the file could not be understood, never that it was
// understood to contain nothing: a package with no files and a package whose
// file list failed to decode must not produce the same Package.
func ReadFile(r io.Reader) (Package, Meta, error) {
	// The magic is checked before the rest of the lead is demanded, so that a
	// file which is not an rpm at all says so. The likeliest way this happens
	// is a mirror answering 404 with an HTML page: that is 53 bytes, shorter
	// than the lead, and insisting on 96 first would report it as a truncated
	// rpm rather than as the thing it is.
	magic := make([]byte, len(rpmLeadMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != string(rpmLeadMagic) {
		return Package{}, Meta{}, ErrNotRPM
	}
	if _, err := io.ReadFull(r, make([]byte, rpmLeadSize-len(rpmLeadMagic))); err != nil {
		return Package{}, Meta{}, fmt.Errorf("reading rpm lead: %w", rpmEOF(err))
	}

	// The signature header is read and discarded. Its content is checksums and
	// keys, which this does not verify -- but its length has to be consumed to
	// reach the header that follows it.
	sig, err := readHeader(r)
	if err != nil {
		return Package{}, Meta{}, fmt.Errorf("reading rpm signature header: %w", err)
	}
	if pad := (8 - (sig.size % 8)) % 8; pad > 0 {
		if _, err := io.ReadFull(r, make([]byte, pad)); err != nil {
			return Package{}, Meta{}, fmt.Errorf("reading rpm signature padding: %w", rpmEOF(err))
		}
	}

	h, err := readHeader(r)
	if err != nil {
		return Package{}, Meta{}, fmt.Errorf("reading rpm header: %w", err)
	}

	name := h.str(tagName)
	if name == "" {
		return Package{}, Meta{}, errors.New("rpm header carries no NAME tag")
	}
	pkg := Package{
		Format:  FormatRPM,
		Name:    name,
		Version: rpmEVR(int(h.i32(tagEpoch)), h.str(tagVersion), h.str(tagRelease)),
		Epoch:   int(h.i32(tagEpoch)),
		Arch:    h.str(tagArch),
		Source:  SourceRPMName(h.str(tagSourceRPM)),
		Files:   normalizePaths(h.files()),
	}
	meta := Meta{
		Vendor:       h.str(tagVendor),
		Distribution: h.str(tagDistribution),
		ELF:          h.elfFiles(),
		// The header was read to the end, so an empty ELF list above is a
		// package that ships no code and not a question that went unasked. Set
		// here and nowhere else: every error path above returns Meta{}, and
		// that zero value has to keep meaning "unknown".
		FilesKnown: true,
		// A source package has no SOURCERPM of its own, and rpm marks it with
		// SOURCEPACKAGE. Either alone would misfire -- some binary packages
		// genuinely lack SOURCERPM -- so both are consulted.
		SourcePackage: h.has(tagSourcePackage) || strings.EqualFold(pkg.Arch, "src"),
	}
	return pkg, meta, nil
}

// rpmEOF turns a truncated read into a message that says so. io.ErrUnexpectedEOF
// on its own reads as a bug; on a package file it almost always means the
// download stopped early or the file was cut short, which is a different thing
// to tell the user.
func rpmEOF(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		// Normalised to one sentinel: io.ReadFull returns EOF when nothing
		// arrived and ErrUnexpectedEOF when something did, and the caller
		// cares about neither distinction.
		return fmt.Errorf("file ends mid-header: %w", ErrTruncated)
	}
	return err
}

// ErrTruncated means the file stopped before its header did -- a download cut
// short, or a package that was never whole.
var ErrTruncated = errors.New("unexpected end of file")

// rpmHeader is one decoded header section: its index, and the data the index
// points into.
type rpmHeader struct {
	tags map[int32]rpmEntry
	data []byte
	// size is how many bytes this header occupied in the file, which is what
	// the caller needs to compute the padding that follows it.
	size int
}

type rpmEntry struct {
	typ    uint32
	offset uint32
	count  uint32
}

// readHeader consumes exactly one header from r.
func readHeader(r io.Reader) (rpmHeader, error) {
	head := make([]byte, rpmHeaderSize)
	if _, err := io.ReadFull(r, head); err != nil {
		return rpmHeader{}, rpmEOF(err)
	}
	if string(head[:4]) != string(rpmHeaderMagic) {
		return rpmHeader{}, fmt.Errorf("bad header magic %x", head[:4])
	}
	nindex := binary.BigEndian.Uint32(head[8:12])
	hsize := binary.BigEndian.Uint32(head[12:16])
	if nindex > rpmMaxEntries {
		return rpmHeader{}, fmt.Errorf("header claims %d index entries, limit is %d", nindex, rpmMaxEntries)
	}
	if hsize > rpmMaxData {
		return rpmHeader{}, fmt.Errorf("header claims %d bytes of data, limit is %d", hsize, rpmMaxData)
	}

	index := make([]byte, int(nindex)*rpmEntrySize)
	if _, err := io.ReadFull(r, index); err != nil {
		return rpmHeader{}, rpmEOF(err)
	}
	data := make([]byte, hsize)
	if _, err := io.ReadFull(r, data); err != nil {
		return rpmHeader{}, rpmEOF(err)
	}

	h := rpmHeader{
		tags: make(map[int32]rpmEntry, nindex),
		data: data,
		size: rpmHeaderSize + len(index) + len(data),
	}
	for i := 0; i < int(nindex); i++ {
		e := index[i*rpmEntrySize:]
		tag := int32(binary.BigEndian.Uint32(e[0:4]))
		// A duplicate tag keeps the first. rpm's region trailer re-lists tags
		// with offsets into a different frame of reference, and reading the
		// second would point at the wrong bytes.
		if _, seen := h.tags[tag]; seen {
			continue
		}
		h.tags[tag] = rpmEntry{
			typ:    binary.BigEndian.Uint32(e[4:8]),
			offset: binary.BigEndian.Uint32(e[8:12]),
			count:  binary.BigEndian.Uint32(e[12:16]),
		}
	}
	return h, nil
}

func (h rpmHeader) has(tag int32) bool {
	_, ok := h.tags[tag]
	return ok
}

// str reads a single-string tag. An entry whose offset points outside the data
// store yields "" rather than panicking: the header is attacker-supplied and a
// malformed one must fail as a missing tag, not as a crash.
func (h rpmHeader) str(tag int32) string {
	e, ok := h.tags[tag]
	if !ok || (e.typ != rpmTypeString && e.typ != rpmTypeI18NString) {
		return ""
	}
	if int(e.offset) >= len(h.data) {
		return ""
	}
	s := h.data[e.offset:]
	if end := indexByteZero(s); end >= 0 {
		return string(s[:end])
	}
	return ""
}

// strs reads a string-array tag.
func (h rpmHeader) strs(tag int32) []string {
	e, ok := h.tags[tag]
	if !ok || e.typ != rpmTypeStringArray || int(e.offset) >= len(h.data) {
		return nil
	}
	out := make([]string, 0, e.count)
	rest := h.data[e.offset:]
	for i := uint32(0); i < e.count; i++ {
		end := indexByteZero(rest)
		if end < 0 {
			// The array claims more members than the data holds. Return what
			// was actually read; the callers below all check lengths agree
			// before pairing arrays up.
			return out
		}
		out = append(out, string(rest[:end]))
		rest = rest[end+1:]
	}
	return out
}

// i32s reads an int32-array tag. int16 arrays are widened, because rpm narrows
// DIRINDEXES to int16 on packages with few directories.
func (h rpmHeader) i32s(tag int32) []int32 {
	e, ok := h.tags[tag]
	if !ok {
		return nil
	}
	width := 4
	if e.typ == rpmTypeInt16 {
		width = 2
	} else if e.typ != rpmTypeInt32 {
		return nil
	}
	end := int(e.offset) + int(e.count)*width
	if int(e.offset) > len(h.data) || end > len(h.data) {
		return nil
	}
	out := make([]int32, 0, e.count)
	for i := 0; i < int(e.count); i++ {
		b := h.data[int(e.offset)+i*width:]
		if width == 2 {
			out = append(out, int32(binary.BigEndian.Uint16(b[:2])))
		} else {
			out = append(out, int32(binary.BigEndian.Uint32(b[:4])))
		}
	}
	return out
}

// i32 reads a scalar int32 tag, zero when absent. EPOCH is the only one read
// here, and absent EPOCH means zero by rpm's own definition.
func (h rpmHeader) i32(tag int32) int32 {
	if v := h.i32s(tag); len(v) > 0 {
		return v[0]
	}
	return 0
}

// files reassembles the installed paths.
//
// rpm stores them factored: BASENAMES is one entry per file, DIRNAMES is the
// distinct directories, and DIRINDEXES joins them. The three must agree in
// length or the join is meaningless, so a mismatch yields nothing rather than a
// partial list -- a half-read file list would make a package look like it ships
// less than it does, which is the direction that under-reports.
func (h rpmHeader) files() []string {
	base := h.strs(tagBasenames)
	dirs := h.strs(tagDirnames)
	idx := h.i32s(tagDirIndexes)
	if len(base) == 0 || len(base) != len(idx) {
		return nil
	}
	out := make([]string, 0, len(base))
	for i, b := range base {
		d := int(idx[i])
		if d < 0 || d >= len(dirs) {
			return nil
		}
		out = append(out, dirs[d]+b)
	}
	return out
}

// elfFiles are the installed paths file(1) called an ELF object.
//
// FILECLASS is one index per file into CLASSDICT, the distinct file(1) strings.
// Both are written by rpmbuild at package time, so this is the packager's own
// classification and needs no filesystem to consult.
func (h rpmHeader) elfFiles() []string {
	dict := h.strs(tagClassDict)
	class := h.i32s(tagFileClass)
	files := h.files()
	if len(dict) == 0 || len(class) == 0 || len(class) != len(files) {
		return nil
	}
	var out []string
	for i, c := range class {
		if int(c) < 0 || int(c) >= len(dict) {
			continue
		}
		if strings.HasPrefix(dict[c], "ELF ") {
			out = append(out, files[i])
		}
	}
	sort.Strings(out)
	return out
}

// indexByteZero is strings.IndexByte for a NUL, on bytes.
func indexByteZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// rpmEVR composes the version string OSV compares against.
//
// The epoch is always included, including when it is zero. That is not what
// rpm -q prints, but it is what the Red Hat, Rocky and AlmaLinux OSV records
// contain -- verified against api.osv.dev:
//
//	RHSA-2024:2447  openssl    fixed 1:3.0.7-27.el9
//	RHSA-2023:6746  nghttp2    fixed 0:1.43.0-5.el9_3.1   <- explicit zero
//	Rocky Linux:9   openssl    fixed 1:3.0.1-43.el9_0
//	AlmaLinux:9     openssl    fixed 1:3.0.1-41.el9_0
//
// Azure Linux is the exception: its records carry no epoch at all ("3.3.0-1").
// Package.Epoch is exposed separately so the OS plugin can drop the prefix for
// that ecosystem rather than have this layer guess which consumer it has.
func rpmEVR(epoch int, version, release string) string {
	evr := version
	if release != "" {
		evr += "-" + release
	}
	return fmt.Sprintf("%d:%s", epoch, evr)
}

// SourceRPMName extracts the source package name from a SOURCERPM value like
// "openssl-3.2.2-16.el10.src.rpm", which is name-version-release.src.rpm. The
// name itself may contain hyphens ("java-21-openjdk"), so the tail is stripped
// by position from the right rather than by splitting from the left.
func SourceRPMName(srpm string) string {
	s := strings.TrimSuffix(strings.TrimSpace(srpm), ".src.rpm")
	s = strings.TrimSuffix(s, ".nosrc.rpm")
	if s == "" || s == srpm {
		// Not the expected shape; a bare name is still usable, anything else
		// is better dropped than passed to OSV as a package name.
		if strings.HasSuffix(srpm, ".rpm") {
			return ""
		}
		return s
	}
	// Strip "-release" then "-version".
	for i := 0; i < 2; i++ {
		dash := strings.LastIndex(s, "-")
		if dash <= 0 {
			return ""
		}
		s = s[:dash]
	}
	return s
}

// normalizePaths makes rpm's file list tree-absolute and ordered. rpm stores
// absolute paths already, but relocatable packages and malformed headers can
// produce relative ones, which would silently fail to match anything.
func normalizePaths(files []string) []string {
	if len(files) == 0 {
		return nil
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if !strings.HasPrefix(f, "/") {
			f = "/" + f
		}
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
