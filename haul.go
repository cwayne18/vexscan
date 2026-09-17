package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/haul"
)

// --haul: scanning a hauler haul.
//
// A haul is how software crosses an airgap, and the thing that makes it worth
// a flag of its own rather than a line in the --images-from documentation is
// that it can be scanned without a registry. Inside, a haul is an OCI image
// layout; skopeo reads that transport; so every image in one can be extracted
// and analysed on a machine with no route to the internet, which is the
// machine the images are going to run on.
//
// The other half of the flag is what it refuses to do quietly. A haul carries
// charts and files next to its images, and vexscan scans none of those. It
// would be easy to filter the index down to images, scan those, and print a
// clean report -- and that report would be indistinguishable from one over a
// haul that had no charts in it at all. So everything not scanned is counted
// and named on stderr before the scan starts, in the same spelling the rest of
// the tool uses for a hole in its coverage.

// openHaul opens the haul at path and turns it into a list of things to scan,
// saying on the way what in it is not one.
//
// The caller owns closing the returned haul: it may be a temporary unpack of a
// multi-gigabyte archive, and the blobs have to stay on disk for as long as
// images are still being extracted out of them.
func openHaul(ctx context.Context, path string, logf func(string, ...any)) (*haul.Haul, []scanTarget) {
	h, err := haul.Open(ctx, path, logf)
	if err != nil {
		fail("read --haul: %v", err)
	}

	images := h.Images()
	if len(images) == 0 {
		h.Close()
		fail("--haul %s holds no images (%s)", path, haulContents(h))
	}

	logf("Haul %s: %d image(s) of %d artifact(s)", path, len(images), len(h.Artifacts))
	reportHaulSkips(h)

	targets := make([]scanTarget, 0, len(images))
	for _, a := range images {
		targets = append(targets, scanTarget{ref: a.Ref, storeRef: a.StoreRef})
	}
	return h, targets
}

// haulContents describes what is in a haul, for the error a haul with no
// images in it produces. "no images" on its own invites the reader to think
// the file is broken; "no images: 12 charts, 30 files" tells them it is a
// hauler bundle that was built to carry something else.
func haulContents(h *haul.Haul) string {
	var parts []string
	for _, t := range []struct {
		typ   haul.Type
		label string
	}{
		{haul.TypeChart, "chart"},
		{haul.TypeFile, "file"},
		{haul.TypeAttached, "signature/attestation/SBOM"},
		{haul.TypeUnknown, "unrecognised artifact"},
	} {
		if n := h.Count(t.typ); n > 0 {
			parts = append(parts, tally(n, t.label))
		}
	}
	if len(parts) == 0 {
		return "it holds nothing this reader recognised"
	}
	return "it holds " + strings.Join(parts, ", ")
}

// reportHaulSkips says what was in the haul that will not be scanned.
//
// On stderr and not gated on --quiet, for the reason every other caveat in
// this tool is not: a report over eight of a haul's images that does not
// mention the three charts beside them is a report that looks complete and is
// not. The warnings are per category, because the answer differs -- a chart
// may or may not have already contributed its images, an unrecognised entry is
// a gap in this reader, and a registryless name is a correctness footgun
// downstream -- and a single "3 artifacts skipped" line would collapse three
// different problems into one shrug.
func reportHaulSkips(h *haul.Haul) {
	if n := h.Count(haul.TypeChart); n > 0 {
		// The nuance that matters: hauler resolves a chart's images into the
		// store itself when the manifest said add-images, in which case they
		// are already in the list above and nothing is missing. When it did
		// not, those images are not in the haul at all, and no scan of this
		// file can cover them.
		fmt.Fprintf(os.Stderr,
			"warning: %s in this haul %s not scanned; vexscan has no chart target.\n"+
				"         If they were added with add-images, their images are in the haul and are covered above.\n"+
				"         If they were not, their images are not in this haul and nothing here covers them.\n",
			tally(n, "chart"), isAre(n))
		nameSome(h, haul.TypeChart)
	}
	if n := h.Count(haul.TypeFile); n > 0 {
		fmt.Fprintf(os.Stderr, "warning: %s in this haul %s not scanned; vexscan has no file target.\n",
			tally(n, "file"), isAre(n))
	}
	if n := h.Count(haul.TypeUnknown); n > 0 {
		// Loudest of the three. The others are things this tool knowingly does
		// not scan; this is a thing it did not recognise, which on a haul
		// written by a newer hauler could be an image in a shape this reader
		// has never seen.
		fmt.Fprintf(os.Stderr,
			"warning: %s in this haul could not be classified and %s not scanned.\n"+
				"         If any of them is an image, this scan is missing it:\n",
			tally(n, "artifact"), isAre(n))
		for _, a := range h.Artifacts {
			if a.Type == haul.TypeUnknown {
				fmt.Fprintf(os.Stderr, "         %s: %s\n", a.Ref, a.Detail)
			}
		}
	}
	if unq := unqualified(h); len(unq) > 0 {
		// Not cosmetic. The reference is what names the product in a VEX
		// document and what a hub index is keyed on, so scanning under a name
		// with the registry missing files the findings somewhere a registry
		// scan of the same image would never look.
		fmt.Fprintf(os.Stderr,
			"warning: %s in this haul %s no fully qualified reference recorded, so %s scanned under the\n"+
				"         registryless name hauler stored. Findings for %s will not line up with a --image scan,\n"+
				"         and --vex-out would file %s under a different product purl:\n",
			tally(len(unq), "image"), haveHas(len(unq)), theyIt(len(unq)), themIt(len(unq)), themIt(len(unq)))
		for _, ref := range unq {
			fmt.Fprintf(os.Stderr, "         %s\n", ref)
		}
	}
	if h.Skipped > 0 {
		fmt.Fprintf(os.Stderr,
			"warning: %s in the haul archive %s not a regular file or directory and %s not unpacked.\n",
			tally(h.Skipped, "entry"), waswere(h.Skipped), waswere(h.Skipped))
	}
}

// unqualified lists the scannable images whose reference has no registry.
func unqualified(h *haul.Haul) []string {
	var out []string
	for _, a := range h.Images() {
		if !a.Qualified {
			out = append(out, a.Ref)
		}
	}
	sort.Strings(out)
	return out
}

// nameSome prints up to a handful of a type's references, so the warning is
// actionable without a hundred-chart haul burying the report under its own
// caveat. The count in the line above is always exact; this is the sample.
func nameSome(h *haul.Haul, t haul.Type) {
	const max = 5
	var refs []string
	for _, a := range h.Artifacts {
		if a.Type == t {
			refs = append(refs, a.Ref)
		}
	}
	sort.Strings(refs)
	for i, r := range refs {
		if i == max {
			fmt.Fprintf(os.Stderr, "         ... and %d more\n", len(refs)-max)
			break
		}
		fmt.Fprintf(os.Stderr, "         %s\n", r)
	}
}

// tally renders a count with its unit: "1 chart", "3 charts". Separate from
// plural in fixplan.go, which picks between two words a caller supplies; this
// one owns the number too, because every use here is "N things".
func tally(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	if unit == "entry" {
		return fmt.Sprintf("%d entries", n)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func waswere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

func haveHas(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

func theyIt(n int) string {
	if n == 1 {
		return "it is"
	}
	return "they are"
}

func themIt(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
