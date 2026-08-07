package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/cvss"
)

// Colour.
//
// Restricted to the eight basic ANSI colours and bold, because these reports
// are read on terminals whose themes this tool knows nothing about: a 256-colour
// grey that is legible on one background is invisible on another. The eight are
// the ones every theme remaps to something readable.
//
// Nothing that colour conveys is conveyed by colour alone. Every severity and
// every verdict is already spelled out in the cell -- the escapes make the
// worst rows findable in a 300-row table and change no bytes of meaning. That
// is also what makes `--color never` correct rather than lossy, and why the
// alignment guard below matters more than the palette does.

// ANSI select-graphic-rendition sequences. Written out rather than generated so
// grepping the source for an escape finds them all in one place.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
)

// palette decides how a report is coloured.
//
// The zero value writes no escapes at all, which is why "never" is not a code
// path: every wrap method returns its argument unchanged, so the uncoloured
// report is produced by the same code as the coloured one rather than by a
// branch beside it. That is what keeps the two from drifting -- and what lets
// the sixteen existing renderText callers keep asserting on plain text.
type palette struct{ on bool }

// wrap puts s between a sequence and a reset, or returns it untouched.
//
// An empty s is never wrapped: a zero-width cell of pure escapes is invisible
// to a reader and not to writeTable, and there is nothing to colour anyway.
func (p palette) wrap(seq, s string) string {
	if !p.on || s == "" || seq == "" {
		return s
	}
	return seq + s + ansiReset
}

func (p palette) bold(s string) string { return p.wrap(ansiBold, s) }

// severity colours a severity label. The ordering is cvss's, so an unrated
// finding is dimmed rather than given a colour that would imply a rating -- the
// same refusal to guess that puts UNKNOWN between HIGH and MEDIUM in the sort.
func (p palette) severity(label string) string {
	switch cvss.Display(label) {
	case cvss.Critical:
		return p.wrap(ansiBold+ansiRed, label)
	case cvss.High:
		return p.wrap(ansiRed, label)
	case cvss.Medium:
		return p.wrap(ansiYellow, label)
	case cvss.Low:
		return p.wrap(ansiBlue, label)
	default:
		return p.wrap(ansiDim, label)
	}
}

// status colours a verdict. Red for the two that mean the code is there and
// loadable, green for the two that rule it out, yellow for the one that says
// the tool could not tell -- which is a caution and not a clearance, and is
// coloured to keep it from reading as one.
func (p palette) status(s analyze.Status, text string) string {
	switch s {
	case analyze.StatusLinked, analyze.StatusReachable:
		return p.wrap(ansiRed, text)
	case analyze.StatusNotPresent, analyze.StatusNotInPath:
		return p.wrap(ansiGreen, text)
	default:
		return p.wrap(ansiYellow, text)
	}
}

// heading colours a section heading, so the eye can find where one table ends
// in a report that scrolls for pages.
func (p palette) heading(s string) string { return p.bold(s) }

// bannerPrefixes are the line openings writeCaveats produces, and the ones
// banners bolds.
var bannerPrefixes = []string{"INCOMPLETE:", "NOTE:"}

// banners bolds the caveat prefixes in an already-rendered block.
//
// A post-pass rather than a palette argument threaded into writeCaveats,
// writeMetadataCaveat and writeTriageCaveats and applied at each of their ten
// Fprintf calls. The prefixes are the contract -- writeFooter repeats this
// block verbatim precisely because those words are what a reader scans for --
// so matching on them is matching on the thing that is guaranteed, and a caveat
// added later is bolded without anyone remembering to.
//
// Only a prefix at the very start of a line is touched, so a continuation line
// that happens to contain the word is left alone.
func (p palette) banners(block string) string {
	if !p.on || block == "" {
		return block
	}
	lines := strings.Split(block, "\n")
	for i, l := range lines {
		for _, prefix := range bannerPrefixes {
			if strings.HasPrefix(l, prefix) {
				lines[i] = p.bold(prefix) + l[len(prefix):]
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// visibleWidth is the printed width of s in columns, skipping ANSI escapes.
//
// writeTable's alignment is rune arithmetic over every cell, and an escape
// sequence is runes that occupy no columns. Without this one coloured severity
// cell shifts every column to its right on that row and nowhere else, which is
// the specific way a table breaks that nobody notices until it is pasted into a
// bug report.
//
// Only CSI sequences (ESC '[' parameters final) are recognised, which is all
// this palette emits. A lone ESC not followed by '[' is counted as the rune it
// is rather than swallowing the rest of the cell -- misjudging one column beats
// losing a line.
func visibleWidth(s string) int {
	const (
		text = iota
		afterESC
		inCSI
	)
	n, state := 0, text
	for _, r := range s {
		if state == inCSI {
			// Parameter and intermediate bytes are 0x20-0x3F; the sequence ends
			// at the first final byte, 0x40-0x7E.
			if r >= '@' && r <= '~' {
				state = text
			}
			continue
		}
		if state == afterESC {
			if r == '[' {
				state = inCSI
				continue
			}
			n++ // the ESC led nowhere, so it was text after all
			state = text
		}
		if r == '\x1b' {
			state = afterESC
			continue
		}
		n++
	}
	if state == afterESC {
		n++ // a trailing ESC with nothing after it
	}
	return n
}

// colorPolicy is the resolved answer to whether this run writes escapes.
type colorPolicy struct {
	mode string // "auto", "always" or "never", as given
}

// parseColor validates --color. Strict, like every other enumerated flag here:
// a misspelled "allways" that silently meant "auto" would be a setting the user
// believes they changed.
func parseColor(mode string) (colorPolicy, error) {
	switch mode {
	case "auto", "always", "never":
		return colorPolicy{mode: mode}, nil
	default:
		return colorPolicy{}, fmt.Errorf("--color %q is not one of auto, always, never", mode)
	}
}

// destination is where a rendered report is going, which auto has to know.
type destination struct {
	file bool // --out was given
	gist bool // --gist was given
	json bool // --format json or sarif (both are JSON documents color would corrupt)
}

// palette resolves the policy against where the output is going.
//
// auto requires all four: a terminal is watching, NO_COLOR is unset, no file is
// being written and no gist is being uploaded. The last two are not politeness.
// emit writes the same rendered string to the file, and uploadGist sends that
// same string afterwards, so an escape sequence that reaches either is stored
// permanently in a document that will be read by something that does not
// interpret it.
//
// always overrides all four, because piping to `less -R` is a real thing to
// want and is indistinguishable from piping to grep from in here. It does not
// override --format json: escapes in JSON would make it unparseable, which is
// past the line between "looks wrong" and "is wrong".
func (c colorPolicy) palette(d destination) palette {
	if d.json || c.mode == "never" {
		return palette{}
	}
	if c.mode == "always" {
		return palette{on: true}
	}
	// https://no-color.org: set and non-empty means off, whatever the value.
	if os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	if d.file || d.gist {
		return palette{}
	}
	return palette{on: stdoutIsTerminal()}
}
