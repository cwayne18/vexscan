package main

import (
	"flag"
	"strings"
)

// versionFlag stands in the doorway of a flag whose meaning changed.
//
// In every scanner a user is likely to have typed it into, --version prints
// the tool's version. In vexscan it has always meant "override the module
// version read from a binary's build info", so `vexscan --version` answered
// "flag needs an argument: -version" and dumped usage -- the first thing a new
// user types and the first thing a bug report needs, and it did neither.
//
// The two meanings cannot share a token, so the override moved to
// --module-version. The value form is kept working rather than deleted because
// a pipeline that has been passing --version=1.2.3 for a year deserves a
// warning, not a silent scan of a different version.
type versionFlag struct {
	// print is set by a bare --version, which the flag package spells as the
	// value "true" because of IsBoolFlag below.
	print bool
	// override is the deprecated module version from --version=1.2.3.
	override string
}

// IsBoolFlag lets the flag package accept a bare --version without consuming
// the next argument. It is also what leaves the "1.2.3" of `--version 1.2.3`
// in flag.Args(), which checkPositional turns into a pointed error rather than
// the silent drop it would otherwise be.
func (v *versionFlag) IsBoolFlag() bool { return true }

func (v *versionFlag) String() string { return v.override }

// Set records which of the two spellings was used. A module version of
// literally "true" is indistinguishable from the bare form and is read as the
// bare form; no such version exists, and --module-version is unambiguous.
func (v *versionFlag) Set(s string) error {
	if s == "true" {
		v.print = true
		return nil
	}
	v.override = s
	return nil
}

// looksLikeVersion reports whether s is plausibly the module version that was
// meant to follow --version. It only has to be right about the mistake it
// exists to diagnose, so "1.2.3" and "v1.2.3" are enough.
func looksLikeVersion(s string) bool {
	s = strings.TrimPrefix(s, "v")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// checkPositional rejects leftover arguments.
//
// vexscan takes none, and until now ignored any it was given: `vexscan --image
// debian:12 --all extra` scanned without the last word and said nothing about
// it. Silently discarding part of a command line is the same failure mode as
// silently discarding part of a report.
func checkPositional(v *versionFlag) {
	rest := flag.Args()
	if len(rest) == 0 {
		return
	}
	// The likeliest way to get here by accident, now that --version is a bool
	// flag: the space form of the old override.
	if v.print && len(rest) == 1 && looksLikeVersion(rest[0]) {
		fail("--version now prints vexscan's own version; use --module-version=%s to override a module version", rest[0])
	}
	fail("unexpected argument %q; vexscan takes no positional arguments", rest[0])
}
