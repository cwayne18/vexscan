package elfgraph

import "fmt"

// TaintKind names a reason the closure cannot be trusted to be complete.
//
// A taint never sets a status. It blocks the analysis from concluding that
// something is unaffected, and says in the output why the conclusion was not
// available. That direction is the whole point: the failure mode worth
// engineering against is a tool that reports "not reachable" about an image
// whose reachability it could not actually compute.
type TaintKind string

const (
	// TaintUnresolvedNeeded is a DT_NEEDED entry that matched no file. The
	// library it names might be the one that holds the vulnerable code, so
	// conclusions about that soname are blocked -- but only that soname.
	TaintUnresolvedNeeded TaintKind = "unresolved-needed"

	// TaintDlopen is a reachable object that imports dlopen or dlmopen. Its
	// real dependency set is chosen at runtime from strings this package
	// cannot read, so the closure is a lower bound on what gets loaded.
	TaintDlopen TaintKind = "dlopen"

	// TaintStaticELF is a reachable executable with no program interpreter.
	// It carries its libraries inside itself, where DT_NEEDED cannot see
	// them, so an unreferenced .so on disk proves nothing about whether the
	// same code is running.
	TaintStaticELF TaintKind = "static-elf"

	// TaintShellEntrypoint is an entrypoint that is a shell or a supervisor
	// rather than the program itself. What it goes on to execute is not
	// knowable from the image, so every executable in the PATH directories is
	// treated as a root.
	TaintShellEntrypoint TaintKind = "shell-entrypoint"

	// TaintNoEntrypoint is an image config with neither Entrypoint nor Cmd,
	// or one naming a file that is not in the image -- or, in rootfs mode, the
	// absence of any config at all. There is nothing to root the closure at,
	// so the same escalation applies.
	TaintNoEntrypoint TaintKind = "no-entrypoint"

	// TaintExec is an entrypoint that can start another program. The closure
	// models one process image, not a process tree, so what the entrypoint execs
	// -- and every library that program would load -- is outside it.
	//
	// Unlike the other kinds this one is also recorded when it does not apply,
	// discharged, because the interesting fact about an entrypoint that cannot
	// exec is that somebody checked. See ExecProber.
	TaintExec TaintKind = "exec"

	// TaintMissingRoot is a --roots path the closure could not start from: one
	// naming nothing in the image, or naming a file that is not an ELF object.
	//
	// This is the only taint raised by what the user said rather than by what
	// the image contains, and it is the one that most needs raising. --roots is
	// how a user answers an exec taint -- "it runs this, now conclude" -- so a
	// root that silently goes missing takes the closure down with it while
	// --exec-policy=assume-none discharges the taint that was withholding the
	// answer. Dropping it with a log line makes a typo and a correct run produce
	// byte-identical reports, one of which is wrong.
	//
	// It threatens presence as well as reachability, by the default in
	// ThreatensPresence: the program nobody could find may be exactly the static
	// binary carrying a copy of the vulnerable code.
	TaintMissingRoot TaintKind = "missing-root"

	// TaintInertAssertion is a --dlopen-assume-none name that matched no dlopen
	// caller in this image, so the assertion discharged nothing.
	//
	// Unlike TaintMissingRoot this never blocks, and the asymmetry is the whole
	// point of recording it. A --roots path that goes missing shrinks the
	// closure, so it makes conclusions wider than the evidence supports and has
	// to stop the scan. An assume-none name that matches nothing removes no
	// taint, so the run is strictly more conservative than the user asked for
	// and no conclusion in it can be wrong.
	//
	// It is reported because it is still a mistake -- a typo, or a profile
	// pointed at the wrong image -- and one that is invisible in its
	// consequences. The user sees rows still blocked by a dlopen they thought
	// they had answered, with nothing in the report connecting the two. Saying
	// so costs nothing and is the difference between "this image loads more
	// than you think" and "you spelled bash wrong".
	TaintInertAssertion TaintKind = "inert-assertion"
)

// ThreatensPresence says whether this kind of taint can put a copy of the
// vulnerable code somewhere a package's own symbol tables do not describe.
//
// Two different questions get asked of an image, and the taints do not bear on
// them equally. "Would the dynamic linker load this library" is about
// reachability, and every taint here undermines it: each one is a way the
// closure is a lower bound on what runs. "Does any object this package ships
// define the vulnerable function" is about presence, and most taints say
// nothing about it -- dlopen chooses which of the image's objects to load, and
// choosing to load an object cannot add a symbol the object does not define.
// Read a package's tables, find the function in none of them, and dlopen has no
// way to make that answer wrong.
//
// A static binary is the case that does. It carries its libraries inside
// itself, so the vulnerable code can be running with no file on disk that
// exports it, and there the package's tables genuinely do not describe
// everything in the image.
//
// The shell-entrypoint and no-entrypoint kinds are filed with the static case
// rather than against it, on the grounds that the program nobody has identified
// may be exactly such a binary. Neither blocks today -- they escalate the root
// set instead of withholding an answer, so they never reach this test -- and
// the classification is here to be right if that ever changes.
//
// The list is written as the exemptions rather than the members so that a kind
// added later blocks both questions until someone makes the argument that it
// only blocks one. Getting that default backwards would quietly widen every
// not_present conclusion in the tool.
func (k TaintKind) ThreatensPresence() bool {
	switch k {
	case TaintDlopen, TaintUnresolvedNeeded:
		return false
	}
	return true
}

// Taint is one recorded reason a not_affected conclusion is unavailable.
type Taint struct {
	Kind TaintKind `json:"kind"`

	// Detail is the human-readable statement of what was observed.
	Detail string `json:"detail"`

	// Path is the object that caused it, when there is one.
	Path string `json:"path,omitempty"`

	// Soname scopes an unresolved-needed taint to the library that went
	// missing. Conclusions about every other library are unaffected by it.
	Soname string `json:"soname,omitempty"`

	// Blocking says whether this taint stops a not_affected conclusion.
	// Blocking is a field rather than a property of Kind because
	// --dlopen-policy=assume-none demotes a dlopen taint to a note: the user
	// asserted the risk away, and the record should still show it was there.
	Blocking bool `json:"blocking"`

	// Discharged says this taint would have blocked and something answered it:
	// --dlopen-policy=assume-none, or a StaticProber that could account for a
	// static entrypoint's contents.
	//
	// It is separate from !Blocking because the two say different things. A
	// static utility that is not the entrypoint never blocked in the first
	// place -- every glibc distribution ships a static ldconfig -- and it is
	// recorded for completeness. A discharged taint is load-bearing: it is the
	// reason a conclusion was available at all, so a report that omits it lets
	// a cleared verdict read as one nothing ever threatened.
	Discharged bool `json:"discharged,omitempty"`

	// Global says the taint applies to every package rather than to the
	// scope named by Path or Soname.
	Global bool `json:"global,omitempty"`
}

func (t Taint) String() string {
	if t.Detail != "" {
		return fmt.Sprintf("%s: %s", t.Kind, t.Detail)
	}
	return string(t.Kind)
}

// DlopenPolicy decides what a reachable dlopen call does to the closure.
type DlopenPolicy string

const (
	// DlopenTaint is the default: record it and block not_affected.
	DlopenTaint DlopenPolicy = "taint"

	// DlopenAssumeNone takes the user's word that nothing meaningful is
	// dlopen'd, recording the observation without letting it block.
	DlopenAssumeNone DlopenPolicy = "assume-none"
)

// ParseDlopenPolicy validates a --dlopen-policy value.
func ParseDlopenPolicy(s string) (DlopenPolicy, error) {
	switch DlopenPolicy(s) {
	case "", DlopenTaint:
		return DlopenTaint, nil
	case DlopenAssumeNone:
		return DlopenAssumeNone, nil
	}
	return "", fmt.Errorf("unknown dlopen policy %q: want %q or %q", s, DlopenTaint, DlopenAssumeNone)
}

// matchDlopenAssertion returns the --dlopen-assume-none name that answers this
// caller, or "" when the user named none of them.
//
// A name matches the caller's tree-absolute path or its SONAME and nothing
// else. Matching a bare basename was considered and rejected: a multiarch image
// carries /usr/lib/libcrypto.so.3 and /usr/lib32/libcrypto.so.3, and an
// assertion about the one the user looked at would silently discharge the other
// too. The point of this flag over --dlopen-policy=assume-none is that it says
// exactly which caller was waved off, and a loose match gives that back.
func matchDlopenAssertion(names []string, path, soname string) string {
	for _, n := range names {
		if n == path || (soname != "" && n == soname) {
			return n
		}
	}
	return ""
}

// ExecPolicy decides what an entrypoint that can start another program does to
// the closure.
type ExecPolicy string

const (
	// ExecTaint is the default: record it and block not_affected.
	ExecTaint ExecPolicy = "taint"

	// ExecAssumeNone takes the user's word that the programs the entrypoint runs
	// are accounted for -- named with --roots, or known not to matter --
	// recording the observation without letting it block.
	ExecAssumeNone ExecPolicy = "assume-none"
)

// ParseExecPolicy validates an --exec-policy value.
func ParseExecPolicy(s string) (ExecPolicy, error) {
	switch ExecPolicy(s) {
	case "", ExecTaint:
		return ExecTaint, nil
	case ExecAssumeNone:
		return ExecAssumeNone, nil
	}
	return "", fmt.Errorf("unknown exec policy %q: want %q or %q", s, ExecTaint, ExecAssumeNone)
}
