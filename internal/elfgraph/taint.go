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
	// or one naming a file that is not in the image. There is nothing to root
	// the closure at, so the same escalation applies.
	TaintNoEntrypoint TaintKind = "no-entrypoint"
)

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
