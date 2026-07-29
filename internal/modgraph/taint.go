package modgraph

import "fmt"

// TaintKind names a reason the import graph cannot be trusted to be complete.
//
// A taint never sets a status. It blocks the analysis from concluding that
// something is unaffected, and says in the output why the conclusion was not
// available. That direction is the whole point: the failure mode worth
// engineering against is a tool that reports "never imported" about an image
// whose imports it could not actually compute.
//
// The kinds mirror internal/elfgraph's, because the failure modes are the
// same ones: something referenced that is not there, something loaded by a
// name computed at runtime, and an entrypoint that does not say what it runs.
type TaintKind string

const (
	// TaintUnresolvedImport is a specifier that resolved to no file. The
	// module it names might be the one holding the vulnerable code, so
	// conclusions about that specifier are blocked -- but only that specifier.
	TaintUnresolvedImport TaintKind = "unresolved-import"

	// TaintDynamicImport is a reachable file that imports a name computed at
	// runtime: importlib.import_module(x), __import__(x), require(x). What it
	// loads is chosen from strings this package cannot read, so the graph is a
	// lower bound on what runs.
	//
	// A *literal* argument is not this. importlib.import_module("foo.bar")
	// resolves exactly like a static import and is followed as an ordinary
	// edge; only a computed one taints, and only the file that computes it.
	// Without that distinction nearly every Python image taints, which is the
	// same honest-but-useless failure the shell-entrypoint rule guards against.
	TaintDynamicImport TaintKind = "dynamic-import"

	// TaintPluginDiscovery is reachable code that enumerates installed
	// distributions rather than naming one: entry_points(),
	// pkgutil.iter_modules. Where the set of discoverable plugins can be read
	// off disk the language roots them instead, and this taint is only emitted
	// for the part that could not be enumerated.
	TaintPluginDiscovery TaintKind = "plugin-discovery"

	// TaintForeignEntrypoint is an argv[0] that is not this language's
	// interpreter, so the graph has nothing to root at. Every installed module
	// is treated as a root.
	TaintForeignEntrypoint TaintKind = "foreign-entrypoint"

	// TaintNoEntrypoint is an image config with neither Entrypoint nor Cmd.
	// Same escalation, different cause.
	TaintNoEntrypoint TaintKind = "no-entrypoint"

	// TaintBundled is an entrypoint whose dependencies were compiled into it
	// by a bundler, so the files that would carry the vulnerable code are not
	// on disk under the names an inventory knows.
	TaintBundled TaintKind = "bundled-entrypoint"

	// TaintUnreadable is a file that is reachable and could not be read. Its
	// imports are unknown, so everything downstream of it is missing from the
	// graph.
	TaintUnreadable TaintKind = "unreadable-module"
)

// Taint is one recorded reason a not_affected conclusion is unavailable.
type Taint struct {
	Kind TaintKind `json:"kind"`

	// Detail is the human-readable statement of what was observed.
	Detail string `json:"detail"`

	// Path is the file that caused it, when there is one.
	Path string `json:"path,omitempty"`

	// Spec scopes a taint to the specifier that went unresolved. Conclusions
	// about every other module are unaffected by it.
	Spec string `json:"spec,omitempty"`

	// Scope narrows a taint to the distributions it can affect, by import
	// name. A dynamic import inside one distribution says nothing about the
	// rest of the image, and scoping it is what keeps the whole scan from
	// being tainted by one plugin loader.
	Scope []string `json:"scope,omitempty"`

	// Blocking says whether this taint stops a not_affected conclusion.
	// Blocking is a field rather than a property of Kind because
	// --dynamic-import-policy=assume-none demotes a dynamic import to a note:
	// the user asserted the risk away, and the record should still show it.
	Blocking bool `json:"blocking"`

	// Global says the taint applies to every distribution rather than to the
	// scope named by Spec or Scope.
	Global bool `json:"global,omitempty"`
}

func (t Taint) String() string {
	if t.Detail != "" {
		return fmt.Sprintf("%s: %s", t.Kind, t.Detail)
	}
	return string(t.Kind)
}

// DynamicPolicy decides what a reachable computed import does to the graph.
type DynamicPolicy string

const (
	// DynamicTaint is the default: record it and block not_affected.
	DynamicTaint DynamicPolicy = "taint"

	// DynamicAssumeNone takes the user's word that nothing meaningful is
	// imported by a computed name, recording the observation without letting
	// it block.
	DynamicAssumeNone DynamicPolicy = "assume-none"
)

// ParseDynamicPolicy validates a --dynamic-import-policy value.
func ParseDynamicPolicy(s string) (DynamicPolicy, error) {
	switch DynamicPolicy(s) {
	case "", DynamicTaint:
		return DynamicTaint, nil
	case DynamicAssumeNone:
		return DynamicAssumeNone, nil
	}
	return "", fmt.Errorf("unknown dynamic import policy %q: want %q or %q", s, DynamicTaint, DynamicAssumeNone)
}
