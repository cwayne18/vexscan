package main

import "strings"

// stringList is a repeatable flag that also accepts a comma-separated value,
// so `--package a --package b` and `--package a,b` mean the same thing.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

// argvFlag is a repeatable flag whose value is one argv token, in order:
// `--entrypoint /usr/bin/tini --entrypoint --` is the two-word command line.
//
// It is not a stringList, and the difference is the point. stringList splits on
// commas and drops the empties, which is right for a list of paths and wrong
// for a command line twice over: an argument may contain a comma
// (`--listen=1.2.3.4,5.6.7.8` is one token, not two) and "given, but empty" is
// a claim of its own -- `--cmd=` says this image is started with no arguments,
// which is not what saying nothing says. One token per occurrence has no
// separator to collide with and no empties to discard.
type argvFlag struct {
	// set records that the flag appeared at all, which is the distinction the
	// closure turns on: a nil override leaves the image's own half of the
	// command line in place, an empty non-nil one replaces it with nothing.
	set    bool
	tokens []string
}

func (a *argvFlag) String() string { return strings.Join(a.tokens, " ") }

func (a *argvFlag) Set(v string) error {
	a.set = true
	if v == "" {
		// Not an empty argument -- an empty command line. A literal empty token
		// is expressible in a Kubernetes manifest and not here, which is a
		// trade worth making: wanting one is vanishingly rare, and wanting to
		// say "with no arguments" is not.
		return nil
	}
	a.tokens = append(a.tokens, v)
	return nil
}

// value is the override as the graph wants it: nil when the flag was never
// given, and a non-nil slice -- empty or not -- when it was.
func (a *argvFlag) value() []string {
	if !a.set {
		return nil
	}
	if a.tokens == nil {
		return []string{}
	}
	return a.tokens
}

// flagSource names the command line as the origin of an entrypoint override,
// for the clause the report and the emitted VEX carry.
//
// It names the flags rather than saying "the command line" because that clause
// is the one a reviewer is meant to disagree with, and the useful form of
// disagreeing is knowing which argument to go and look at. Empty when neither
// was given, which is what keeps the clause off every run that made no such
// claim.
func flagSource(entrypoint, cmd bool) string {
	switch {
	case entrypoint && cmd:
		return "--entrypoint and --cmd"
	case entrypoint:
		return "--entrypoint"
	case cmd:
		return "--cmd"
	}
	return ""
}
