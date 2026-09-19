package elfgraph

import "testing"

// Which taints are exempt from the presence question is the one place in this
// package where getting the default backwards would widen a conclusion rather
// than narrow it, so the exemptions are written out here one at a time. A kind
// that stops appearing in this table has either been deleted or has quietly
// changed sides, and both should be a test failure rather than a silent
// loosening of every not_present in the tool.
func TestOnlyTheReachabilityTaintsAreExemptFromPresence(t *testing.T) {
	for kind, want := range map[TaintKind]bool{
		// Choosing which of the image's objects to load cannot add a symbol
		// to an object that does not define it.
		TaintDlopen: false,
		// A DT_NEEDED that matched no file names a library that is not in the
		// image, so it is not a place the image can be hiding a copy.
		TaintUnresolvedNeeded: false,

		// A static binary holds its libraries inside itself, where no symbol
		// table on disk describes them.
		TaintStaticELF: true,
		// An entrypoint that can start another program can start a static one,
		// and that program is not a root, so nothing else raises the hazard.
		TaintExec: true,
		// Both of these leave the real workload unidentified, and the program
		// nobody identified may be a static binary. Neither blocks today --
		// they escalate the root set instead -- so this side of the answer
		// costs nothing and is the one to be holding if that changes.
		TaintShellEntrypoint: true,
		TaintNoEntrypoint:    true,
	} {
		if got := kind.ThreatensPresence(); got != want {
			t.Errorf("%s.ThreatensPresence() = %v, want %v", kind, got, want)
		}
	}
}

// The exemption list is written as exemptions so that a kind nobody has thought
// about yet blocks both questions. A contributor adding one and forgetting this
// file should get the conservative answer for free.
func TestAnUnclassifiedTaintThreatensPresence(t *testing.T) {
	if !TaintKind("something-nobody-has-argued-about-yet").ThreatensPresence() {
		t.Error("an unrecognised taint kind was treated as harmless to the presence question")
	}
}
