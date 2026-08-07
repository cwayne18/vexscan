package debian

import "strings"

// codenames maps a Debian VERSION_ID major to the tracker's release key. The
// tracker is indexed by codename, but os-release reports a number, so the two
// have to be bridged. Only stable releases the tracker still carries need an
// entry; anything else maps to nothing and the provider declines, which is the
// safe direction.
var codenames = map[string]string{
	"8":  "jessie",
	"9":  "stretch",
	"10": "buster",
	"11": "bullseye",
	"12": "bookworm",
	"13": "trixie",
	"14": "forky",
}

// codenameFor turns a Debian VERSION_ID into the tracker's release key.
//
// os-release gives "12" or occasionally a point version like "12.4"; the tracker
// keys on the codename of the major release, so only the major matters. A value
// that maps to no known stable release -- testing, unstable, something newer
// than this table -- returns empty, and the caller then declines to clear rather
// than match against a release it cannot name.
func codenameFor(versionID string) string {
	v := strings.TrimSpace(versionID)
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	return codenames[v]
}
