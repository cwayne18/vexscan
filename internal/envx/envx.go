// Package envx resolves vexscan's own environment variables, honoring the
// legacy GOMODVEX_ names the tool used before it was renamed from gomod-vex.
package envx

import (
	"os"
	"strings"
)

// Prefixes are the accepted variable prefixes, newest first.
var Prefixes = []string{"VEXSCAN_", "GOMODVEX_"}

// Get returns the value of the first set variable named by suffix across
// Prefixes, trimmed of surrounding whitespace. It returns "" when none is set,
// so callers keep their existing "unset means default" handling.
func Get(suffix string) string {
	for _, p := range Prefixes {
		if v := strings.TrimSpace(os.Getenv(p + suffix)); v != "" {
			return v
		}
	}
	return ""
}
