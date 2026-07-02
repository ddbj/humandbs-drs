// Package buildinfo exposes build-time version metadata. The values are set
// via -ldflags at build time and fall back to placeholders for local builds.
package buildinfo

import "fmt"

var (
	// Version is the released version, or "dev" for local builds.
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "none"
	// Date is the build timestamp.
	Date = "unknown"
)

// String returns a human-readable one-line build summary.
func String() string {
	return fmt.Sprintf("version %s (commit %s, built %s)", Version, Commit, Date)
}
