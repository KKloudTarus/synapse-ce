// Package buildinfo reports dependency + application versions from the compiled
// binary's build metadata, used to record scan reproducibility.
package buildinfo

import "runtime/debug"

// Module returns the version of the dependency at the given module path (honoring
// a replace directive), or "unknown" if it is not in the build graph.
func Module(path string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, d := range bi.Deps {
		if d.Path != path {
			continue
		}
		if d.Replace != nil && d.Replace.Version != "" {
			return d.Replace.Version
		}
		if d.Version != "" {
			return d.Version
		}
	}
	return "unknown"
}

// version is injected at release-build time via
//
//	-ldflags "-X github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo.version=vX.Y.Z"
//
// (goreleaser sets it from the git tag). It is empty for `go run`, `go build`, and plain
// `go install`, which fall back to the compiled build metadata read below.
var version string

// App returns the main module's version. A release build injects the tag via ldflags (see version);
// otherwise it reads the compiled build metadata — "devel" for an untagged `go run` / `go build`, or the
// tag/pseudo-version for `go install <module>@<version>`.
func App() string {
	if version != "" {
		return version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return "devel"
	}
	return bi.Main.Version
}
