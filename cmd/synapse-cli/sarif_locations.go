package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// sarifManifestPaths maps each component (name@version) to the manifest that declares it, as a slash-separated
// path relative to the scanned directory, so a dependency result in SARIF points at that manifest the way a
// secret or SAST result points at its file. A component whose manifest cannot be placed under root is left
// out, and its result then carries no location: a result with no location is a valid repository-level alert,
// while an absolute path names a file on one machine that no code-scanning service can match, and differs
// from runner to runner. If two components share a name and version, the last one read wins; either manifest
// declares it.
func sarifManifestPaths(root string, components []sbom.Component) map[string]string {
	out := map[string]string{}
	for _, c := range components {
		if path, ok := manifestPathUnderRoot(root, c.Location); ok {
			out[c.Name+"@"+c.Version] = path
		}
	}
	return out
}

// manifestPathUnderRoot returns location as a slash-separated path relative to root, or false when location
// does not name a file under root. Two producers record locations differently:
//
//   - the owned producer records the manifest's absolute path, which is under root because a local directory is
//     scanned in place. root is also tried with its symlinks resolved, since the path the producer recorded and
//     the directory the user named can differ by a link (on macOS /tmp is /private/tmp);
//   - Syft roots a directory scan's paths at the scanned directory with a leading slash ("/pom.xml"). That form
//     is only accepted when the file really is there, so an absolute path from elsewhere is never passed off as
//     a path in the repository, which is what turned /private/tmp/... into "private/tmp/...".
func manifestPathUnderRoot(root, location string) (string, bool) {
	location = strings.TrimSpace(location)
	if root == "" || location == "" {
		return "", false
	}
	roots := []string{root}
	if resolved, err := filepath.EvalSymlinks(root); err == nil && resolved != root {
		roots = append(roots, resolved)
	}
	if filepath.IsAbs(location) {
		for _, r := range roots {
			if rel, ok := relativeUnder(r, location); ok {
				return rel, true
			}
		}
	}
	candidate := filepath.Join(root, filepath.FromSlash(strings.TrimLeft(location, `/\`)))
	if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
		return relativeUnder(root, candidate)
	}
	return "", false
}

// relativeUnder returns path relative to root, slash-separated, when path is strictly inside root.
func relativeUnder(root, path string) (string, bool) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}
