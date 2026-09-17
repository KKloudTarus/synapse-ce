package runtimeevidence

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ospkg"
)

// collectRpm resolves, from the rpm database under the collector root, the packages that own any of the
// loaded objects, returning each such package's owned files with device+inode. It reuses ospkg.RPMOwnership,
// which reads the binary rpm header store directly (no shell) across all three container formats (sqlite,
// BerkeleyDB, ndb) with the same bounded, recover-wrapped hardening the SBOM cataloger uses, so a hostile
// or corrupt DB degrades to empty coverage rather than crashing or hanging the sweep.
//
// Like the dpkg and apk collectors, it is scoped and lazy: a package is emitted only when it owns one of the
// loaded objects, and device+inode are stat'd only for those owning packages, so the sweep costs O(files) to
// scan but O(files-in-owning-packages) stats. An unreadable DB is a declared CoverageReason, keeping the
// raise-only join coverage-honest.
func (c *Collector) collectRpm(loadedSet map[string]struct{}) ([]runtimereach.PackageFiles, []runtimereach.CoverageReason) {
	// The rpm walkers honor context cancellation, but the collector API carries no context; their per-blob
	// size filter plus total-byte and package-count budgets bound the work regardless, so a background
	// context is safe here.
	pkgs, err := ospkg.RPMOwnership(context.Background(), c.root)
	if err != nil {
		return nil, []runtimereach.CoverageReason{runtimereach.CoverageUnreadablePackageDB}
	}
	if len(pkgs) == 0 {
		// Collect() only reaches here when an rpm DB file is present, yet no file-owning package was read. A
		// real rpm root always has hundreds (glibc, bash, ...); zero means the DB is corrupt, an unsupported
		// container variant, or truncated. Declare the gap rather than pass the host off as "no vulnerable
		// library loaded", keeping the raise-only join coverage-honest.
		return nil, []runtimereach.CoverageReason{runtimereach.CoverageUnreadablePackageDB}
	}
	var out []runtimereach.PackageFiles
	for _, p := range pkgs {
		// First pass: does this package own any loaded object? Cheap path-membership test, no stats.
		owns := false
		cleaned := make([]string, 0, len(p.Files))
		for _, raw := range p.Files {
			lp := cleanLoadPath(raw)
			if lp == "" {
				continue
			}
			cleaned = append(cleaned, lp)
			if _, ok := loadedSet[lp]; ok {
				owns = true
			}
		}
		if !owns {
			continue // owns no loaded object: skip the O(files) stat entirely (scoped report)
		}
		// RPMOwnership guarantees identity: parseRPMHeaderFiles returns a package only when NAME and VERSION
		// are present, so unlike the dpkg/apk paths there is no owning-but-unversioned record to declare a gap
		// for. Every owning package here is joinable.
		files := make([]runtimereach.OwnedFile, 0, len(cleaned))
		for _, lp := range cleaned {
			files = append(files, c.ownedFile(lp)) // Collect() Normalizes (sorts) before shipping
		}
		out = append(out, runtimereach.PackageFiles{
			Package: runtimereach.PackageRef{Name: p.Name, Version: p.Version},
			Files:   files,
		})
	}
	return out, nil
}
