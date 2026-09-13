package runtimereach

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Wire-contract bounds. A fleet agent supplies this report, so every slice and string is capped at the
// trust boundary: a misbehaving or compromised agent must not be able to make the server allocate or index
// an unbounded runtime-evidence document. The caps are generous for a real host (a large distro image has a
// few thousand packages and a busy host loads a few thousand distinct objects between sweeps) and reject
// anything an order of magnitude beyond that as not-an-inventory.
const (
	MaxReportPackages     = 100_000
	MaxFilesPerPackage    = 200_000
	MaxReportLoads        = 200_000
	MaxReportPathBytes    = 4_096
	MaxReportCoverage     = 256
	maxReportPackageBytes = 1_024
)

// CoverageReason is a closed label explaining why the runtime evidence is partial. Like the host-inventory
// coverage model, an honest gap (no eBPF privilege, an unreadable package database) lowers what the join can
// prove but never turns absence into a false negative: runtime reachability is raise-only, so missing
// evidence simply forgoes an urgency raise.
type CoverageReason string

const (
	CoverageSensorUnavailable   CoverageReason = "sensor-unavailable"    // eBPF could not run (no privilege / kernel)
	CoverageUnreadablePackageDB CoverageReason = "unreadable-package-db" // dpkg/rpm/apk query failed
	CoverageUnsupportedPlatform CoverageReason = "unsupported-platform"  // not a Linux host with a known package manager
	CoverageTruncated           CoverageReason = "truncated"             // evidence exceeded a local cap and was cut
)

func (r CoverageReason) valid() bool {
	switch r {
	case CoverageSensorUnavailable, CoverageUnreadablePackageDB, CoverageUnsupportedPlatform, CoverageTruncated:
		return true
	}
	return false
}

// Report is the runtime-reachability evidence a host agent ships: the OS packages that own the shared
// objects observed loaded (scoped to the loaded set, not the whole file database), the observed loads, and
// any coverage gaps. It is the wire twin of the resolver inputs: Build turns a validated report into an
// Ownership index and a LoadEvent slice with no further trust in the agent's framing.
type Report struct {
	PackageFiles []PackageFiles   `json:"package_files,omitempty"`
	Loads        []LoadEvent      `json:"loads,omitempty"`
	Coverage     []CoverageReason `json:"coverage,omitempty"`
}

// Validate rejects a malformed or unbounded report at the trust boundary.
func (r Report) Validate() error {
	if len(r.PackageFiles) > MaxReportPackages {
		return fmt.Errorf("%w: runtime report has %d packages, above the %d cap", shared.ErrValidation, len(r.PackageFiles), MaxReportPackages)
	}
	if len(r.Loads) > MaxReportLoads {
		return fmt.Errorf("%w: runtime report has %d loads, above the %d cap", shared.ErrValidation, len(r.Loads), MaxReportLoads)
	}
	if len(r.Coverage) > MaxReportCoverage {
		return fmt.Errorf("%w: runtime report has too many coverage entries", shared.ErrValidation)
	}
	for _, pkg := range r.PackageFiles {
		if err := validatePackageIdentity(pkg.Package); err != nil {
			return err
		}
		if len(pkg.Files) > MaxFilesPerPackage {
			return fmt.Errorf("%w: package %q lists %d files, above the %d cap", shared.ErrValidation, pkg.Package.Name, len(pkg.Files), MaxFilesPerPackage)
		}
		for _, f := range pkg.Files {
			if err := validatePath(f.Path); err != nil {
				return fmt.Errorf("package %q: %w", pkg.Package.Name, err)
			}
		}
	}
	for _, load := range r.Loads {
		if err := validatePath(load.Path); err != nil {
			return err
		}
		if load.RealPath != "" {
			if err := validatePath(load.RealPath); err != nil {
				return err
			}
		}
	}
	for _, c := range r.Coverage {
		if !c.valid() {
			return fmt.Errorf("%w: unknown runtime coverage reason %q", shared.ErrValidation, c)
		}
	}
	return nil
}

func validatePackageIdentity(p PackageRef) error {
	name, version := strings.TrimSpace(p.Name), strings.TrimSpace(p.Version)
	if name == "" || version == "" {
		return fmt.Errorf("%w: runtime report package needs a name and version", shared.ErrValidation)
	}
	if len(name) > maxReportPackageBytes || len(version) > maxReportPackageBytes {
		return fmt.Errorf("%w: runtime report package identity exceeds bounds", shared.ErrValidation)
	}
	return nil
}

func validatePath(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("%w: runtime report has an empty path", shared.ErrValidation)
	}
	if len(p) > MaxReportPathBytes {
		return fmt.Errorf("%w: runtime report path exceeds %d bytes", shared.ErrValidation, MaxReportPathBytes)
	}
	// A shared-library load and a package-owned file are both absolute host paths (the agent's collector only
	// ever emits absolute, cleaned paths). Reject a relative path at the trust boundary so a malformed or
	// hostile agent cannot slip a non-absolute token into the ownership/path matching.
	if !strings.HasPrefix(strings.TrimSpace(p), "/") {
		return fmt.Errorf("%w: runtime report path %q is not absolute", shared.ErrValidation, p)
	}
	return nil
}

// Build converts a validated report into the resolver inputs: the Ownership index the loads are resolved
// against, and the observed loads. It does not itself validate; callers Validate at the trust boundary.
func (r Report) Build() (*Ownership, []LoadEvent) {
	ownership := NewOwnership(r.PackageFiles)
	loads := append([]LoadEvent(nil), r.Loads...)
	return ownership, loads
}

// Normalize orders the report deterministically so two syncs of an unchanged host produce an identical
// document, and drops packages with no owned files. It does not change meaning.
func (r Report) Normalize() Report {
	out := Report{}
	for _, pkg := range r.PackageFiles {
		if len(pkg.Files) == 0 {
			continue
		}
		files := append([]OwnedFile(nil), pkg.Files...)
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		out.PackageFiles = append(out.PackageFiles, PackageFiles{Package: pkg.Package, Files: files})
	}
	sort.Slice(out.PackageFiles, func(i, j int) bool {
		if out.PackageFiles[i].Package.Name != out.PackageFiles[j].Package.Name {
			return out.PackageFiles[i].Package.Name < out.PackageFiles[j].Package.Name
		}
		return out.PackageFiles[i].Package.Version < out.PackageFiles[j].Package.Version
	})
	out.Loads = append([]LoadEvent(nil), r.Loads...)
	sort.Slice(out.Loads, func(i, j int) bool { return out.Loads[i].Path < out.Loads[j].Path })
	out.Coverage = append([]CoverageReason(nil), r.Coverage...)
	sort.Slice(out.Coverage, func(i, j int) bool { return out.Coverage[i] < out.Coverage[j] })
	return out
}

// Empty reports whether the report carries no runtime evidence at all (nothing to join).
func (r Report) Empty() bool { return len(r.PackageFiles) == 0 || len(r.Loads) == 0 }
