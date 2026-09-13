// Package runtimereach models the deterministic join from an OBSERVED runtime library load on a
// monitored host (EPIC #1042 #1061) to the OS package that owns the loaded file, and from that package
// to the finding it affects. The signal is RAISE-ONLY: an observed load raises a finding's urgency, and
// the absence of a load proves nothing (a host may not have exercised the path yet), so this package
// never concludes not-reachable and never suppresses.
//
// The join is by PACKAGE OWNERSHIP, never a bare path string. A loaded object is attributed to a package
// through the host's dpkg/rpm/apk file database, disambiguated by filesystem identity (device + inode) so
// that a symlink, a deleted-then-replaced file, or two installed versions of the same library resolve to
// the exact package that was loaded. When ownership is ambiguous (a path several packages claim, with no
// filesystem identity to separate them) the resolver returns no match: a bare-path collision must never
// misattribute a load to the wrong package.
package runtimereach

import (
	"sort"
	"strings"
)

// PackageRef identifies one installed OS package by the name and version its package manager records.
// Two versions of the same library are two distinct PackageRefs, which is what lets a load of one version
// raise only that version's finding.
type PackageRef struct {
	Name    string
	Version string
}

// IsZero reports whether the reference names no package.
func (p PackageRef) IsZero() bool {
	return strings.TrimSpace(p.Name) == "" && strings.TrimSpace(p.Version) == ""
}

// FileID is the filesystem identity of a file: the device it lives on and its inode. It is unique per file
// on a running host, so it disambiguates a path that several packages claim and it survives a symlink (the
// resolved target carries the real device+inode). A zero FileID means the identity was not observed.
type FileID struct {
	Device uint64
	Inode  uint64
}

// Known reports whether both halves of the identity were observed.
func (f FileID) Known() bool { return f.Device != 0 && f.Inode != 0 }

// OwnedFile is one file the package database attributes to a package, carrying its canonical install path
// and, when the agent could stat it, its filesystem identity.
type OwnedFile struct {
	Path string
	ID   FileID
}

// PackageFiles is the file set the package database attributes to one package.
type PackageFiles struct {
	Package PackageRef
	Files   []OwnedFile
}

// MatchKind records HOW a load was attributed, for the sealed audit trail. A file-identity match is the
// strong, misattribution-proof attribution; a unique-path match is the weaker fallback used only when the
// path is owned by exactly one package.
type MatchKind string

const (
	// MatchNone means the load was not attributed to any package. It is the fail-closed outcome for an
	// unknown path, a bare-path collision with no filesystem identity, or a deleted file with no identity.
	MatchNone MatchKind = ""
	// MatchFileIdentity attributes a load by device+inode: the exact file the package DB owns was loaded,
	// regardless of the path it was opened through (symlink) or how many packages claim that path.
	MatchFileIdentity MatchKind = "file_identity"
	// MatchUniquePath attributes a load by canonical path when exactly ONE package owns that path and no
	// filesystem identity was available to confirm it. A path owned by more than one package never matches
	// this way.
	MatchUniquePath MatchKind = "unique_path"
)

// Ownership is the host's file-to-package map, built once per host from its dpkg/rpm/apk file database. It
// indexes ownership two ways: by filesystem identity (device+inode) and by canonical path. The path index
// records EVERY package that claims a path, so a collision is detectable and can fail closed.
type Ownership struct {
	byID   map[FileID][]PackageRef
	byPath map[string][]PackageRef
	// hasIDCoverage is true when the package DB carried filesystem identity for at least one file. When it
	// does, an observed load whose known device+inode is ABSENT from the index means the on-disk file no
	// longer matches what the DB records (an out-of-band replacement), so the path fallback is skipped to
	// avoid over-attributing the load to the path's recorded owner. When the DB carries no identity at all
	// (path-only export), the path fallback stays the only option and is always used.
	hasIDCoverage bool
}

// NewOwnership builds the index from the host's package file lists. Duplicate (package, key) pairs collapse,
// so a package that lists the same path twice, or two file lists for the same package, do not fabricate a
// collision. Paths are cleaned (see cleanPath) so an index lookup and an event lookup normalize identically.
func NewOwnership(packages []PackageFiles) *Ownership {
	o := &Ownership{byID: map[FileID][]PackageRef{}, byPath: map[string][]PackageRef{}}
	seenID := map[FileID]map[PackageRef]struct{}{}
	seenPath := map[string]map[PackageRef]struct{}{}
	for _, pkg := range packages {
		ref := pkg.Package
		if ref.IsZero() {
			continue
		}
		for _, f := range pkg.Files {
			if f.ID.Known() {
				o.hasIDCoverage = true
				if seenID[f.ID] == nil {
					seenID[f.ID] = map[PackageRef]struct{}{}
				}
				if _, dup := seenID[f.ID][ref]; !dup {
					seenID[f.ID][ref] = struct{}{}
					o.byID[f.ID] = append(o.byID[f.ID], ref)
				}
			}
			path := cleanPath(f.Path)
			if path == "" {
				continue
			}
			if seenPath[path] == nil {
				seenPath[path] = map[PackageRef]struct{}{}
			}
			if _, dup := seenPath[path][ref]; !dup {
				seenPath[path][ref] = struct{}{}
				o.byPath[path] = append(o.byPath[path], ref)
			}
		}
	}
	return o
}

// LoadEvent is one observed runtime library load, post-normalization: the path the process opened, its
// symlink-resolved real path when the agent could read it, the loaded file's filesystem identity, and
// whether the mapped file had been unlinked (the "(deleted)" case, where the path can no longer be trusted).
type LoadEvent struct {
	Path     string
	RealPath string
	ID       FileID
	Deleted  bool
}

// Resolve attributes one load to the package that owns the loaded file, returning the package and how it
// was matched. It is deterministic and fails closed:
//
//   - Filesystem identity wins: if the load carries a device+inode the package DB indexes to EXACTLY one
//     package, that package owns the load (MatchFileIdentity). This is immune to symlinks, to a path several
//     packages claim, and to two installed versions (each version's file has its own inode). If the identity
//     resolves to more than one package (a cross-package hard link, rare) it is ambiguous and does not match.
//   - Identity that disagrees with an identity-carrying DB fails closed: if the load carries a device+inode,
//     the DB records identities for its files, but this exact device+inode is in none of them, the on-disk
//     file no longer matches any package's recorded file (an out-of-band replacement, overlay, or stale DB).
//     The stronger identity evidence is not silently discarded for a weaker path match, so this returns no
//     match rather than attributing the load to the path's recorded owner.
//   - Path is the fallback only: with no usable identity (the load carried none, or the DB carries none at
//     all), the real path (preferred) or the opened path is matched against the package DB. A path owned by
//     exactly one package matches (MatchUniquePath). A path owned by several packages is a collision and does
//     NOT match, so a bare-path collision never misattributes. A deleted file with no identity never matches
//     on path, because its path was unlinked and may now name a different file.
func (o *Ownership) Resolve(ev LoadEvent) (PackageRef, MatchKind) {
	if o == nil {
		return PackageRef{}, MatchNone
	}
	if ev.ID.Known() {
		if refs := o.byID[ev.ID]; len(refs) == 1 {
			return refs[0], MatchFileIdentity
		} else if len(refs) > 1 {
			// A single inode owned by several packages cannot be separated by identity; fail closed.
			return PackageRef{}, MatchNone
		} else if o.hasIDCoverage {
			// The load carries a filesystem identity and the DB carries identities too, but this exact
			// device+inode is in none of them: the on-disk file no longer matches any package's recorded
			// file (an out-of-band replacement). Falling back to the path would over-attribute the load to
			// the path's recorded owner, so fail closed. (When the DB has no identity data at all, this
			// branch is skipped and the path fallback below still runs.)
			return PackageRef{}, MatchNone
		}
	}
	if ev.Deleted {
		// The mapped file was unlinked. Without a filesystem identity the path is untrustworthy (it may now
		// name a replacement file from a different package), so a deleted load only ever matches by identity.
		return PackageRef{}, MatchNone
	}
	for _, candidate := range []string{ev.RealPath, ev.Path} {
		path := cleanPath(candidate)
		if path == "" {
			continue
		}
		if refs := o.byPath[path]; len(refs) == 1 {
			return refs[0], MatchUniquePath
		} else if len(refs) > 1 {
			// The path is claimed by several packages and no identity separates them; fail closed rather
			// than guess. This is the "bare path collision does not misattribute" guarantee.
			return PackageRef{}, MatchNone
		}
	}
	return PackageRef{}, MatchNone
}

// cleanPath normalizes a filesystem path for a stable index/lookup: it trims surrounding space, strips a
// trailing " (deleted)" marker the kernel appends to an unlinked mapping's path, collapses redundant
// separators, and drops a trailing slash. It does not resolve symlinks (the agent does that, reporting
// RealPath) and does not touch case (Linux paths are case-sensitive).
func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimSuffix(p, " (deleted)")
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Collapse duplicate slashes without importing path.Clean's "." / ".." semantics, which are wrong for a
	// package DB path (a literal "/a/../b" file, however unlikely, is a different file than "/b").
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// SortPackageRefs orders references by name then version, for deterministic output.
func SortPackageRefs(refs []PackageRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Name != refs[j].Name {
			return refs[i].Name < refs[j].Name
		}
		return refs[i].Version < refs[j].Version
	})
}
