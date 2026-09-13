package runtimereach

import (
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FindingPackage binds a finding to the OS package its vulnerability is about. The caller derives it from
// the finding (its DedupKey parses to advisory+component+version), so this package never imports the
// finding domain and stays a pure join over identities.
type FindingPackage struct {
	FindingID shared.ID
	Package   PackageRef
}

// Hit is one raise-only runtime-reachability conclusion: the finding whose package was observed loaded, the
// package that resolved, and how the load was attributed. A Hit is only ever produced for an actual observed
// load; there is no "miss" record, because the absence of a load is not evidence of unreachability.
type Hit struct {
	FindingID shared.ID
	Package   PackageRef
	Match     MatchKind
}

// Join resolves each observed load to its owning package and raises every finding whose package matches, by
// EXACT name and version. The exact-version match is the multi-version guarantee: a load of libfoo 3.0 never
// raises a libfoo 1.1 finding, because they are distinct PackageRefs and the load resolved (by inode) to
// exactly one of them. A load that resolves to no package, or to a package no finding is about, yields no
// Hit. Output is one Hit per finding at most (the strongest match kind for that finding wins), sorted by
// finding id, so the result is deterministic and free of duplicates when several loads hit the same package.
func Join(loads []LoadEvent, ownership *Ownership, findings []FindingPackage) []Hit {
	if ownership == nil || len(loads) == 0 || len(findings) == 0 {
		return nil
	}
	// Index findings by their package identity. Several findings can share a package (two CVEs in one
	// library), so the value is a slice.
	byPkg := map[PackageRef][]shared.ID{}
	for _, fp := range findings {
		if fp.FindingID.IsZero() || fp.Package.IsZero() {
			continue
		}
		byPkg[fp.Package] = append(byPkg[fp.Package], fp.FindingID)
	}
	if len(byPkg) == 0 {
		return nil
	}
	best := map[shared.ID]Hit{}
	for _, ev := range loads {
		ref, kind := ownership.Resolve(ev)
		if kind == MatchNone {
			continue
		}
		for _, fid := range byPkg[ref] {
			if cur, ok := best[fid]; ok && matchRank(cur.Match) >= matchRank(kind) {
				continue // keep the strongest attribution for a deterministic, churn-free result
			}
			best[fid] = Hit{FindingID: fid, Package: ref, Match: kind}
		}
	}
	out := make([]Hit, 0, len(best))
	for _, h := range best {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FindingID < out[j].FindingID })
	return out
}

// matchRank orders attribution strength so the file-identity match beats a unique-path match for the same
// finding.
func matchRank(k MatchKind) int {
	switch k {
	case MatchFileIdentity:
		return 2
	case MatchUniquePath:
		return 1
	default:
		return 0
	}
}
