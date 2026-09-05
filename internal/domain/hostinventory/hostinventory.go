// Package hostinventory is the fleet VM-agent inventory model (#410, epic #405): the facts and
// installed packages an agent collects from a host that is not a container. It is pure domain
// (imports only shared, sbom, and the stdlib).
//
// Coverage honesty is the point of this type. An unreadable package database or an unsupported
// platform is a CoverageIssue, and any issue makes the inventory Incomplete. A silent partial
// inventory reported as complete is exactly the failure this platform exists to prevent.
package hostinventory

import (
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// MaxHostsPerAgent bounds how many distinct host assets one enrolled agent identity may create.
// A host key is agent supplied, so without a cap a misbehaving or compromised agent could mint
// unbounded hosts, hidden vulnerability contexts and scans by varying its facts. A reimaged machine
// gets a new machine id and legitimately consumes one slot. The use case checks the cap before it
// writes; the fleet_assets trigger in migration 0132 and the in-memory store enforce the same number
// inside the write so concurrent syncs cannot exceed it.
const MaxHostsPerAgent = 16

// CoverageKind classifies why part of the host could not be inventoried.
type CoverageKind string

const (
	// CoverageUnreadableDB: a package database exists but could not be read.
	CoverageUnreadableDB CoverageKind = "unreadable-package-db"
	// CoverageNoPackageDB: no supported package database was found on the host.
	CoverageNoPackageDB CoverageKind = "no-package-db"
	// CoverageUnsupportedPlatform: the agent cannot inventory this OS/platform.
	CoverageUnsupportedPlatform CoverageKind = "unsupported-platform"
	// CoverageMissingFact: a host fact could not be determined.
	CoverageMissingFact CoverageKind = "missing-fact"
	// CoverageNotCollected: a dimension the model supports is not gathered in this release, so its
	// absence is declared rather than passed off as "nothing present".
	CoverageNotCollected CoverageKind = "not-collected"
)

// Valid reports whether k is a known coverage kind.
func (k CoverageKind) Valid() bool {
	switch k {
	case CoverageUnreadableDB, CoverageNoPackageDB, CoverageUnsupportedPlatform, CoverageMissingFact, CoverageNotCollected:
		return true
	default:
		return false
	}
}

// Degraded reports whether this kind means data that should have been collectable could NOT be read,
// making what WAS collected untrustworthy (an existing package DB we failed to open). This is distinct
// from an honest, expected gap (no package manager on the host, a platform we don't support, or a
// dimension not yet collected in this release), which lowers completeness but does not poison the data
// we did gather. Callers use this to decide whether an inventory is fit to report as a clean success.
func (k CoverageKind) Degraded() bool {
	return k == CoverageUnreadableDB
}

// CoverageIssue is one reason the inventory is not fully trustworthy. The json tags are the wire
// contract shared by the agent (encoder) and the control-plane ingest endpoint (decoder).
type CoverageIssue struct {
	Kind   CoverageKind `json:"kind"`
	Detail string       `json:"detail,omitempty"`
}

// HostFacts identify the host and are the substrate for the asset inventory (#431).
type HostFacts struct {
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`         // e.g. linux
	OSVersion     string `json:"os_version,omitempty"` // from /etc/os-release
	Kernel        string `json:"kernel,omitempty"`
	Arch          string `json:"arch,omitempty"`
	MachineID     string `json:"machine_id,omitempty"`     // stable per-host identifier
	CloudInstance string `json:"cloud_instance,omitempty"` // cloud instance id when available; empty otherwise
}

// HostInventory is a point-in-time host assessment. Complete is derived from Coverage: it is true
// only when there are no coverage issues.
type HostInventory struct {
	Facts    HostFacts        `json:"facts"`
	Packages []sbom.Component `json:"packages,omitempty"`
	Coverage []CoverageIssue  `json:"coverage,omitempty"`
	Complete bool             `json:"complete"`
}

// Normalize deterministically orders packages and coverage and derives Complete. It never mutates
// its input's meaning, only canonicalises order and the Complete flag.
func (h HostInventory) Normalize() HostInventory {
	out := h
	out.Packages = append([]sbom.Component(nil), h.Packages...)
	sort.Slice(out.Packages, func(i, j int) bool {
		if out.Packages[i].Name != out.Packages[j].Name {
			return out.Packages[i].Name < out.Packages[j].Name
		}
		return out.Packages[i].Version < out.Packages[j].Version
	})
	out.Coverage = append([]CoverageIssue(nil), h.Coverage...)
	sort.Slice(out.Coverage, func(i, j int) bool {
		if out.Coverage[i].Kind != out.Coverage[j].Kind {
			return out.Coverage[i].Kind < out.Coverage[j].Kind
		}
		return out.Coverage[i].Detail < out.Coverage[j].Detail
	})
	out.Complete = out.IsComplete()
	return out
}

// AddIssue records a coverage issue (trimming the detail).
func (h *HostInventory) AddIssue(kind CoverageKind, detail string) {
	h.Coverage = append(h.Coverage, CoverageIssue{Kind: kind, Detail: strings.TrimSpace(detail)})
}

// IsComplete reports completeness directly from the coverage list, so a caller that reads it after
// AddIssue (without re-running Normalize) still gets the right answer. Complete is the stored mirror.
func (h HostInventory) IsComplete() bool { return len(h.Coverage) == 0 }

// Degraded reports whether any coverage issue poisons the collected data (see CoverageKind.Degraded).
// An inventory that is merely incomplete (expected gaps) is not degraded; a degraded one must not be
// reported as a clean success.
func (h HostInventory) Degraded() bool {
	for _, c := range h.Coverage {
		if c.Kind.Degraded() {
			return true
		}
	}
	return false
}
