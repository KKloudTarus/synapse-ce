// Package importedfinding models a finding produced by a THIRD-PARTY scanner and ingested into this
// system's governance path.
//
// The whole point of the type is that an external result is never presented as this system's own
// analysis. Provenance is mandatory and immutable: a finding whose tool, rule and source document cannot
// be established is refused rather than stored, because an unattributable finding cannot be reasoned
// about, disputed, or re-checked against its source.
//
// An imported finding also carries no promotion authority. An external tool's confidence is not a
// distinct verifier's sealed verdict, so it participates in the finding lifecycle without ever being
// able to promote itself through the judgment gate.
package importedfinding

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Provenance is the immutable record of where an imported finding came from. Every field is required:
// together they let a reader re-derive the finding from its source document.
type Provenance struct {
	// ToolName and ToolVersion identify the scanner that produced the result.
	ToolName    string
	ToolVersion string
	// RuleID is the tool's own rule identifier.
	RuleID string
	// SourceDigest is the SHA-256 of the exact document ingested, which makes ingest idempotent and
	// lets a dispute be settled against the original bytes.
	SourceDigest string
	// IngestedBy is the actor who performed the ingest, and IngestedAt when.
	IngestedBy shared.ID
	IngestedAt string
}

// Validate reports whether the provenance is complete. A partial provenance is refused rather than
// stored, because it cannot be attributed.
func (p Provenance) Validate() error {
	missing := make([]string, 0, 6)
	for name, value := range map[string]string{
		"tool name":     p.ToolName,
		"tool version":  p.ToolVersion,
		"rule id":       p.RuleID,
		"source digest": p.SourceDigest,
		"ingested at":   p.IngestedAt,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if p.IngestedBy.IsZero() {
		missing = append(missing, "ingested by")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: imported finding provenance is incomplete: missing %s",
			shared.ErrValidation, strings.Join(sortedStrings(missing), ", "))
	}
	return nil
}

// Location is the normalized position an external result points at. Only repository-relative paths are
// accepted: a SARIF document is untrusted input, and an absolute path or a traversal would let a report
// point outside the scanned tree.
type Location struct {
	// Path is a repository-relative slash path, empty when the result has no physical location.
	Path string
	// StartLine and StartColumn are 1-based; zero means unspecified.
	StartLine   int
	StartColumn int
	// LogicalName is the tool's logical location (a fully-qualified symbol), kept when present.
	LogicalName string
}

// ImportedFinding is one third-party result under this system's governance.
type ImportedFinding struct {
	ID           shared.ID
	TenantID     shared.ID
	EngagementID shared.ID
	// FindingID links to a first-party finding this result agrees with, when deduplication matched one.
	FindingID shared.ID
	// Severity is the mapped severity. It is shared.SeverityUnknown when the source severity has no
	// documented mapping — NEVER a default of medium, which would silently invent a risk level.
	Severity shared.Severity
	// Title and Message are the tool's own description, kept verbatim for the reader.
	Title    string
	Message  string
	Location Location
	// Suppressed records that the source document marked this result suppressed. It is kept rather than
	// acted on: an external tool's suppression is information, not authority over this system's gate.
	Suppressed bool
	// Fingerprint is the tool's partial fingerprint, used for stable identity across re-scans.
	Fingerprint string
	Provenance  Provenance
	Audit       shared.Audit
}

// External reports that this finding came from another tool. It exists so every surface that renders a
// finding has one obvious predicate to branch on rather than inferring it.
func (ImportedFinding) External() bool { return true }

// CanSelfPromote reports whether an imported finding may promote itself through the judgment gate.
//
// It is always false. An external tool's confidence is not a distinct verifier's sealed verdict, so an
// imported result can only ever be evidence a human or a verifier weighs — never its own justification.
func (ImportedFinding) CanSelfPromote() bool { return false }

// Validate checks the invariants that must hold before a finding is stored.
func (f ImportedFinding) Validate() error {
	if f.EngagementID.IsZero() {
		return fmt.Errorf("%w: imported finding needs an engagement", shared.ErrValidation)
	}
	if f.TenantID.IsZero() {
		return fmt.Errorf("%w: imported finding needs a tenant", shared.ErrValidation)
	}
	if err := f.Provenance.Validate(); err != nil {
		return err
	}
	if !validSeverity(f.Severity) {
		return fmt.Errorf("%w: imported finding severity %q is not a known severity", shared.ErrValidation, f.Severity)
	}
	return nil
}

func validSeverity(s shared.Severity) bool {
	switch s {
	case shared.SeverityCritical, shared.SeverityHigh, shared.SeverityMedium,
		shared.SeverityLow, shared.SeverityInfo, shared.SeverityUnknown:
		return true
	}
	return false
}

// RefusalReason is a typed explanation for a result that was NOT ingested.
//
// Refusals are returned as a list rather than a count, because a silent refusal is indistinguishable
// from a clean ingest — the caller must be able to see exactly what was dropped and why.
type RefusalReason struct {
	// RunIndex and ResultIndex locate the refused result in the source document.
	RunIndex    int
	ResultIndex int
	// Code is the machine-readable refusal class.
	Code RefusalCode
	// Detail is a short human-readable explanation that never quotes document content.
	Detail string
}

// RefusalCode enumerates why a result can be refused.
type RefusalCode string

const (
	RefusalNoProvenance    RefusalCode = "no-provenance"
	RefusalInvalidLocation RefusalCode = "invalid-location"
	RefusalUnsupportedURI  RefusalCode = "unsupported-uri-scheme"
	RefusalPathTraversal   RefusalCode = "path-traversal"
	RefusalAbsolutePath    RefusalCode = "absolute-path"
	RefusalMalformedResult RefusalCode = "malformed-result"
	RefusalCyclicRelation  RefusalCode = "cyclic-related-locations"
)

// Valid reports whether c is a known refusal code.
func (c RefusalCode) Valid() bool {
	switch c {
	case RefusalNoProvenance, RefusalInvalidLocation, RefusalUnsupportedURI,
		RefusalPathTraversal, RefusalAbsolutePath, RefusalMalformedResult, RefusalCyclicRelation:
		return true
	}
	return false
}

// CoverageIssue records a limitation of the ingest itself, distinct from a refused result.
type CoverageIssue struct {
	Detail string
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
