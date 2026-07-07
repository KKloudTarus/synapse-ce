// Package finding models a confirmed or candidate security issue in an engagement.
package finding

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
)

// Status is the finding triage lifecycle state.
type Status string

const (
	StatusOpen       Status = "open"
	StatusTriage     Status = "triage"
	StatusConfirmed  Status = "confirmed"
	StatusFalsePos   Status = "false_positive"
	StatusRemediated Status = "remediated"
)

// Finding classes: third-party findings are actionable; first-party
// historical advisories are matched against the project's own unversioned modules
// and are informational only — never counted in remediation/critical totals.
const (
	ClassThirdParty         = "third_party"
	ClassFirstPartyHistoric = "first_party_historical"
	// ClassFirstParty is a first-party, ACTIONABLE weakness in the project's OWN source — e.g. a
	// deterministic pattern-SAST hit. Unlike ClassFirstPartyHistoric (unconfirmable advisory,
	// informational), it is real and remediable; unlike ClassThirdParty, it is not a dependency.
	ClassFirstParty = "first_party"
)

// Kind discriminates how a finding was produced. It governs promotion
// gating: SCA findings are backed by scanner + DB evidence and
// are not gated here; exploitation/AI findings MUST clear the evidence bar
// (>= EvidenceThreshold) before promotion. recon/manual findings are not gated.
type Kind string

const (
	KindSCA          Kind = "sca"
	KindRecon        Kind = "recon"
	KindExploitation Kind = "exploitation"
	KindManual       Kind = "manual"
	KindSAST         Kind = "sast"       // first-party source-code issue (SAST)
	KindSecret       Kind = "secret"     // a hardcoded secret found in source (deterministic; ungated)
	KindDAST         Kind = "dast"       // runtime app issue (DAST; deferred)
	KindThreat       Kind = "threat"     // threat-model item
	KindHypothesis   Kind = "hypothesis" // AI-proposed attack-chain hypothesis linking findings (gated until human-verified)
)

// Valid reports whether k is a known finding kind.
func (k Kind) Valid() bool {
	switch k {
	case KindSCA, KindRecon, KindExploitation, KindManual, KindSAST, KindSecret, KindDAST, KindThreat, KindHypothesis:
		return true
	}
	return false
}

// Valid reports whether s is a known triage status.
func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusTriage, StatusConfirmed, StatusFalsePos, StatusRemediated:
		return true
	}
	return false
}

// Finding is a confirmed or candidate security issue within an engagement.
type Finding struct {
	ID           shared.ID
	EngagementID shared.ID
	Title        string
	Description  string
	Severity     shared.Severity
	CVSSVector   string
	CWE          string
	Status       Status

	// Kind discriminates how the finding was produced (sca|recon|exploitation|
	// manual); it drives promotion gating. Empty is treated as KindSCA for
	// backward compatibility with legacy rows.
	Kind Kind

	// Workflow: the human assignee, and an optimistic-concurrency version that
	// Kanban/status/assignee edits check to prevent lost updates.
	Assignee string
	Version  int

	// Risk priority (CISA KEV -> EPSS x CVSS), copied from the source vuln so
	// findings can be ordered by real risk. KEV findings rank above all.
	KEV       bool
	RiskScore float64

	// Detection provenance: the sources that detected the underlying
	// vulnerability and the multi-source confidence. Empty for non-SCA findings.
	Sources    []string
	Confidence string

	// Class separates actionable third-party findings from historical
	// advisories matched against the project's own unversioned modules.
	Class string

	// Finding-quality signals: the component scope, metadata-only
	// reachability, action impact, and unified Synapse risk priority (1..5).
	Scope        string
	Reachability string
	Impact       string
	Priority     int

	// ClassReachability is the coarse JVM class-reachability verdict for the component:
	// "reachable" | "unreferenced" | "" (unknown). Advisory only — deprioritizes an unreferenced
	// component's finding, never suppresses it; lets a report/export SEPARATE used from unreferenced deps.
	ClassReachability string `json:",omitempty"`

	// nb: Class constants are below.

	// DedupKey makes a finding idempotent across re-scans (e.g. advisory+component+version
	// for SCA vulns, or license:<id>); used as the upsert conflict key.
	DedupKey string

	// EvidenceScore gates promotion: candidates below the threshold are not
	// auto-promoted (deterministic evidence gating: AI-proposed findings are never
	// auto-promoted).
	EvidenceScore int

	// ProposedBy is the actor that proposed an exploitation/AI finding (e.g. "agent:<sid>").
	// It exists so the adversarial verifier that later raises the score CANNOT be the same
	// actor that proposed it (a finding cannot confirm itself). Empty for
	// SCA/recon/manual findings.
	ProposedBy string

	Audit shared.Audit
}

// EvidenceThreshold is the minimum evidence score for a finding to be promoted. It is the shared
// bar — defined once in internal/domain/verdict and aliased here, so finding + judgment can
// never drift apart.
const EvidenceThreshold = verdict.EvidenceThreshold

// MeetsEvidenceBar reports whether the finding has enough evidence to be promoted.
func (f *Finding) MeetsEvidenceBar() bool { return f.EvidenceScore >= EvidenceThreshold }

// kindNormalized treats an empty Kind as KindSCA (back-compat) so a gating decision
// never depends on the raw zero value.
func (f *Finding) kindNormalized() Kind {
	if f.Kind == "" {
		return KindSCA
	}
	return f.Kind
}

// RequiresEvidenceGate reports whether this finding must clear the evidence bar before promotion.
// It gates on PROVENANCE, not category: any AI/agent-proposed finding (ProposedBy != "") is
// an unproven CLAIM and is gated, plus KindExploitation as a defensive belt for the highest-risk
// kind. SCA/recon/manual — and a HUMAN-entered sast/dast/threat (ProposedBy == "", carrying
// human evidence like a manual finding) — are not gated. Attribution implies gating; a
// missing/unknown Kind can never REMOVE the gate (fail-closed via the ProposedBy check +
// kindNormalized). NewManual never sets ProposedBy, so manual findings stay ungated.
func (f *Finding) RequiresEvidenceGate() bool {
	return strings.TrimSpace(f.ProposedBy) != "" || f.kindNormalized() == KindExploitation
}

// CanPromote reports whether the finding may be promoted/auto-published. Gated
// kinds must meet the evidence bar (>= EvidenceThreshold); others always may.
// The recon/exploitation use cases MUST call this before persisting
// a finding as confirmed — it is the deterministic evidence gate.
func (f *Finding) CanPromote() bool {
	if f.RequiresEvidenceGate() {
		return f.MeetsEvidenceBar()
	}
	return true
}

// Publishable filters a finding slice to those that may appear in a customer-facing
// deliverable, applying the deterministic evidence gate via CanPromote.
// It is the SINGLE rule every client-facing reader funnels through — directly, or via
// the repository's ListPublishableByEngagement — so no export/report surface (PDF, HTML,
// DOCX, SARIF, OpenVEX, engagement bundle) can leak an unproven exploitation finding.
// The input is not mutated; order is preserved.
func Publishable(in []Finding) []Finding {
	out := make([]Finding, 0, len(in))
	for i := range in {
		if in[i].CanPromote() {
			out = append(out, in[i])
		}
	}
	return out
}
