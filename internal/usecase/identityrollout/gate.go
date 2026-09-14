package identityrollout

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Phase string

const (
	PhaseExpand                      Phase = "expand"
	PhaseLegacyAuthoritativeBackfill Phase = "legacy_authoritative_backfill"
	PhaseShadowComparison            Phase = "shadow_comparison"
	PhaseCanaryAuthoritativeRead     Phase = "canary_authoritative_read"
	PhaseCanaryIdentityMutations     Phase = "canary_identity_mutations"
	PhasePointOfNoReturn             Phase = "point_of_no_return"
	PhaseContract                    Phase = "contract"
)

func (phase Phase) Valid() bool {
	switch phase {
	case PhaseExpand, PhaseLegacyAuthoritativeBackfill, PhaseShadowComparison, PhaseCanaryAuthoritativeRead, PhaseCanaryIdentityMutations, PhasePointOfNoReturn, PhaseContract:
		return true
	default:
		return false
	}
}

type GateSnapshot struct {
	TenantID                 string
	Owner                    string
	SourceOfTruth            string
	AllowedWriters           []string
	SourceCount              int
	ProjectedCount           int
	DriftCount               int
	CorruptCredentialCount   int
	DuplicateCredentialCount int
	BootstrapMembershipCount int
	DenialCount              int
	ErrorCount               int
	SessionCount             int
	ObservationMinutes       int
	AbortThresholdBPS        int
	BackfillCompleted        bool
	ShadowComparisonComplete bool
	AuthoritativeReads       bool
	IdentityMutations        bool
	LegacyWritesEnabled      bool
	MetricsRecorded          bool
	ApprovalRecorded         bool
	RollbackDrillPassed      bool
	PairedBackupApproved     bool
	LastKnownGoodPhase       string
	RollbackAction           string
}

type GateFinding struct {
	Code    string
	Message string
}

type GateDecision struct {
	Phase    Phase
	TenantID string
	Allowed  bool
	Blockers []GateFinding
	Warnings []GateFinding
}

// Evaluate applies only invariant gates. It deliberately does not invent rollout percentages,
// latency ceilings, or observation durations: operational thresholds must come from measured
// baseline/canary evidence and are supplied in the snapshot when applicable.
func Evaluate(phase Phase, snapshot GateSnapshot) (GateDecision, error) {
	snapshot.TenantID = strings.TrimSpace(snapshot.TenantID)
	snapshot.Owner = strings.TrimSpace(snapshot.Owner)
	snapshot.SourceOfTruth = strings.TrimSpace(snapshot.SourceOfTruth)
	snapshot.LastKnownGoodPhase = strings.TrimSpace(snapshot.LastKnownGoodPhase)
	snapshot.RollbackAction = strings.TrimSpace(snapshot.RollbackAction)
	if !phase.Valid() || snapshot.TenantID == "" || len(snapshot.TenantID) > 128 || snapshot.Owner == "" || len(snapshot.Owner) > 256 || snapshot.RollbackAction == "" || invalidGateCounts(snapshot) {
		return GateDecision{}, fmt.Errorf("%w: identity rollout gate input is invalid", shared.ErrValidation)
	}

	decision := GateDecision{Phase: phase, TenantID: snapshot.TenantID, Blockers: []GateFinding{}, Warnings: []GateFinding{}}
	block := func(code, message string) { decision.Blockers = append(decision.Blockers, GateFinding{Code: code, Message: message}) }
	warn := func(code, message string) { decision.Warnings = append(decision.Warnings, GateFinding{Code: code, Message: message}) }

	if !allowedSourceOfTruth(snapshot.SourceOfTruth) {
		block("source_of_truth_invalid", "rollout source of truth is not a closed supported value")
	}
	if !validWriterSet(snapshot.AllowedWriters) {
		block("writer_set_invalid", "allowed writers contain an unknown or duplicate identity writer")
	}
	if snapshot.CorruptCredentialCount > 0 {
		block("corrupt_legacy_credential", "legacy credential digests must be valid before identity rollout can advance")
	}
	if snapshot.DuplicateCredentialCount > 0 {
		block("duplicate_legacy_credential", "legacy credential digests must be unique before identity rollout can advance")
	}
	if snapshot.BootstrapMembershipCount > 0 {
		block("bootstrap_membership_present", "deployment bootstrap authority must not become an ordinary membership")
	}
	if snapshot.ProjectedCount > snapshot.SourceCount {
		block("projection_count_invalid", "projected identity count cannot exceed legacy source count")
	}
	if snapshot.ErrorCount > snapshot.SessionCount && snapshot.SessionCount > 0 {
		block("error_count_invalid", "observed identity errors cannot exceed the measured request/session sample")
	}
	if snapshot.AbortThresholdBPS > 0 && snapshot.SessionCount > 0 && snapshot.ErrorCount*10000 > snapshot.SessionCount*snapshot.AbortThresholdBPS {
		block("abort_threshold_exceeded", "measured identity error rate exceeds the operator-supplied abort threshold")
	}

	switch phase {
	case PhaseExpand:
		if snapshot.SourceOfTruth != "legacy_users" {
			block("expand_source_not_legacy", "expand must leave legacy users authoritative")
		}
		if !containsOnly(snapshot.AllowedWriters, "legacy_users") {
			block("expand_writer_not_legacy", "expand must keep legacy users as the only identity writer")
		}
		if snapshot.AuthoritativeReads || snapshot.IdentityMutations {
			block("expand_authority_enabled", "expand cannot enable enterprise identity reads or mutations")
		}
	case PhaseLegacyAuthoritativeBackfill:
		requireLegacyAuthority(snapshot, block)
		if !snapshot.BackfillCompleted {
			block("backfill_incomplete", "legacy-authoritative backfill has not completed")
		}
		if snapshot.SourceCount != snapshot.ProjectedCount || snapshot.DriftCount != 0 {
			block("backfill_not_reconciled", "backfill source and projection counts must reconcile with zero drift")
		}
	case PhaseShadowComparison:
		requireLegacyAuthority(snapshot, block)
		if !snapshot.BackfillCompleted || !snapshot.ShadowComparisonComplete {
			block("shadow_incomplete", "shadow comparison requires a completed reconciled backfill")
		}
		if snapshot.SourceCount != snapshot.ProjectedCount || snapshot.DriftCount != 0 {
			block("shadow_drift", "shadow comparison must have full cardinality and zero unexplained drift")
		}
		if snapshot.ObservationMinutes == 0 || !snapshot.MetricsRecorded {
			block("shadow_observation_missing", "shadow comparison requires a recorded observation window and metrics")
		}
	case PhaseCanaryAuthoritativeRead:
		if snapshot.SourceOfTruth != "shadow_compare" {
			block("canary_read_source_invalid", "canary authoritative reads require shadow comparison as the declared source boundary")
		}
		if !snapshot.AuthoritativeReads || snapshot.IdentityMutations {
			block("canary_read_flags_invalid", "read canary enables enterprise reads without enterprise identity mutations")
		}
		if !snapshot.LegacyWritesEnabled {
			block("legacy_writer_disabled_early", "legacy writes remain enabled before mutation cutover")
		}
		requireCanaryEvidence(snapshot, block)
	case PhaseCanaryIdentityMutations:
		if !snapshot.AuthoritativeReads || !snapshot.IdentityMutations {
			block("mutation_canary_not_enabled", "identity mutation canary requires authoritative reads and mutations")
		}
		if snapshot.SourceOfTruth != "enterprise_identity" {
			block("mutation_source_invalid", "identity mutation canary must explicitly declare enterprise identity authority")
		}
		requireCanaryEvidence(snapshot, block)
	case PhasePointOfNoReturn:
		if snapshot.SourceOfTruth != "enterprise_identity" || !snapshot.AuthoritativeReads || !snapshot.IdentityMutations || snapshot.LegacyWritesEnabled {
			block("point_of_no_return_authority_invalid", "point of no return requires enterprise authority and disabled legacy writers")
		}
		if !snapshot.RollbackDrillPassed || !snapshot.PairedBackupApproved {
			block("recovery_evidence_missing", "point of no return requires rollback rehearsal and approved paired backup")
		}
		requireCanaryEvidence(snapshot, block)
	case PhaseContract:
		if snapshot.SourceOfTruth != "enterprise_identity" || !snapshot.AuthoritativeReads || !snapshot.IdentityMutations || snapshot.LegacyWritesEnabled {
			block("contract_authority_invalid", "contract requires enterprise identity as the sole authority")
		}
		if !snapshot.RollbackDrillPassed || !snapshot.PairedBackupApproved {
			block("contract_recovery_evidence_missing", "contract requires retained recovery evidence")
		}
		requireCanaryEvidence(snapshot, block)
	}

	if phase != PhaseExpand && snapshot.LastKnownGoodPhase == "" {
		warn("last_known_good_missing", "record a last-known-good phase before advancing rollout")
	}
	if phase != PhaseExpand && !snapshot.ApprovalRecorded {
		block("approval_missing", "phase advancement requires explicit approval evidence")
	}
	return finalizeGate(decision), nil
}

func requireLegacyAuthority(snapshot GateSnapshot, block func(string, string)) {
	if snapshot.SourceOfTruth != "legacy_users" || !snapshot.LegacyWritesEnabled || !containsOnly(snapshot.AllowedWriters, "legacy_users") {
		block("legacy_authority_changed_early", "backfill/shadow phases must keep legacy users as the sole writer and source of truth")
	}
	if snapshot.AuthoritativeReads || snapshot.IdentityMutations {
		block("enterprise_authority_enabled_early", "enterprise identity authority cannot be enabled during legacy-authoritative rollout")
	}
}

func requireCanaryEvidence(snapshot GateSnapshot, block func(string, string)) {
	if !snapshot.BackfillCompleted || !snapshot.ShadowComparisonComplete || snapshot.DriftCount != 0 || snapshot.SourceCount != snapshot.ProjectedCount {
		block("canary_projection_not_clean", "canary requires completed backfill and shadow comparison with zero drift")
	}
	if snapshot.ObservationMinutes == 0 || !snapshot.MetricsRecorded || snapshot.AbortThresholdBPS == 0 || snapshot.SessionCount == 0 {
		block("canary_observation_missing", "canary requires a measured observation window, metrics, sample, and operator-supplied abort threshold")
	}
}

func invalidGateCounts(snapshot GateSnapshot) bool {
	values := []int{snapshot.SourceCount, snapshot.ProjectedCount, snapshot.DriftCount, snapshot.CorruptCredentialCount, snapshot.DuplicateCredentialCount, snapshot.BootstrapMembershipCount, snapshot.DenialCount, snapshot.ErrorCount, snapshot.SessionCount, snapshot.ObservationMinutes, snapshot.AbortThresholdBPS}
	for _, value := range values {
		if value < 0 {
			return true
		}
	}
	return snapshot.AbortThresholdBPS > 10000
}

func allowedSourceOfTruth(value string) bool {
	return value == "legacy_users" || value == "shadow_compare" || value == "enterprise_identity"
}

func validWriterSet(writers []string) bool {
	seen := map[string]bool{}
	for _, writer := range writers {
		writer = strings.TrimSpace(writer)
		if writer != "legacy_users" && writer != "legacy_dual_write" && writer != "enterprise_identity" {
			return false
		}
		if seen[writer] {
			return false
		}
		seen[writer] = true
	}
	return len(seen) > 0
}

func containsOnly(values []string, expected string) bool {
	return len(values) == 1 && strings.TrimSpace(values[0]) == expected
}

func finalizeGate(decision GateDecision) GateDecision {
	sort.Slice(decision.Blockers, func(i, j int) bool { return decision.Blockers[i].Code < decision.Blockers[j].Code })
	sort.Slice(decision.Warnings, func(i, j int) bool { return decision.Warnings[i].Code < decision.Warnings[j].Code })
	decision.Allowed = len(decision.Blockers) == 0
	return decision
}
