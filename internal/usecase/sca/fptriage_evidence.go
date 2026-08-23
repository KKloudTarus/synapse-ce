package sca

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	aiPolicyEvidenceSealFailed       = "evidence_seal_failed"
	aiEvidenceSealFailureAuditAction = "sca.ai_triage.evidence_seal_failed"
	aiEvidenceSealFailureMetricName  = "synapse_sca_ai_triage_evidence_seal_failures_total"
	aiEvidenceSealFailureWarning     = "AI gate exemption revoked because scan evidence could not be sealed; affected findings remain gating. Retry after the evidence ledger recovers."
	aiEvidenceFailureAuditTimeout    = 5 * time.Second
)

// AIEvidenceSealError is returned when an evidence failure revoked AI gate authority.
// The scan remains failed before result persistence; callers may retry after the ledger recovers.
type AIEvidenceSealError struct {
	RevokedExemptions int
	Err               error
}

func (e *AIEvidenceSealError) Error() string {
	if e == nil {
		return "AI evidence seal failure"
	}
	return fmt.Sprintf("AI gate exemption evidence failed closed after revoking %d exemption(s); findings remain gating and the scan can be retried: %v", e.RevokedExemptions, e.Err)
}

func (e *AIEvidenceSealError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// sealEvidenceFailClosed preserves the #386 boundary: any configured evidence failure still
// fails the scan before run, finding, review, or result persistence. #391 adds the narrower
// authority cleanup before that error escapes. When an active AI exemption cannot be sealed,
// clear every positive GateExempt bit in-memory, mark the finding for review, emit a stable
// operator-visible metric event plus warning, and append an audit event. Do not retry the evidence
// write here: Evidence.Service already owns the bounded chain-head retry, while a generic Append
// error can be commit-ambiguous. The operator retries the whole scan after the ledger recovers.
func (s *Service) sealEvidenceFailClosed(ctx context.Context, actor string, engagementID shared.ID, now time.Time, result *ScanResult) (shared.ID, error) {
	return s.sealEvidenceFailClosedWithID(ctx, actor, engagementID, now, result, "")
}

func (s *Service) sealEvidenceFailClosedWithID(ctx context.Context, actor string, engagementID shared.ID, now time.Time, result *ScanResult, evidenceID shared.ID) (shared.ID, error) {
	ref, sealErr := s.sealEvidence(ctx, actor, engagementID, now, result, evidenceID)
	if sealErr == nil {
		return ref, nil
	}

	revoked := revokeAIGateExemptions(result)
	if revoked == 0 {
		return "", sealErr
	}

	recordAIEvidenceSealFailureAccounting(result, revoked)
	appendSourceWarningOnce(result, aiEvidenceSealFailureWarning)
	s.emitAIEvidenceSealFailureMetric(ctx, engagementID, revoked)

	if s.audit == nil {
		return "", &AIEvidenceSealError{
			RevokedExemptions: revoked,
			Err: errors.Join(
				sealErr,
				fmt.Errorf("audit AI evidence revocation: %w", shared.ErrValidation),
			),
		}
	}
	auditAt := now
	if s.clock != nil {
		auditAt = s.clock.Now()
	}
	// A request timeout can be the reason the evidence path failed. The failure audit is
	// compensating state and must get its own bounded chance to persist after cancellation,
	// while retaining request values such as tenant/actor context.
	auditCtx, cancelAudit := context.WithTimeout(context.WithoutCancel(ctx), aiEvidenceFailureAuditTimeout)
	auditErr := s.audit.Record(auditCtx, ports.AuditEntry{
		Actor:  actor,
		Action: aiEvidenceSealFailureAuditAction,
		Target: engagementID.String(),
		Metadata: map[string]string{
			"engagement":             engagementID.String(),
			"evidence_seal_failures": "1",
			"revoked_exemptions":     strconv.Itoa(revoked),
		},
		At: auditAt,
	})
	cancelAudit()
	if auditErr != nil {
		return "", &AIEvidenceSealError{
			RevokedExemptions: revoked,
			Err: errors.Join(
				sealErr,
				fmt.Errorf("audit AI evidence revocation: %w", auditErr),
			),
		}
	}

	return "", &AIEvidenceSealError{RevokedExemptions: revoked, Err: sealErr}
}

// emitAIEvidenceSealFailureMetric emits a stable structured counter event before the failed
// ScanResult is discarded. P1.5 owns the broader telemetry/exporter surface; this narrow event is
// deliberately log-derived so #391 does not introduce a second metrics stack. It is logged at ERROR
// because every supported log configuration retains errors, including an operator-selected error-only
// threshold. WithoutCancel keeps a request timeout from suppressing the compensating observation for the
// failure it caused.
func (s *Service) emitAIEvidenceSealFailureMetric(ctx context.Context, engagementID shared.ID, revoked int) {
	if revoked <= 0 {
		return
	}
	s.logger().LogAttrs(
		context.WithoutCancel(ctx),
		slog.LevelError,
		"AI gate exemption revoked after evidence seal failure",
		slog.String("metric", aiEvidenceSealFailureMetricName),
		slog.String("metric_kind", "counter"),
		slog.Int("metric_value", 1),
		slog.String("engagement", engagementID.String()),
		slog.Int("revoked_exemptions", revoked),
	)
}

// revokeAIGateExemptions clears every stored GateExempt bit, including malformed/forged DTOs that
// would already fail server-side revalidation. The evidence precondition failed globally, so retaining
// any positive authority bit would be misleading even when another guard currently ignores it.
func revokeAIGateExemptions(result *ScanResult) int {
	if result == nil {
		return 0
	}
	revoked := 0
	for i := range result.AITriage {
		critique := &result.AITriage[i]
		if !critique.GateExempt {
			continue
		}
		critique.GateExempt = false
		critique.ReviewRequired = true
		critique.PolicyReason = aiPolicyEvidenceSealFailed
		revoked++
	}
	return revoked
}

func recordAIEvidenceSealFailureAccounting(result *ScanResult, revoked int) {
	if result == nil || revoked <= 0 {
		return
	}
	if result.AITriageBudget == nil {
		result.AITriageBudget = &AITriageBudget{}
	}
	result.AITriageBudget.EvidenceSealFailures++
	result.AITriageBudget.EvidenceRevokedExemptions += revoked
}

func appendSourceWarningOnce(result *ScanResult, warning string) {
	if result == nil || strings.TrimSpace(warning) == "" {
		return
	}
	for _, existing := range result.SourceWarnings {
		if existing == warning {
			return
		}
	}
	result.SourceWarnings = append(result.SourceWarnings, warning)
}
