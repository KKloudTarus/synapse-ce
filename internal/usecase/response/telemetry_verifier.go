package response

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type verificationEvidenceSealer interface {
	SealOnce(ctx context.Context, engagementID shared.ID, kind, idempotencyKey string, content []byte, actor string) (evdom.Evidence, error)
}

// TelemetryEffectVerifier uses an observer's signed readiness report only as a causal trigger. It derives
// the outcome from independently accepted endpoint timeline and materialized coverage records.
type TelemetryEffectVerifier struct {
	identity     string
	observations ports.ResponseVerificationStore
	receipts     ports.ResponseTargetEvidenceReceiptStore
	timeline     ports.EndpointTimelineStore
	coverage     ports.CoverageWindowStore
	evidence     verificationEvidenceSealer
	dispatcher   ObservationDispatcher
}

// ObservationDispatcher remains an alias for compatibility; the dispatcher port lives in ports.
type ObservationDispatcher = ports.ResponseObservationDispatcher

var _ EffectVerifier = (*TelemetryEffectVerifier)(nil)

func NewTelemetryEffectVerifier(identity string, observations ports.ResponseVerificationStore, receipts ports.ResponseTargetEvidenceReceiptStore, timeline ports.EndpointTimelineStore, coverage ports.CoverageWindowStore, evidence verificationEvidenceSealer) (*TelemetryEffectVerifier, error) {
	identity = strings.TrimSpace(identity)
	if identity == "" || observations == nil || receipts == nil || timeline == nil || coverage == nil || evidence == nil {
		return nil, fmt.Errorf("%w: telemetry response verifier is missing an identity or dependency", shared.ErrValidation)
	}
	return &TelemetryEffectVerifier{
		identity: identity, observations: observations, receipts: receipts, timeline: timeline, coverage: coverage, evidence: evidence,
	}, nil
}

func (v *TelemetryEffectVerifier) Identity() string { return v.identity }

func (v *TelemetryEffectVerifier) SetObservationDispatcher(dispatcher ObservationDispatcher) {
	v.dispatcher = dispatcher
}

func (v *TelemetryEffectVerifier) Verify(ctx context.Context, req VerificationRequest) (VerificationReceipt, error) {
	observation, found, err := v.observations.GetResponseVerification(ctx, req.AttemptKey)
	if err != nil {
		return VerificationReceipt{}, fmt.Errorf("read response verification observation: %w", err)
	}
	if !found {
		if v.dispatcher != nil {
			if dispatchErr := v.dispatcher.EnsureObservation(ctx, req); dispatchErr != nil {
				return VerificationReceipt{Outcome: VerificationPending}, fmt.Errorf("dispatch response observer: %w", dispatchErr)
			}
		}
		return VerificationReceipt{Outcome: VerificationPending}, ErrVerificationPending
	}
	if err := observation.Validate(); err != nil {
		return VerificationReceipt{}, fmt.Errorf("validate accepted response verification: %w", err)
	}
	source := &VerificationSource{
		Report: observation.Report, RecordedAt: observation.RecordedAt, SignedContentDigest: observation.SignedContentDigest,
	}
	if err := source.validateBinding(req); err != nil {
		return VerificationReceipt{}, err
	}
	receipt, receiptFound, receiptErr := v.receipts.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey)
	if receiptErr != nil {
		return VerificationReceipt{}, fmt.Errorf("read target evidence receipt: %w", receiptErr)
	}
	if !receiptFound || receipt.ReceiptID != source.Report.ReceiptID || receipt.Digest != source.Report.ReceiptDigest || receipt.Validate() != nil {
		return VerificationReceipt{}, fmt.Errorf("%w: accepted report has no valid matching target evidence receipt", shared.ErrForbidden)
	}
	if receipt.TenantID != req.TenantID || receipt.EngagementID != req.EngagementID || receipt.ActionID != req.Action.ID || receipt.ActionDigest != responseActionDigest(req.Action) || receipt.VerificationChallenge != req.VerificationChallenge || receipt.Target != req.Target || receipt.Reversal != req.Reversal || receipt.AttemptKey != req.AttemptKey || !receipt.AttemptedAt.Equal(req.AttemptedAt.UTC()) || receipt.WindowUntil.After(req.DeadlineAt) {
		return VerificationReceipt{}, fmt.Errorf("%w: target evidence receipt is not bound to attempt", shared.ErrForbidden)
	}
	source.Receipt, source.Timeline, source.Coverage = receipt, receipt.Timeline, receipt.Coverage
	outcome := VerificationUnknown
	if receipt.TimelineComplete && receipt.CoverageComplete && !receipt.Saturated {
		outcome, err = deriveTelemetryVerification(req, receipt)
	}
	if err != nil {
		return VerificationReceipt{}, err
	}
	content, err := MarshalVerificationEvidence(req, outcome, v.identity, source)
	if err != nil {
		return VerificationReceipt{}, err
	}
	item, err := v.evidence.SealOnce(ctx, req.EngagementID, VerificationEvidenceKind, req.AttemptKey, content, v.identity)
	if err != nil {
		return VerificationReceipt{}, fmt.Errorf("seal response verification evidence: %w", err)
	}
	if item.ID.IsZero() || item.EngagementID != req.EngagementID || item.Kind != VerificationEvidenceKind ||
		!strings.EqualFold(strings.TrimSpace(item.CreatedBy), v.identity) {
		return VerificationReceipt{}, fmt.Errorf("%w: evidence service returned an unbound response verification record", shared.ErrForbidden)
	}
	return VerificationReceipt{Outcome: outcome, EvidenceID: item.ID, Source: source}, nil
}

func deriveTelemetryVerification(req VerificationRequest, receipt fleetagent.ResponseTargetEvidenceReceipt) (rdom.Verification, error) {
	if err := receipt.Validate(); err != nil {
		return VerificationUnknown, err
	}
	if receipt.SourceAgentID == req.ExecutorAgentID || strings.EqualFold("agent:"+receipt.SourceAgentID.String()+":response-observer", strings.TrimSpace(req.ExecutorID)) {
		return VerificationUnknown, fmt.Errorf("%w: target evidence receipt cannot originate from the response executor", shared.ErrForbidden)
	}
	if !receipt.TimelineComplete || !receipt.CoverageComplete || receipt.Saturated {
		return VerificationUnknown, nil
	}
	if !completeProcessCoverage(req, receipt) {
		return VerificationUnknown, nil
	}
	targetExited, targetRunning := false, false
	replacement := shared.ID("")
	for _, entry := range receipt.Timeline {
		if entry.TenantID != req.TenantID || entry.AssetID != req.Target.ProcessAssetID || entry.SourceAgentID != receipt.SourceAgentID || entry.SourceAgentSessionID != receipt.SourceAgentSessionID || entry.OccurredAt.Before(req.AttemptedAt) || entry.OccurredAt.After(receipt.WindowUntil) {
			return VerificationUnknown, fmt.Errorf("%w: receipt timeline contains unbound entry", shared.ErrForbidden)
		}
		if entry.EntityID == req.Target.ProcessEntityID {
			if entry.Kind == endpoint.TimelineProcessExit {
				targetExited = true
			}
			if entry.Kind == endpoint.TimelineProcessStart || entry.Kind == endpoint.TimelineProcessExec {
				targetRunning = true
			}
			continue
		}
		if req.Reversal && targetExited && (entry.Kind == endpoint.TimelineProcessStart || entry.Kind == endpoint.TimelineProcessExec) {
			if replacement.IsZero() {
				replacement = entry.EntityID
			} else if replacement != entry.EntityID {
				return VerificationUnknown, nil
			}
		}
	}
	if !req.Reversal {
		if targetExited && targetRunning {
			return VerificationUnknown, nil
		}
		if targetExited {
			return VerificationSucceeded, nil
		}
		if targetRunning {
			return VerificationFailed, nil
		}
		return VerificationUnknown, nil
	}
	if targetRunning {
		return VerificationFailed, nil
	}
	if targetExited && !replacement.IsZero() {
		return VerificationSucceeded, nil
	}
	return VerificationUnknown, nil
}

func completeProcessCoverage(req VerificationRequest, receipt fleetagent.ResponseTargetEvidenceReceipt) bool {
	cursor := req.AttemptedAt.UTC()
	latest := map[string]sensorstate.CoverageWindow{}
	for _, window := range receipt.Coverage {
		if err := window.Validate(); err != nil || window.AssetID != req.Target.ProcessAssetID || window.AgentID != receipt.SourceAgentID || window.HostID != receipt.SourceHostID {
			return false
		}
		key := window.Since.String() + "/" + window.Until.String()
		if current, ok := latest[key]; !ok || current.Revision < window.Revision {
			latest[key] = window
		}
	}
	ordered := make([]sensorstate.CoverageWindow, 0, len(latest))
	for _, w := range latest {
		ordered = append(ordered, w)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Since.Before(ordered[j].Since) })
	for _, window := range ordered {
		if window.Since.After(cursor) || !window.Until.After(cursor) || window.Vector.Process != 100 || window.SampledCount != 0 || window.TruncatedCount != 0 || window.DroppedCount != 0 || window.GapCount != 0 || window.BatchCount == 0 {
			continue
		}
		cursor = window.Until
		if !cursor.Before(receipt.WindowUntil) {
			return true
		}
	}
	return false
}
