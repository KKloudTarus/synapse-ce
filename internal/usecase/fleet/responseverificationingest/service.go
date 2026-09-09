// Package responseverificationingest authenticates and persists purpose-signed response observations.
package responseverificationingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type signingKeyResolver interface {
	ResolveSigningKey(ctx context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error)
}

type observationOrderStore interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*workorder.WorkOrder, error)
}

type Result struct {
	ReportID shared.ID
}

type Service struct {
	observations ports.ResponseVerificationAuditStore
	receipts     ports.ResponseTargetEvidenceReceiptStore
	responses    ports.ResponseStore
	orders       observationOrderStore
	observers    ports.ResponseObservationTargetResolver
	keys         signingKeyResolver
	audit        ports.IdempotentAuditLogger
	clock        ports.Clock
}

func NewService(observations ports.ResponseVerificationAuditStore, receipts ports.ResponseTargetEvidenceReceiptStore, responses ports.ResponseStore, orders observationOrderStore, observers ports.ResponseObservationTargetResolver, keys signingKeyResolver, audit ports.IdempotentAuditLogger, clock ports.Clock) (*Service, error) {
	if observations == nil || receipts == nil || responses == nil || orders == nil || observers == nil || keys == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: response-verification ingest is missing a dependency", shared.ErrValidation)
	}
	return &Service{observations: observations, receipts: receipts, responses: responses, orders: orders, observers: observers, keys: keys, audit: audit, clock: clock}, nil
}

// Ingest admits one signed observer report only when transport identity, a live server-owned observer
// target binding, key purpose, durable attempt state, target, action digest, direction, and post-command
// challenge agree.
func (s *Service) Ingest(ctx context.Context, authAgentID shared.ID, report fleetagent.ResponseVerificationReport) (Result, error) {
	now := s.clock.Now().UTC().Truncate(time.Microsecond)
	refuse := func(reason string, cause error) (Result, error) {
		if err := s.reject(ctx, authAgentID, report, reason, now); err != nil {
			return Result{}, err
		}
		return Result{}, cause
	}
	if err := report.Validate(); err != nil {
		return refuse("invalid_report", err)
	}
	if authAgentID.IsZero() || report.AgentID != authAgentID {
		return refuse("identity_mismatch", fmt.Errorf("%w: response observer is not the authenticated agent", shared.ErrForbidden))
	}
	if report.HostID != authAgentID {
		return refuse("host_mismatch", fmt.Errorf("%w: response observer host is not the authenticated agent host", shared.ErrForbidden))
	}
	if report.AgentSessionID != fleetagent.CanonicalSessionID(authAgentID) {
		return refuse("session_mismatch", fmt.Errorf("%w: response observer session is not the authenticated enrollment session", shared.ErrForbidden))
	}
	assetID, err := s.observers.ResolveResponseObservationAsset(ctx, authAgentID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: response-observer target binding is not established", shared.ErrForbidden)
		}
		return refuse("observer_binding_missing", err)
	}
	if assetID.IsZero() || report.AssetID != assetID {
		return refuse("asset_mismatch", fmt.Errorf("%w: response observer asset does not match its live server-authorized target binding", shared.ErrForbidden))
	}
	if report.ObservedAt.After(now) {
		return refuse("future_observation", fmt.Errorf("%w: response observation is later than server receipt time", shared.ErrForbidden))
	}
	key, err := s.keys.ResolveSigningKey(ctx, report.AgentID, report.KeyID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return refuse("key_unresolved", fmt.Errorf("%w: response observer signing key %q is not registered", shared.ErrForbidden, report.KeyID))
		}
		return Result{}, fmt.Errorf("resolve response observer signing key %q: %w", report.KeyID, err)
	}
	// The signature binds the observer's event-time key lifecycle, while admission also
	// requires that the resolved key remains trusted at this server-owned receipt time.
	if err := fleetagent.VerifyResponseVerificationWithKey(key, report.ObservedAt, report); err != nil {
		return refuse("signature_invalid", err)
	}
	if err := key.UsableAt(now); err != nil {
		return refuse("key_not_currently_usable", err)
	}
	record, found, err := s.responses.Get(ctx, report.ActionID)
	if err != nil {
		return Result{}, fmt.Errorf("read response action for verification: %w", err)
	}
	if !found {
		return refuse("action_missing", fmt.Errorf("%w: response action %s", shared.ErrNotFound, report.ActionID))
	}
	digest, err := rdom.CanonicalDigest(record.Action)
	if err != nil {
		return refuse("stored_action_invalid", err)
	}
	if record.EngagementID != report.EngagementID || digest != report.ActionDigest {
		return refuse("action_mismatch", fmt.Errorf("%w: response observation is not bound to the stored action", shared.ErrForbidden))
	}
	attempt, found, err := s.responses.GetAttempt(ctx, strings.TrimSpace(report.AttemptKey))
	if err != nil {
		return Result{}, fmt.Errorf("read response attempt for verification: %w", err)
	}
	if !found {
		return refuse("attempt_missing", fmt.Errorf("%w: response attempt %s", shared.ErrNotFound, report.AttemptKey))
	}
	existing, alreadyAccepted, err := s.observations.GetResponseVerification(ctx, report.AttemptKey)
	if err != nil {
		return Result{}, fmt.Errorf("read accepted response observation: %w", err)
	}
	if attempt.ActionID != report.ActionID || attempt.Target != report.Target || attempt.IsReversal != report.Reversal ||
		attempt.VerificationChallenge != report.VerificationChallenge || !report.ObservedAt.After(attempt.At) ||
		attempt.DeadlineAt.IsZero() || !report.ObservedAt.Before(attempt.DeadlineAt) || !now.Before(attempt.DeadlineAt) {
		return refuse("attempt_mismatch", fmt.Errorf("%w: response observation is not bound to the post-command attempt", shared.ErrForbidden))
	}
	if !eligibleAttemptState(attempt, alreadyAccepted) {
		return refuse("attempt_state", fmt.Errorf("%w: response attempt %s is not accepting verification in state %s", shared.ErrConflict, report.AttemptKey, attempt.State))
	}
	if attempt.ExecutorAgentID.IsZero() {
		return refuse("executor_identity_missing", fmt.Errorf("%w: response attempt has no trusted executor agent identity", shared.ErrForbidden))
	}
	if strings.EqualFold(strings.TrimSpace(attempt.ExecutorID), report.ObserverIdentity()) || attempt.ExecutorAgentID == report.AgentID {
		return refuse("self_verification", fmt.Errorf("%w: response executor cannot submit its own verification observation", shared.ErrForbidden))
	}
	order, err := s.orders.GetByID(ctx, record.TenantID, report.ReportID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return refuse("observation_order_missing", fmt.Errorf("%w: response observation work order %s", shared.ErrForbidden, report.ReportID))
		}
		return Result{}, fmt.Errorf("read response observation work order: %w", err)
	}
	if err := validateObservationOrder(order, report, now, attempt.DeadlineAt); err != nil {
		return refuse("observation_order_mismatch", err)
	}
	if s.receipts == nil {
		return refuse("receipt_store_missing", fmt.Errorf("%w: target evidence receipt store is unavailable", shared.ErrForbidden))
	}
	receipt, receiptFound, err := s.receipts.GetResponseTargetEvidenceReceipt(ctx, report.AttemptKey)
	if err != nil {
		return Result{}, fmt.Errorf("read target evidence receipt: %w", err)
	}
	if !receiptFound || receipt.ReceiptID != report.ReceiptID || receipt.Digest != report.ReceiptDigest || receipt.TenantID != record.TenantID || receipt.EngagementID != report.EngagementID || receipt.ActionID != report.ActionID || receipt.ActionDigest != report.ActionDigest || receipt.Target != report.Target || receipt.Reversal != report.Reversal {
		return refuse("receipt_mismatch", fmt.Errorf("%w: response report does not bind the stored target evidence receipt", shared.ErrForbidden))
	}

	signedContent := sha256.Sum256(fleetagent.ResponseVerificationMessage(report))
	observation := ports.AcceptedResponseVerification{
		Report: report, ObserverID: report.ObserverIdentity(), SignedContentDigest: hex.EncodeToString(signedContent[:]), RecordedAt: now,
	}
	if alreadyAccepted && !ports.SameAcceptedResponseVerification(existing, observation) {
		return refuse("attempt_equivocation", fmt.Errorf("%w: response attempt already has different signed verification content", shared.ErrConflict))
	}
	intentID := "fleet.response_verification.ingest:" + report.ReportID.String()
	intent := ports.FleetAuditIntent{ID: intentID, Entry: ports.AuditEntry{
		Actor: observation.ObserverID, Action: "fleet.response_verification.ingest", Target: report.ReportID.String(), At: now,
		Metadata: map[string]string{
			"idempotency_key": intentID, "agent_id": authAgentID.String(), "asset_id": assetID.String(),
			"action_id": report.ActionID.String(), "attempt_key": report.AttemptKey,
		},
	}}
	intent, err = s.observations.AppendResponseVerificationWithAudit(ctx, observation, intent)
	if err != nil {
		if errors.Is(err, shared.ErrConflict) {
			return refuse("report_equivocation", err)
		}
		return Result{}, fmt.Errorf("persist response-verification observation: %w", err)
	}
	if err := s.audit.RecordOnce(ctx, intent.Entry); err != nil {
		return Result{}, fmt.Errorf("audit response-verification admission: %w", err)
	}
	if err := s.observations.AcknowledgeFleetAudit(ctx, intent.ID); err != nil {
		return Result{}, fmt.Errorf("acknowledge response-verification admission audit: %w", err)
	}
	return Result{ReportID: report.ReportID}, nil
}

func validateObservationOrder(order *workorder.WorkOrder, report fleetagent.ResponseVerificationReport, now, attemptDeadline time.Time) error {
	if order == nil || order.ResponseObserve == nil || order.ID != report.ReportID || order.State != workorder.StateRunning ||
		order.Capability != workorder.CapabilityResponseObserve || order.AgentID != report.AgentID ||
		order.LeaseID == "" || !now.Before(order.LeaseUntil) || !now.Before(order.NotAfter) ||
		attemptDeadline.IsZero() || order.NotAfter.After(attemptDeadline) {
		return fmt.Errorf("%w: response verification has no live addressed observation work order", shared.ErrForbidden)
	}
	if err := order.ValidateResponseBinding(); err != nil {
		return fmt.Errorf("%w: invalid response observation work order: %v", shared.ErrForbidden, err)
	}
	request := order.ResponseObserve
	if request.RequestID != report.ReportID || request.ObserverAgentID != report.AgentID || request.AssetID != report.AssetID ||
		request.EngagementID != report.EngagementID || request.ActionID != report.ActionID || request.ActionDigest != report.ActionDigest ||
		request.AttemptKey != report.AttemptKey || request.VerificationChallenge != report.VerificationChallenge || request.ReceiptID != report.ReceiptID || request.ReceiptDigest != report.ReceiptDigest || request.Target != report.Target ||
		request.Reversal != report.Reversal || report.ObservedAt.Before(request.IssuedAt) || !report.ObservedAt.After(request.AttemptedAt) ||
		report.ObservedAt.After(request.NotAfter) || request.NotAfter.After(attemptDeadline) {
		return fmt.Errorf("%w: response verification disagrees with its observation work order", shared.ErrForbidden)
	}
	return nil
}

func eligibleAttemptState(attempt responsesaga.ResponseAttempt, alreadyAccepted bool) bool {
	if attempt.IsReversal {
		if attempt.State == responsesaga.StateRollbackVerifying || attempt.State == responsesaga.StateRollbackUnknown {
			return true
		}
		return alreadyAccepted && (attempt.State == responsesaga.StateRolledBack || attempt.State == responsesaga.StateRollbackFailed)
	}
	if attempt.State == responsesaga.StateVerifying || attempt.State == responsesaga.StateOutcomeUnknown {
		return true
	}
	if !alreadyAccepted {
		return false
	}
	switch attempt.State {
	case responsesaga.StateVerifiedSucceeded, responsesaga.StateVerificationFailed,
		responsesaga.StateVerificationUnknown, responsesaga.StateTimedOut, responsesaga.StateRollbackRequested:
		return true
	default:
		return false
	}
}

func (s *Service) reject(ctx context.Context, actor shared.ID, report fleetagent.ResponseVerificationReport, reason string, at time.Time) error {
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: "fleet.response_verification.reject", Target: report.ReportID.String(), At: at,
		Metadata: map[string]string{
			"agent_id": report.AgentID.String(), "asset_id": report.AssetID.String(), "action_id": report.ActionID.String(), "reason": reason,
		},
	}); err != nil {
		return fmt.Errorf("%w: audit response-verification rejection: %v", shared.ErrSaturated, err)
	}
	return nil
}
