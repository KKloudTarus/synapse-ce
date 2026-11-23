package response

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

func (s *Service) record(tenant, eng shared.ID, action rdom.Action, target engagement.Target, fingerprint responsesaga.TargetFingerprint, submitter string, state State, approver string, evID shared.ID) Record {
	now := s.clock.Now().UTC()
	r := Record{
		ID: action.ID, TenantID: tenant, EngagementID: eng, Action: action,
		AuthorizationTarget: target, TargetFingerprint: fingerprint,
		SubmittedBy: submitter, State: state, ApprovedBy: approver, ApprovalEvidenceID: evID, UpdatedAt: now,
	}
	if state == StateApplied {
		r.AppliedAt = now // only a genuinely applied action carries an apply time
	}
	return r
}

func newAttempt(action rdom.Action, target responsesaga.TargetFingerprint, reversal bool, state responsesaga.SagaState, haltGeneration int64, decidedBy string, at time.Time) responsesaga.ResponseAttempt {
	return responsesaga.ResponseAttempt{
		ActionID: action.ID, Attempt: 1, IdempotencyKey: responseAttemptKey(action, reversal),
		Target: target, IsReversal: reversal, State: state, HaltGeneration: haltGeneration, DecidedBy: decidedBy, At: at,
	}
}

func (s *Service) newAttempt(action rdom.Action, target responsesaga.TargetFingerprint, reversal bool, state responsesaga.SagaState, haltGeneration int64, decidedBy string, at time.Time) responsesaga.ResponseAttempt {
	attempt := newAttempt(action, target, reversal, state, haltGeneration, decidedBy, at)
	attempt.DeadlineAt = at.Add(s.verificationTimeout)
	return attempt
}

func responseAttemptKey(action rdom.Action, reversal bool) string {
	payload, _ := json.Marshal(struct {
		Action   rdom.Action
		Reversal bool
	}{Action: action, Reversal: reversal})
	digest := sha256.Sum256(payload)
	return fmt.Sprintf("response-attempt:v1:%x", digest[:])
}

func responseActionDigest(action rdom.Action) string {
	digest, _ := rdom.CanonicalDigest(action)
	return digest
}

func setVerificationChallenge(attempt *responsesaga.ResponseAttempt) error {
	if validVerificationChallenge(attempt.VerificationChallenge) {
		return nil
	}
	random := make([]byte, sha256.Size)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generate post-command verification challenge: %w", err)
	}
	attempt.VerificationChallenge = hex.EncodeToString(random)
	return nil
}

func validVerificationChallenge(value string) bool {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	return err == nil && len(decoded) == sha256.Size
}

func sameAction(a, b rdom.Action) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func cloneAction(action rdom.Action) rdom.Action {
	action.Argv = slices.Clone(action.Argv)
	action.Reversal.Argv = slices.Clone(action.Reversal.Argv)
	return action
}

func sameProposedAction(a, b agent.ProposedAction) bool {
	return a.ID == b.ID && a.SessionID == b.SessionID && a.EngagementID == b.EngagementID &&
		a.Tool == b.Tool && a.Action == b.Action && a.Target == b.Target && a.Risk == b.Risk &&
		a.Rationale == b.Rationale && a.ProposedAt.Equal(b.ProposedAt) &&
		slices.Equal(a.Argv, b.Argv) && slices.Equal(a.EgressPreview, b.EgressPreview)
}

func responseApprovalMatchesRecord(proposal agent.ProposedAction, rec Record, reversal bool) bool {
	proposalID := rec.ID
	kind := string(rec.Action.Kind)
	argv := rec.Action.Argv
	rationale := "defensive response: " + kind
	if reversal {
		proposalID = shared.ID("revert:" + rec.ID.String())
		kind = string(rec.Action.Reversal.Kind)
		argv = rec.Action.Reversal.Argv
		rationale = "reverse response: " + rec.Action.Reversal.Description
	}
	tool := "response." + kind
	return proposal.ID == proposalID && proposal.SessionID == shared.ID("response:"+rec.ID.String()) &&
		proposal.EngagementID == rec.EngagementID && proposal.Tool == tool && proposal.Action == tool &&
		proposal.Target == rec.AuthorizationTarget && proposal.Risk == agent.RiskIntrusive &&
		proposal.Rationale == rationale && slices.Equal(proposal.Argv, argv) && len(proposal.EgressPreview) == 0
}

func (s *Service) recordExecutionIntent(ctx context.Context, actor string, action rdom.Action, attempt responsesaga.ResponseAttempt, decidedBy string) error {
	operation := "apply"
	if attempt.IsReversal {
		operation = "revert"
	}
	return s.audit.RecordOnce(ctx, ports.AuditEntry{
		Actor: actor, Action: "response.execution_intent", Target: action.ID.String(), At: attempt.At,
		Metadata: map[string]string{
			"decided_by": decidedBy, "idempotency_key": attempt.IdempotencyKey + ":intent",
			"operation": operation, "target_fingerprint_kind": string(attempt.Target.Kind),
		},
	})
}

func (s *Service) recordOutcome(ctx context.Context, event, actor string, action rdom.Action, attempt responsesaga.ResponseAttempt, meta map[string]string) error {
	intent := responseOutcomeAuditIntent(event, actor, action, attempt, meta)
	outcome, notify := responseNotificationOutcome(event, attempt.State)
	if s.notifications == nil {
		committed, err := s.store.EnqueueResponseAudit(ctx, intent)
		if err != nil {
			return err
		}
		return s.deliverResponseAudit(ctx, committed)
	}
	record, found, err := s.store.Get(ctx, action.ID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: response %s for outcome notification", shared.ErrNotFound, action.ID)
	}
	var committed ports.ResponseAuditIntent
	err = s.notificationTx.Run(ctx, record.TenantID, func(txCtx context.Context) error {
		var enqueueErr error
		committed, enqueueErr = s.store.EnqueueResponseAudit(txCtx, intent)
		if enqueueErr != nil {
			return enqueueErr
		}
		if !notify {
			return nil
		}
		return s.appendResponseFinished(txCtx, record, outcome, actor)
	})
	if err != nil {
		return err
	}
	return s.deliverResponseAudit(ctx, committed)
}

func responseOutcomeAuditIntent(event, actor string, action rdom.Action, attempt responsesaga.ResponseAttempt, meta map[string]string) ports.ResponseAuditIntent {
	metadata := make(map[string]string, len(meta)+3)
	for key, value := range meta {
		metadata[key] = value
	}
	metadata["idempotency_key"] = attempt.IdempotencyKey + ":" + event
	metadata["kind"] = string(action.Kind)
	metadata["target"] = action.Target.String()
	metadata["executor_id"] = attempt.ExecutorID
	if attempt.VerifierID != "" && event != "response.applied" {
		metadata["verifier_id"] = attempt.VerifierID
		metadata["verification_evidence_id"] = attempt.VerificationEvidenceID.String()
	}
	return responseAuditIntent(attempt.IdempotencyKey+":"+event, actor, event, action.ID.String(), attempt.At, metadata)
}

func (s *Service) commitAttemptOutcome(ctx context.Context, attempt responsesaga.ResponseAttempt, from, to responsesaga.SagaState, event, actor string, action rdom.Action, meta map[string]string) (responsesaga.ResponseAttempt, ports.ResponseAuditIntent, error) {
	attempt.State = to
	intent := responseOutcomeAuditIntent(event, actor, action, attempt, meta)
	outcome, notify := responseNotificationOutcome(event, attempt.State)
	if s.notifications == nil {
		stored, transitioned, committed, err := s.store.TransitionAttemptWithAudit(ctx, attempt, from, intent)
		if err != nil {
			return responsesaga.ResponseAttempt{}, ports.ResponseAuditIntent{}, err
		}
		if !transitioned {
			return responsesaga.ResponseAttempt{}, ports.ResponseAuditIntent{}, fmt.Errorf("%w: response attempt %s changed concurrently from %s to %s", shared.ErrConflict, attempt.IdempotencyKey, from, stored.State)
		}
		return stored, committed, nil
	}
	record, found, err := s.store.Get(ctx, action.ID)
	if err != nil {
		return responsesaga.ResponseAttempt{}, ports.ResponseAuditIntent{}, err
	}
	if !found {
		return responsesaga.ResponseAttempt{}, ports.ResponseAuditIntent{}, fmt.Errorf("%w: response %s for attempt notification", shared.ErrNotFound, action.ID)
	}
	var (
		stored       responsesaga.ResponseAttempt
		transitioned bool
		committed    ports.ResponseAuditIntent
	)
	err = s.notificationTx.Run(ctx, record.TenantID, func(txCtx context.Context) error {
		var transitionErr error
		stored, transitioned, committed, transitionErr = s.store.TransitionAttemptWithAudit(txCtx, attempt, from, intent)
		if transitionErr != nil || !transitioned {
			return transitionErr
		}
		if !notify {
			return nil
		}
		return s.appendResponseFinished(txCtx, record, outcome, actor)
	})
	if err != nil {
		return responsesaga.ResponseAttempt{}, ports.ResponseAuditIntent{}, err
	}
	if !transitioned {
		return responsesaga.ResponseAttempt{}, ports.ResponseAuditIntent{}, fmt.Errorf("%w: response attempt %s changed concurrently from %s to %s", shared.ErrConflict, attempt.IdempotencyKey, from, stored.State)
	}
	return stored, committed, nil
}

// responseNotificationOutcome translates only settled response outcomes to the
// small terminal vocabulary exposed to notification subscribers. Journal entries
// still record ambiguous and intermediate events, but those events must not claim
// that a response finished.
func responseNotificationOutcome(event string, state responsesaga.SagaState) (string, bool) {
	switch event {
	case "response.applied":
		return "applied", true
	case "response.verified", "response.verification_succeeded":
		return "verified", true
	case "response.reverted":
		return "reverted", true
	case "response.attempt_halted":
		// A halt only has a terminal meaning when the attempt was stopped before
		// dispatch, or its rollback was stopped before dispatch. Executing and
		// post-effect states are retained in the audit journal for reconciliation.
		switch state {
		case responsesaga.StateCommandFailed, responsesaga.StateRollbackFailed:
			return "halted", true
		}
	case "response.execution_failed", "response.verification_failed", "response.rollback_verification_failed":
		return "failed", true
	case "response.attempt_terminal":
		switch state {
		case responsesaga.StateCommandFailed, responsesaga.StateRollbackFailed:
			return "failed", true
		}
	}
	return "", false
}

func (s *Service) put(ctx context.Context, r Record) error { return s.store.Put(ctx, r) }

func (s *Service) transition(ctx context.Context, r Record, from State) error {
	transitioned, err := s.store.Transition(ctx, r, from)
	if err != nil {
		return err
	}
	if !transitioned {
		return fmt.Errorf("%w: response %s state changed concurrently from %s", shared.ErrConflict, r.ID, from)
	}
	return nil
}

func (s *Service) transitionAttempt(ctx context.Context, attempt responsesaga.ResponseAttempt, from, to responsesaga.SagaState) (responsesaga.ResponseAttempt, error) {
	attempt.State = to
	stored, transitioned, err := s.store.TransitionAttempt(ctx, attempt, from)
	if err != nil {
		return responsesaga.ResponseAttempt{}, err
	}
	if !transitioned {
		return responsesaga.ResponseAttempt{}, fmt.Errorf("%w: response attempt %s changed concurrently from %s to %s", shared.ErrConflict, attempt.IdempotencyKey, from, stored.State)
	}
	return stored, nil
}

func responseFlightKey(tenantID, actionID shared.ID, reversal bool) string {
	direction := "apply"
	if reversal {
		direction = "revert"
	}
	return tenantID.String() + "/" + actionID.String() + "/" + direction
}

// radiusExceeded reports whether the observed effect is broader than declared (state_changing beyond a
// declared read_only). Mirrors the exploitation rule.
func radiusExceeded(declared, observed offensivepolicy.Radius) bool {
	return declared == offensivepolicy.RadiusReadOnly && observed == offensivepolicy.RadiusStateChanging
}

func attemptOutcomeInRadius(declared offensivepolicy.Radius, attempt responsesaga.ResponseAttempt) bool {
	return attempt.ObservedRadius.Valid() && !radiusExceeded(declared, attempt.ObservedRadius) && attempt.AffectedCount <= 1
}

// isMachine reports whether an approver identity is non-human. It normalises (trim + lower-case) before
// matching the machine-prefix families so a leading space or a capitalised "Agent:" cannot slip a
// machine identity past the "a model can never approve" check. (The stronger guard — requiring a
// resolved human Principal — lands with the HTTP layer; this is the domain-side backstop.)
func isMachine(actor string) bool {
	return shared.IsMachineActor(actor)
}

func isPending(err error) bool { return errors.Is(err, safety.ErrPendingApproval) }
