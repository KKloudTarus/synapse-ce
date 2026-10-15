// Package approval is the Human-In-The-Loop gate for AI-proposed actions.
// A proposed action is auto-approved (per the engagement's ApprovalMode + the action's
// RiskClass), or enqueued for a human, or – if undecided past the timeout – failed CLOSED
// (denied). Every decision is recorded on the append-only audit log, attributed to the
// deciding human (or the system on a timeout). It does NOT execute anything: it only
// produces an ApprovalDecision the safety gate consumes.
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ResumeFunc re-drives a suspended session after its pending action was decided (here: timed
// out). The composition root supplies it (enqueue an orchestrator resume job) so the approval
// package does NOT import the orchestrator – avoiding the orchestrator→safety→approval cycle.
type ResumeFunc func(ctx context.Context, sessionID, actionID shared.ID) error

// Service runs the approval policy over a durable ApprovalStore.
type Service struct {
	store   ports.ApprovalStore
	audit   ports.AuditLogger
	clock   ports.Clock
	mode    agent.ApprovalMode
	timeout time.Duration
	resume  ResumeFunc // optional; set via SetResumeEnqueuer to re-drive on timeout
	// transactions makes a decision and its audit record one unit. Optional: the in-memory and
	// file stores have no transactions, and the Postgres composition roots set it.
	transactions   ports.TenantTransactionRunner
	notifications  ports.NotificationOutbox
	approvalOutbox ports.ApprovalNotificationOutbox
	lifecycleFacts ports.NotificationLifecycleFactsReader
	approverFacts  ports.NotificationApproverFactsReader
}

// SetTransactionRunner makes Decide atomic. Without it the decision commits first and the audit
// append is a separate transaction, so an audit failure returns an error to an operator whose
// approval has already taken effect: the interface reports failure, the agent proceeds, and the
// retry answers "already decided".
func (s *Service) SetTransactionRunner(transactions ports.TenantTransactionRunner) {
	s.transactions = transactions
}

// SetNotifications makes approval state, audit history and lifecycle source
// records one tenant-local unit. The facts readers snapshot mutable names and
// recipient identities before the transaction commits.
func (s *Service) SetNotifications(tx ports.TenantTransactionRunner, outbox ports.NotificationOutbox, lifecycle ports.NotificationLifecycleFactsReader, approvers ports.NotificationApproverFactsReader) error {
	if tx == nil || outbox == nil || lifecycle == nil || approvers == nil {
		return fmt.Errorf("%w: approval notification dependencies are required", shared.ErrValidation)
	}
	approvalOutbox, ok := outbox.(ports.ApprovalNotificationOutbox)
	if !ok {
		return fmt.Errorf("%w: approval notification outbox must capture recipient snapshots", shared.ErrValidation)
	}
	s.transactions, s.notifications, s.lifecycleFacts, s.approverFacts = tx, outbox, lifecycle, approvers
	s.approvalOutbox = approvalOutbox
	return nil
}

// SetResumeEnqueuer installs the callback used to re-drive a session after a timeout deny, so
// the suspended session resumes, sees the denial via the idempotent gate, and fails fast
// instead of hanging in awaiting_approval forever.
func (s *Service) SetResumeEnqueuer(f ResumeFunc) { s.resume = f }

// NewService validates its deps and returns the approval service. An unknown mode is left
// as-is (AutoApproves fails safe to manual); a non-positive timeout disables auto-expiry.
func NewService(store ports.ApprovalStore, audit ports.AuditLogger, clock ports.Clock, mode agent.ApprovalMode, timeout time.Duration) (*Service, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: approval service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, audit: audit, clock: clock, mode: mode, timeout: timeout}, nil
}

// Request returns the current decision for a proposed action. If it was already decided
// (resume path), that decision is returned. Otherwise: auto-approvable → approved + audited;
// else enqueued and returned PENDING (the orchestrator suspends; a human Decides).
func (s *Service) Request(ctx context.Context, p agent.ProposedAction) (agent.ApprovalDecision, error) {
	if s.notifications != nil {
		return s.requestWithNotifications(ctx, p)
	}
	if _, dec, err := s.store.Get(ctx, p.ID); err == nil {
		return dec, nil // action IDs are immutable idempotency keys, including pending requests
	} else if !errors.Is(err, shared.ErrNotFound) {
		return agent.ApprovalDecision{}, fmt.Errorf("load approval: %w", err)
	}
	if err := s.store.Enqueue(ctx, p); err != nil {
		return agent.ApprovalDecision{}, fmt.Errorf("enqueue approval: %w", err)
	}
	if s.mode.AutoApproves(p.Risk) {
		dec := agent.ApprovalDecision{
			ActionID: p.ID, State: agent.ApprovalApproved, DecidedBy: "auto",
			Reason: fmt.Sprintf("auto-approved (mode %s, risk %s)", s.mode, p.Risk), DecidedAt: s.clock.Now(),
		}
		if err := s.store.Decide(ctx, dec); err != nil {
			return agent.ApprovalDecision{}, fmt.Errorf("record auto-approval: %w", err)
		}
		if err := s.record(ctx, p, "agent.approval.auto", dec.DecidedBy); err != nil {
			return agent.ApprovalDecision{}, fmt.Errorf("record auto-approval decision: %w", err)
		}
		return dec, nil
	}
	if err := s.record(ctx, p, "agent.approval.requested", p.SessionID.String()); err != nil {
		return agent.ApprovalDecision{}, fmt.Errorf("record approval request: %w", err)
	}
	_, dec, err := s.store.Get(ctx, p.ID)
	return dec, err // pending
}

func (s *Service) requestWithNotifications(ctx context.Context, p agent.ProposedAction) (agent.ApprovalDecision, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return agent.ApprovalDecision{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var result agent.ApprovalDecision
	err := s.transactions.Run(ctx, tenantID, func(txCtx context.Context) error {
		_, current, err := s.store.Get(txCtx, p.ID)
		if err == nil {
			// Action IDs are immutable idempotency keys. A retry must retain the
			// first proposal and its already-captured notification facts.
			result = current
			return nil
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return fmt.Errorf("load approval: %w", err)
		}
		if err := s.store.Enqueue(txCtx, p); err != nil {
			return fmt.Errorf("enqueue approval: %w", err)
		}
		// Enqueue is idempotent. Another request may have inserted this action after
		// our initial Get returned not-found, so re-read before deriving policy or
		// capture facts. The stored proposal is the immutable action identity: using
		// the caller's retry here could auto-approve a low-risk retry of a pending
		// high-risk action.
		stored, pending, err := s.store.Get(txCtx, p.ID)
		if err != nil {
			return fmt.Errorf("reload enqueued approval: %w", err)
		}
		if pending.State != agent.ApprovalPending {
			// A concurrent decision won before this retry reloaded the row. It already
			// owns the terminal source record and audit entry.
			result = pending
			return nil
		}
		p = stored
		if err := s.appendNotification(txCtx, notification.EventApprovalRequested, "approval_requested", p, pending, ""); err != nil {
			return err
		}
		if !s.mode.AutoApproves(p.Risk) {
			// The source record is durable before the audit append. The transaction
			// rolls both back on failure and keeps the shared audit lock last.
			if err := s.record(txCtx, p, "agent.approval.requested", p.SessionID.String()); err != nil {
				return fmt.Errorf("record approval request: %w", err)
			}
			result = pending
			return nil
		}
		result = agent.ApprovalDecision{ActionID: p.ID, State: agent.ApprovalApproved, DecidedBy: "auto", Reason: fmt.Sprintf("auto-approved (mode %s, risk %s)", s.mode, p.Risk), DecidedAt: s.clock.Now()}
		if err := s.store.Decide(txCtx, result); err != nil {
			return fmt.Errorf("record auto-approval: %w", err)
		}
		if err := s.appendNotification(txCtx, notification.EventApprovalDecided, "approval_decided", p, result, result.DecidedBy); err != nil {
			return err
		}
		if err := s.record(txCtx, p, "agent.approval.auto", result.DecidedBy); err != nil {
			return fmt.Errorf("record auto-approval decision: %w", err)
		}
		return nil
	})
	if err != nil {
		return agent.ApprovalDecision{}, err
	}
	return result, nil
}

// Get returns the immutable proposal and current decision for an existing approval request.
func (s *Service) Get(ctx context.Context, actionID shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	return s.store.Get(ctx, actionID)
}

// Decide records a human's approve/deny (idempotent – a 2nd decision returns ErrConflict),
// audited under the HUMAN actor.
func (s *Service) Decide(ctx context.Context, human string, actionID shared.ID, approve bool, reason string) (agent.ApprovalDecision, error) {
	human = strings.TrimSpace(human)
	if human == "" || shared.IsMachineActor(human) {
		return agent.ApprovalDecision{}, fmt.Errorf("%w: a decision must be attributed to an authenticated human", shared.ErrForbidden)
	}
	state := agent.ApprovalApproved
	if !approve {
		state = agent.ApprovalDenied
	}
	dec := agent.ApprovalDecision{ActionID: actionID, State: state, DecidedBy: human, Reason: reason, DecidedAt: s.clock.Now()}
	if s.transactions == nil {
		return s.decide(ctx, dec, human, state)
	}
	tenantID, _ := shared.TenantFrom(ctx)
	var out agent.ApprovalDecision
	if err := s.transactions.Run(ctx, tenantID, func(txCtx context.Context) error {
		var decideErr error
		out, decideErr = s.decide(txCtx, dec, human, state)
		return decideErr
	}); err != nil {
		return agent.ApprovalDecision{}, err
	}
	return out, nil
}

// decide writes the decision and its audit record. Both statements land on the caller's bound
// transaction when there is one, so a failed audit append undoes the decision instead of leaving a
// committed approval the operator was told had failed.
func (s *Service) decide(ctx context.Context, dec agent.ApprovalDecision, human string, state agent.ApprovalState) (agent.ApprovalDecision, error) {
	if err := s.store.Decide(ctx, dec); err != nil {
		return agent.ApprovalDecision{}, err // ErrConflict if already decided
	}
	a, _, err := s.store.Get(ctx, dec.ActionID)
	if err != nil {
		return agent.ApprovalDecision{}, fmt.Errorf("load decided approval: %w", err)
	}
	if s.notifications != nil {
		eventType, sourceKind := notification.EventApprovalDecided, "approval_decided"
		if state == agent.ApprovalTimeout {
			eventType, sourceKind = notification.EventApprovalTimedOut, "approval_timedout"
		}
		if err := s.appendNotification(ctx, eventType, sourceKind, a, dec, human); err != nil {
			return agent.ApprovalDecision{}, err
		}
	}
	auditAction := "agent.approval." + string(state)
	if state == agent.ApprovalTimeout {
		auditAction = "agent.approval.timeout"
	}
	if err := s.record(ctx, a, auditAction, human); err != nil {
		return agent.ApprovalDecision{}, fmt.Errorf("record approval decision: %w", err)
	}
	return dec, nil
}

func (s *Service) appendNotification(ctx context.Context, eventType notification.EventType, sourceKind string, p agent.ProposedAction, decision agent.ApprovalDecision, actor string) error {
	if s.notifications == nil {
		return nil
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	facts, err := s.lifecycleFacts.SnapshotNotificationLifecycleFacts(ctx, tenantID, p.EngagementID, actor)
	if err != nil {
		return fmt.Errorf("snapshot approval notification facts: %w", err)
	}
	approvers, err := s.approverFacts.SnapshotNotificationApprovers(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("snapshot approval notification approvers: %w", err)
	}
	approvers = uniqueApprovalRecipients(approvers)
	spec, ok := notification.LookupEvent(eventType)
	if !ok {
		return fmt.Errorf("%w: unknown approval notification event", shared.ErrValidation)
	}
	occurredAt := s.clock.Now().UTC()
	title := scrubApprovalText("Approval "+string(decision.State), 200)
	summary := scrubApprovalText("An approval lifecycle event occurred.", 500)
	engagementName := scrubApprovalText(facts.EngagementName, 500)
	actorName := scrubApprovalText(facts.ActorName, 500)
	data := map[string]any{
		"approval_id": p.ID, "engagement_id": p.EngagementID, "lead_user_id": facts.LeadUserID,
		"kind": approvalKind(p), "status": decision.State, "decision": decision.State,
		"actor": actorName, "engagement_name": engagementName,
		"title": title, "summary": summary, "approver_count": len(approvers),
	}
	if !facts.ActorUserID.IsZero() {
		data["actor_user_id"] = facts.ActorUserID
	}
	if s.timeout > 0 {
		data["expires_at"] = p.ProposedAt.Add(s.timeout).UTC()
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode approval notification: %w", err)
	}
	vars := map[string]string{
		"event_type": string(eventType), "event_label": spec.Label, "occurred_at": occurredAt.Format(time.RFC3339),
		"title": title, "summary": summary, "kind": approvalKind(p), "status": string(decision.State),
		"decision": string(decision.State), "engagement_name": engagementName, "actor": actorName,
	}
	if s.timeout > 0 {
		vars["expires_at"] = p.ProposedAt.Add(s.timeout).UTC().Format(time.RFC3339)
	}
	record, err := notification.SnapshotSourceRecord(notification.SourceRecord{TenantID: tenantID, SourceKind: sourceKind, SourceID: p.ID.String(), EventType: eventType, EngagementID: p.EngagementID, OccurredAt: occurredAt, Data: raw, SubjectKind: "approval", SubjectID: p.ID.String()}, vars)
	if err != nil {
		return fmt.Errorf("snapshot approval notification: %w", err)
	}
	if err := s.approvalOutbox.AppendApprovalSource(ctx, record, approvers); err != nil {
		return fmt.Errorf("append approval notification: %w", err)
	}
	return nil
}

func scrubApprovalText(value string, limit int) string {
	return privacy.ScrubURLCredentials(notification.ScrubPersonalText(value, limit))
}

func approvalKind(p agent.ProposedAction) string {
	if strings.HasPrefix(strings.TrimSpace(p.SessionID.String()), "response:") {
		return "response"
	}
	return "agent"
}

func uniqueApprovalRecipients(ids []shared.ID) []shared.ID {
	seen := make(map[shared.ID]struct{}, len(ids))
	unique := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if id.IsZero() {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return unique
}

// SweepExpired flips pending actions for an engagement that have outlived the timeout to a
// fail-closed timeout-deny. Returns how many were expired. A worker calls this periodically.
func (s *Service) SweepExpired(ctx context.Context, engagementID shared.ID) (int, error) {
	if s.timeout <= 0 {
		return 0, nil
	}
	pending, err := s.store.Pending(ctx, engagementID)
	if err != nil {
		return 0, err
	}
	now := s.clock.Now()
	n := 0
	for _, a := range pending {
		if now.Sub(a.ProposedAt) < s.timeout {
			continue
		}
		dec := agent.ApprovalDecision{ActionID: a.ID, State: agent.ApprovalTimeout, Reason: "approval timed out (fail-closed)", DecidedAt: now}
		if _, err := s.timeoutDecision(ctx, dec); err == nil {
			n++
			// Re-drive the suspended session so it sees the denial and fails fast (no hang).
			// If the re-enqueue fails the action is already durably timeout-denied (safe); the
			// startup reconciler is the backstop, but log so the stuck session is visible.
			if s.resume != nil {
				if rerr := s.resume(ctx, a.SessionID, a.ID); rerr != nil {
					slog.Warn("approval: resume-on-timeout enqueue failed; reconciler will retry",
						"session", a.SessionID.String(), "action", a.ID.String(), "err", rerr)
				}
			}
		} else if !errors.Is(err, shared.ErrConflict) {
			return n, err
		}
	}
	return n, nil
}

func (s *Service) timeoutDecision(ctx context.Context, dec agent.ApprovalDecision) (agent.ApprovalDecision, error) {
	if s.transactions == nil {
		return s.decide(ctx, dec, "system", agent.ApprovalTimeout)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return agent.ApprovalDecision{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var result agent.ApprovalDecision
	err := s.transactions.Run(ctx, tenantID, func(txCtx context.Context) error {
		var err error
		result, err = s.decide(txCtx, dec, "system", agent.ApprovalTimeout)
		return err
	})
	if err != nil {
		return agent.ApprovalDecision{}, err
	}
	return result, nil
}

// SweepAllExpired sweeps every engagement that currently has a pending approval (the prod
// timeout sweeper's fan-out). Returns the total expired.
//
// The sweeper runs on a background context with no tenant, so each scope's tenant is bound before
// its engagement is swept. Everything downstream of that binding (Pending, Decide, the record
// audit and the resume enqueue) then runs inside one tenant, which is what lets the durable store
// reach the RLS-protected approval queue at all.
func (s *Service) SweepAllExpired(ctx context.Context) (int, error) {
	if s.timeout <= 0 {
		return 0, nil
	}
	scopes, err := s.store.EngagementsWithPending(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, scope := range scopes {
		scopeCtx := ctx
		if !scope.TenantID.IsZero() {
			scopeCtx = shared.WithTenant(ctx, scope.TenantID)
		}
		n, err := s.SweepExpired(scopeCtx, scope.EngagementID)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// RunSweeper periodically sweeps expired approvals until ctx is cancelled (a running binary
// must call this – fail-closed timeout is otherwise never enforced in prod).
func (s *Service) RunSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.SweepAllExpired(ctx)
		}
	}
}

// record appends the approval decision to the audit chain. An approval decision is the
// human gate in front of an agent action, so the decision and its record are one unit: the
// error is returned rather than dropped, and every caller propagates it.
func (s *Service) record(ctx context.Context, p agent.ProposedAction, action, actor string) error {
	entry := ports.AuditEntry{
		Actor:  actor,
		Action: action,
		Target: p.Target.Value,
		Metadata: map[string]string{
			"agent_action_id": p.ID.String(),
			"agent_session":   p.SessionID.String(),
			"tool":            p.Tool,
			"risk":            string(p.Risk),
		},
		At: s.clock.Now(),
	}
	if s.notifications != nil && action == "agent.approval.requested" {
		entry.At = p.ProposedAt
		entry.Metadata["idempotency_key"] = "approval-requested:" + p.ID.String()
		if idempotent, ok := s.audit.(ports.IdempotentAuditLogger); ok {
			return idempotent.RecordOnce(ctx, entry)
		}
	}
	return s.audit.Record(ctx, entry)
}
