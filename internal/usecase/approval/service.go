// Package approval is the Human-In-The-Loop gate for AI-proposed actions.
// A proposed action is auto-approved (per the engagement's ApprovalMode + the action's
// RiskClass), or enqueued for a human, or – if undecided past the timeout – failed CLOSED
// (denied). Every decision is recorded on the append-only audit log, attributed to the
// deciding human (or the system on a timeout). It does NOT execute anything: it only
// produces an ApprovalDecision the safety gate consumes.
package approval

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
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
	if _, dec, err := s.store.Get(ctx, p.ID); err == nil && dec.State != agent.ApprovalPending {
		return dec, nil // already decided – idempotent resume
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
		s.record(ctx, p, "agent.approval.auto", dec.DecidedBy)
		return dec, nil
	}
	s.record(ctx, p, "agent.approval.requested", p.SessionID.String())
	_, dec, err := s.store.Get(ctx, p.ID)
	return dec, err // pending
}

// Decide records a human's approve/deny (idempotent – a 2nd decision returns ErrConflict),
// audited under the HUMAN actor.
func (s *Service) Decide(ctx context.Context, human string, actionID shared.ID, approve bool, reason string) (agent.ApprovalDecision, error) {
	if human == "" {
		return agent.ApprovalDecision{}, fmt.Errorf("%w: a decision must be attributed to a human", shared.ErrValidation)
	}
	state := agent.ApprovalApproved
	if !approve {
		state = agent.ApprovalDenied
	}
	dec := agent.ApprovalDecision{ActionID: actionID, State: state, DecidedBy: human, Reason: reason, DecidedAt: s.clock.Now()}
	if err := s.store.Decide(ctx, dec); err != nil {
		return agent.ApprovalDecision{}, err // ErrConflict if already decided
	}
	if a, _, err := s.store.Get(ctx, actionID); err == nil {
		s.record(ctx, a, "agent.approval."+string(state), human)
	}
	return dec, nil
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
		if err := s.store.Decide(ctx, dec); err == nil {
			s.record(ctx, a, "agent.approval.timeout", "system")
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
		}
	}
	return n, nil
}

// SweepAllExpired sweeps every engagement that currently has a pending approval (the prod
// timeout sweeper's fan-out). Returns the total expired.
func (s *Service) SweepAllExpired(ctx context.Context) (int, error) {
	if s.timeout <= 0 {
		return 0, nil
	}
	engs, err := s.store.EngagementsWithPending(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, e := range engs {
		n, err := s.SweepExpired(ctx, e)
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

func (s *Service) record(ctx context.Context, p agent.ProposedAction, action, actor string) {
	_ = s.audit.Record(ctx, ports.AuditEntry{
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
	})
}
