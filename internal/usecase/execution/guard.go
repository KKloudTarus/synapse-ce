// Package execution holds the shared server-side execution guard: engagement
// scope + legal authorization-window enforcement with append-only audit, applied
// BEFORE any tool runs. Both SCA and recon authorize through this one
// chokepoint – never a per-caller copy of a security-critical control. A
// divergent copy of the gate is the worst possible debt: scope enforcement and
// the append-only audit trail must live in exactly one place.
package execution

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Guard authorizes tool executions against an engagement's scope and legal
// authorization window, recording every decision (allow and deny) on the
// append-only audit log.
type Guard struct {
	engagements ports.EngagementRepository
	clock       ports.Clock
	audit       ports.AuditLogger
}

// NewGuard validates its dependencies and returns the guard.
func NewGuard(engagements ports.EngagementRepository, clock ports.Clock, audit ports.AuditLogger) (*Guard, error) {
	if engagements == nil || clock == nil || audit == nil {
		return nil, fmt.Errorf("%w: execution guard requires engagements, clock, and audit", shared.ErrValidation)
	}
	return &Guard{engagements: engagements, clock: clock, audit: audit}, nil
}

// Request describes one tool execution to authorize. Action is the audit verb
// (e.g. "sca.scan", "recon.subfinder"); Target is the asset that will be acted
// on and is matched kind-aware against the engagement scope. Metadata is recorded
// verbatim on the audit entry (e.g. {"kind": "...", "engagement": "..."}).
type Request struct {
	Actor        string
	EngagementID shared.ID
	Action       string
	Target       engagement.Target
	Metadata     map[string]string
}

// Authorize enforces the engagement lifecycle status, then the authorization
// window, then scope, then the rules of engagement (tool class + blackout), audits
// the decision, and returns the decision timestamp. The order is lifecycle -> time
// -> target -> RoE so a denial reason is unambiguous. On denial it audits
// "<action>.denied" with a reason and returns shared.ErrForbidden; the caller must
// not run any tool.
func (g *Guard) Authorize(ctx context.Context, req Request) (time.Time, error) {
	eng, err := g.engagements.GetByID(ctx, req.EngagementID)
	if err != nil {
		return time.Time{}, fmt.Errorf("load engagement: %w", err)
	}
	now := g.clock.Now()
	if !eng.AllowsExecution() {
		g.auditDenied(ctx, req, now, "engagement_inactive")
		return time.Time{}, fmt.Errorf("%w: engagement %s is not in an executable state", shared.ErrForbidden, req.EngagementID)
	}
	if !eng.IsAuthorizedAt(now) {
		g.auditDenied(ctx, req, now, "expired_window")
		return time.Time{}, fmt.Errorf("%w: engagement %s is outside its authorization window", shared.ErrForbidden, req.EngagementID)
	}
	if !eng.Scope.AllowsTarget(req.Target) {
		g.auditDenied(ctx, req, now, "out_of_scope")
		return time.Time{}, fmt.Errorf("%w: target is not in the engagement scope", shared.ErrForbidden)
	}
	if ok, reason := eng.RoE.Permits(engagement.ToolClassOf(req.Action), now); !ok {
		g.auditDenied(ctx, req, now, reason)
		return time.Time{}, fmt.Errorf("%w: action %q not permitted by the rules of engagement", shared.ErrForbidden, req.Action)
	}
	if err := g.audit.Record(ctx, ports.AuditEntry{
		Actor:    req.Actor,
		Action:   req.Action,
		Target:   req.Target.Value,
		Metadata: req.Metadata,
		At:       now,
	}); err != nil {
		return time.Time{}, fmt.Errorf("audit %s: %w", req.Action, err)
	}
	return now, nil
}

// AuthorizeEngagementArtifact enforces lifecycle, authorization window, and RoE
// for actions over an already engagement-scoped artifact. It deliberately skips
// target scope matching because the action does not execute against an external
// target; the artifact's engagement/tenant ownership is the boundary being
// authorized. This keeps artifact-backed scans on the shared execution/audit
// chokepoint without inventing a fake target.
func (g *Guard) AuthorizeEngagementArtifact(ctx context.Context, req Request) (time.Time, error) {
	eng, err := g.engagements.GetByID(ctx, req.EngagementID)
	if err != nil {
		return time.Time{}, fmt.Errorf("load engagement: %w", err)
	}
	now := g.clock.Now()
	if !eng.AllowsExecution() {
		g.auditDenied(ctx, req, now, "engagement_inactive")
		return time.Time{}, fmt.Errorf("%w: engagement %s is not in an executable state", shared.ErrForbidden, req.EngagementID)
	}
	if !eng.IsAuthorizedAt(now) {
		g.auditDenied(ctx, req, now, "expired_window")
		return time.Time{}, fmt.Errorf("%w: engagement %s is outside its authorization window", shared.ErrForbidden, req.EngagementID)
	}
	if ok, reason := eng.RoE.Permits(engagement.ToolClassOf(req.Action), now); !ok {
		g.auditDenied(ctx, req, now, reason)
		return time.Time{}, fmt.Errorf("%w: action %q not permitted by the rules of engagement", shared.ErrForbidden, req.Action)
	}
	if err := g.audit.Record(ctx, ports.AuditEntry{
		Actor:    req.Actor,
		Action:   req.Action,
		Target:   req.Target.Value,
		Metadata: req.Metadata,
		At:       now,
	}); err != nil {
		return time.Time{}, fmt.Errorf("audit %s: %w", req.Action, err)
	}
	return now, nil
}

// AuditDenial records a denied execution that was rejected BEFORE reaching Authorize
// (e.g. a submit-time fast-fail in the recon use case: out-of-scope, capability,
// live-recon-disabled, invalid target). It exists so no denial path is silent
// – every refusal lands on the append-only audit log, exactly like
// the denials Authorize records itself.
func (g *Guard) AuditDenial(ctx context.Context, req Request, reason string) {
	g.auditDenied(ctx, req, g.clock.Now(), reason)
}

// auditDenied records a gated-out execution on the append-only audit log (golden
// rule 6) – a denied action is never invisible. Best-effort: the denial error is
// returned regardless of whether the audit write succeeds.
func (g *Guard) auditDenied(ctx context.Context, req Request, now time.Time, reason string) {
	md := make(map[string]string, len(req.Metadata)+1)
	for k, v := range req.Metadata {
		md[k] = v
	}
	md["reason"] = reason
	_ = g.audit.Record(ctx, ports.AuditEntry{
		Actor:    req.Actor,
		Action:   req.Action + ".denied",
		Target:   req.Target.Value,
		Metadata: md,
		At:       now,
	})
}
