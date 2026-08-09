// Package fleetrolloutuc is the operator-facing lifecycle of an agent update rollout: set a target,
// promote it past the canary, pause it, resume it, and answer what one agent should be offered.
//
// Every mutation is audited, because a rollout is the one control in the fleet that can replace a
// running binary on a host this project does not own. "Who moved the fleet to 1.4.0, and when" has to
// be answerable from the record rather than from memory.
package fleetrolloutuc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service owns the rollout plan lifecycle.
type Service struct {
	store ports.FleetRolloutStore
	audit ports.AuditLogger
	clock ports.Clock
}

// NewService validates and returns the service.
func NewService(store ports.FleetRolloutStore, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: fleet rollout service needs a store, an audit log and a clock", shared.ErrValidation)
	}
	return &Service{store: store, audit: audit, clock: clock}, nil
}

// Get returns the plan for a channel, or shared.ErrNotFound when none is configured.
func (s *Service) Get(ctx context.Context, tenantID shared.ID, channel string) (*fleetrollout.Plan, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: rollout lookup needs a tenant", shared.ErrValidation)
	}
	return s.store.Get(ctx, tenantID, channel)
}

// SetTargetInput starts or replaces a rollout.
type SetTargetInput struct {
	TenantID      shared.ID
	Channel       string
	TargetVersion string
	CanaryGroups  []string
	Actor         shared.ID
}

// SetTarget sets the version the fleet should reach and the groups that receive it first.
//
// Setting a target ALWAYS resets promotion. Replacing the target while a previous one was promoted to
// every group would otherwise ship the new version to the whole fleet at once, which is the
// unconditional update this design exists to prevent — and it would do it silently, by inheriting a
// decision an operator made about a different version.
func (s *Service) SetTarget(ctx context.Context, in SetTargetInput) (*fleetrollout.Plan, error) {
	if in.TenantID.IsZero() {
		return nil, fmt.Errorf("%w: a rollout needs a tenant", shared.ErrValidation)
	}
	if in.Actor.IsZero() {
		return nil, fmt.Errorf("%w: a rollout change needs an actor", shared.ErrValidation)
	}
	groups, err := fleetrollout.NormalizeCanaryGroups(in.CanaryGroups)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.TargetVersion) != "" && len(groups) == 0 {
		return nil, fmt.Errorf("%w: a rollout needs at least one canary group; a target with no canary can only ever go to every host at once",
			shared.ErrValidation)
	}

	now := s.clock.Now().UTC()
	plan := &fleetrollout.Plan{
		TenantID:      in.TenantID,
		Channel:       fleetrollout.NormalizeChannel(in.Channel),
		TargetVersion: strings.TrimSpace(in.TargetVersion),
		CanaryGroups:  groups,
		PromotedToAll: false,
		UpdatedBy:     in.Actor,
		Audit:         shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if err := s.store.Put(ctx, plan); err != nil {
		return nil, fmt.Errorf("store rollout plan: %w", err)
	}
	s.record(ctx, plan, in.Actor, "fleet.rollout.target", map[string]string{
		"target_version": plan.TargetVersion,
		"canary_groups":  strings.Join(plan.CanaryGroups, ","),
	}, now)
	return plan, nil
}

// Promote releases the current target to every group.
//
// It is a SEPARATE action from setting the target on purpose: the two together are the operator saying
// "the canary held". A single call that set and promoted at once would collapse the control into the
// thing it was built to prevent.
func (s *Service) Promote(ctx context.Context, tenantID shared.ID, channel string, actor shared.ID) (*fleetrollout.Plan, error) {
	plan, err := s.mutable(ctx, tenantID, channel, actor)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(plan.TargetVersion) == "" {
		return nil, fmt.Errorf("%w: there is no target version to promote", shared.ErrValidation)
	}
	if plan.Paused {
		return nil, fmt.Errorf("%w: the rollout is paused (%s); resume it before promoting", shared.ErrValidation, plan.PauseReason)
	}
	now := s.clock.Now().UTC()
	plan.PromotedToAll = true
	plan.UpdatedBy = actor
	plan.Audit.UpdatedAt = now
	if err := s.persist(ctx, plan); err != nil {
		return nil, err
	}
	s.record(ctx, plan, actor, "fleet.rollout.promote", map[string]string{"target_version": plan.TargetVersion}, now)
	return plan, nil
}

// Pause stops every offer, including to the canary, without discarding the plan.
//
// The reason is required. A fleet that stops updating with no recorded reason is indistinguishable
// from one that is broken, and the person debugging it at 3am is usually not the person who paused it.
func (s *Service) Pause(ctx context.Context, tenantID shared.ID, channel string, actor shared.ID, reason string) (*fleetrollout.Plan, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("%w: pausing a rollout needs a reason", shared.ErrValidation)
	}
	plan, err := s.mutable(ctx, tenantID, channel, actor)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	plan.Paused = true
	plan.PauseReason = strings.TrimSpace(reason)
	plan.UpdatedBy = actor
	plan.Audit.UpdatedAt = now
	if err := s.persist(ctx, plan); err != nil {
		return nil, err
	}
	s.record(ctx, plan, actor, "fleet.rollout.pause", map[string]string{"reason": plan.PauseReason}, now)
	return plan, nil
}

// Resume lifts a pause. Promotion state is untouched: resuming returns the rollout to exactly where it
// was, rather than quietly advancing it.
func (s *Service) Resume(ctx context.Context, tenantID shared.ID, channel string, actor shared.ID) (*fleetrollout.Plan, error) {
	plan, err := s.mutable(ctx, tenantID, channel, actor)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	plan.Paused = false
	plan.PauseReason = ""
	plan.UpdatedBy = actor
	plan.Audit.UpdatedAt = now
	if err := s.persist(ctx, plan); err != nil {
		return nil, err
	}
	s.record(ctx, plan, actor, "fleet.rollout.resume", nil, now)
	return plan, nil
}

// DecideFor answers what ONE agent is offered, given its group and running version.
//
// A missing plan is not an error here: it is the normal state for a tenant with no rollout, and the
// decision carries the reason so the agent's silence is explainable.
func (s *Service) DecideFor(ctx context.Context, tenantID shared.ID, channel, agentGroup, agentVersion string) fleetrollout.Decision {
	plan, err := s.store.Get(ctx, tenantID, channel)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			// A store failure must not be read as "no rollout": that would be indistinguishable from a
			// deliberate resting state. It declines, with a reason that says the truth.
			return fleetrollout.Decision{Reason: "the rollout plan could not be read; no update is offered"}
		}
		return fleetrollout.Decide(nil, agentGroup, agentVersion)
	}
	return fleetrollout.Decide(plan, agentGroup, agentVersion)
}

func (s *Service) mutable(ctx context.Context, tenantID shared.ID, channel string, actor shared.ID) (*fleetrollout.Plan, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: a rollout change needs a tenant", shared.ErrValidation)
	}
	if actor.IsZero() {
		return nil, fmt.Errorf("%w: a rollout change needs an actor", shared.ErrValidation)
	}
	return s.store.Get(ctx, tenantID, channel)
}

func (s *Service) persist(ctx context.Context, plan *fleetrollout.Plan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := s.store.Put(ctx, plan); err != nil {
		return fmt.Errorf("store rollout plan: %w", err)
	}
	return nil
}

// record audits a rollout mutation. An audit failure is returned to nobody but is not silently lost:
// it is the caller's error path that already failed the mutation, so this only runs after a successful
// write, and a failure here is reported by the audit log's own alerting rather than by rolling back a
// plan the fleet may already have acted on.
func (s *Service) record(ctx context.Context, plan *fleetrollout.Plan, actor shared.ID, action string, extra map[string]string, at time.Time) {
	metadata := map[string]string{"channel": plan.Channel}
	for k, v := range extra {
		if v != "" {
			metadata[k] = v
		}
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor.String(),
		Action:   action,
		Target:   plan.TenantID.String() + "/" + plan.Channel,
		Metadata: metadata,
		At:       at,
	})
}
