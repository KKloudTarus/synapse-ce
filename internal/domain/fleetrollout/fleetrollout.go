// Package fleetrollout decides whether ONE agent is offered an update, and to which version.
//
// The requirement it exists to enforce (#412 req 9) is stated as a prohibition: there is never an
// unconditional fleet-wide auto-update. An offer therefore requires an operator to have said three
// things explicitly — a target version, who receives it first, and that the rollout has been promoted
// beyond that first group. Anything missing, unparseable, paused or ambiguous yields NO offer.
//
// That direction is deliberate and it is the opposite of the usual default. An update that is not
// offered costs a delay an operator can see and fix; an update offered wrongly replaces a working
// binary on a host this project does not own, at a moment nobody chose. So every rule below fails
// towards "do not offer", and the reason is always carried so the silence is explainable rather than
// mysterious.
//
// It is pure domain code: no store, no clock, no transport.
package fleetrollout

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DefaultGroup is the group an agent belongs to when an operator has not assigned one.
//
// Group membership is operator-assigned and never self-declared. An agent that could name its own
// group could place itself in a group pinned to an older, vulnerable version, which turns a rollout
// control into a downgrade primitive for whoever controls the agent.
const DefaultGroup = "default"

// DefaultChannel is the update channel an agent is on when none is configured.
const DefaultChannel = "stable"

// maxGroups bounds a plan's canary list so a stored plan cannot become unbounded work per heartbeat.
const maxGroups = 64

// maxGroupNameLen bounds one group name.
const maxGroupNameLen = 64

// Plan is one tenant's rollout state for one channel. It is operator-owned: nothing an agent reports
// can change it.
type Plan struct {
	TenantID shared.ID
	Channel  string
	// TargetVersion is the version operators want the fleet to reach. Empty means no rollout is in
	// progress, which is a valid resting state and offers nothing.
	TargetVersion string
	// CanaryGroups receive TargetVersion first. A rollout with no canary group cannot be promoted,
	// because "promote" would then mean "go straight to every host", which is the unconditional
	// fleet-wide update this design forbids.
	CanaryGroups []string
	// PromotedToAll records the second, deliberate operator action: the canary held, so every other
	// group may now receive the target.
	PromotedToAll bool
	// Paused stops all offers, including to the canary, without discarding the plan. Pausing is the
	// documented emergency control; it is not the same as clearing the target.
	Paused      bool
	PauseReason string
	UpdatedBy   shared.ID
	Audit       shared.Audit
}

// Validate reports whether the plan is one an operator could act on.
func (p Plan) Validate() error {
	if p.TenantID.IsZero() {
		return fmt.Errorf("%w: rollout plan needs a tenant", shared.ErrValidation)
	}
	if strings.TrimSpace(p.Channel) == "" {
		return fmt.Errorf("%w: rollout plan needs a channel", shared.ErrValidation)
	}
	if target := strings.TrimSpace(p.TargetVersion); target != "" {
		if _, ok := fleetversion.Parse(target); !ok {
			return fmt.Errorf("%w: rollout target version %q is not a version this control plane can compare",
				shared.ErrValidation, target)
		}
	}
	if len(p.CanaryGroups) > maxGroups {
		return fmt.Errorf("%w: rollout plan names %d canary groups, over the %d bound",
			shared.ErrValidation, len(p.CanaryGroups), maxGroups)
	}
	for _, group := range p.CanaryGroups {
		if err := ValidateGroup(group); err != nil {
			return err
		}
	}
	// Promotion is meaningless without a target, and dangerous without a canary: it would mean every
	// host at once, which is the one behaviour this package exists to prevent.
	if p.PromotedToAll {
		if strings.TrimSpace(p.TargetVersion) == "" {
			return fmt.Errorf("%w: a rollout cannot be promoted without a target version", shared.ErrValidation)
		}
		if len(p.CanaryGroups) == 0 {
			return fmt.Errorf("%w: a rollout cannot be promoted before a canary group has held it", shared.ErrValidation)
		}
	}
	if p.Paused && strings.TrimSpace(p.PauseReason) == "" {
		return fmt.Errorf("%w: pausing a rollout needs a reason, so the fleet's silence is explainable", shared.ErrValidation)
	}
	return nil
}

// ValidateGroup reports whether name is an acceptable agent group.
func ValidateGroup(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("%w: an agent group name is required", shared.ErrValidation)
	}
	if trimmed != name {
		return fmt.Errorf("%w: agent group %q has surrounding whitespace", shared.ErrValidation, name)
	}
	if len(name) > maxGroupNameLen {
		return fmt.Errorf("%w: agent group name is longer than %d characters", shared.ErrValidation, maxGroupNameLen)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("%w: agent group %q may use only letters, digits, dash, underscore and dot",
				shared.ErrValidation, name)
		}
	}
	return nil
}

// NormalizeGroup returns the group an agent belongs to, defaulting an unset one.
func NormalizeGroup(name string) string {
	if trimmed := strings.TrimSpace(name); trimmed != "" {
		return trimmed
	}
	return DefaultGroup
}

// NormalizeChannel returns the channel to use, defaulting an unset one.
func NormalizeChannel(name string) string {
	if trimmed := strings.TrimSpace(name); trimmed != "" {
		return trimmed
	}
	return DefaultChannel
}

// Reason explains a decision in words an operator can act on. It is part of the contract: an agent
// that is not offered an update must be able to say why, or a stalled rollout looks like a bug.
type Reason string

const (
	ReasonNoPlan           Reason = "no rollout plan is configured for this channel"
	ReasonNoTarget         Reason = "the rollout plan names no target version"
	ReasonPaused           Reason = "the rollout is paused"
	ReasonUnparseableAgent Reason = "the agent's version cannot be compared, so no update is offered"
	ReasonUpToDate         Reason = "the agent is already at or above the target version"
	ReasonCanaryOnly       Reason = "the target is limited to the canary groups until it is promoted"
	ReasonCanary           Reason = "the agent is in a canary group for this target"
	ReasonPromoted         Reason = "the target has been promoted to every group"
)

// Decision is the answer for one agent.
type Decision struct {
	// Offer is true only when an operator has explicitly authorised this agent to move to Target.
	Offer bool
	// Target is the version to move to; empty when Offer is false.
	Target string
	Reason Reason
}

// Decide answers whether this agent is offered an update.
//
// plan may be nil, which is the normal state for a tenant with no rollout in progress and yields no
// offer. Every other path is also fail-closed: an unparseable target, an unparseable agent version, a
// paused plan, or a target that is not newer than what the agent runs all decline.
//
// Downgrade is never offered. A target older than the running version declines rather than moving the
// agent backwards, because a rollout control that can move a fleet to an older build is a way to
// reintroduce a fixed vulnerability at scale.
func Decide(plan *Plan, agentGroup, agentVersion string) Decision {
	if plan == nil {
		return Decision{Reason: ReasonNoPlan}
	}
	if plan.Paused {
		return Decision{Reason: ReasonPaused}
	}
	target := strings.TrimSpace(plan.TargetVersion)
	if target == "" {
		return Decision{Reason: ReasonNoTarget}
	}
	targetVersion, ok := fleetversion.Parse(target)
	if !ok {
		// A stored plan should never hold an unparseable target (Validate refuses it), but a decision
		// path that trusted that would offer an unusable version if the invariant ever slipped.
		return Decision{Reason: ReasonNoTarget}
	}
	running, ok := fleetversion.Parse(agentVersion)
	if !ok {
		return Decision{Reason: ReasonUnparseableAgent}
	}
	if !running.Less(targetVersion) {
		return Decision{Reason: ReasonUpToDate}
	}

	group := NormalizeGroup(agentGroup)
	for _, canary := range plan.CanaryGroups {
		if canary == group {
			return Decision{Offer: true, Target: target, Reason: ReasonCanary}
		}
	}
	if !plan.PromotedToAll {
		return Decision{Reason: ReasonCanaryOnly}
	}
	return Decision{Offer: true, Target: target, Reason: ReasonPromoted}
}

// NormalizeCanaryGroups trims, validates, deduplicates and sorts a canary list so a stored plan is
// deterministic and a decision cannot depend on the order an operator typed.
func NormalizeCanaryGroups(groups []string) ([]string, error) {
	seen := make(map[string]bool, len(groups))
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		trimmed := strings.TrimSpace(group)
		if trimmed == "" {
			continue
		}
		if err := ValidateGroup(trimmed); err != nil {
			return nil, err
		}
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out, nil
}
