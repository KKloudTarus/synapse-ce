package engagement

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ToolClass is a coarse category of tool an engagement may permit (e.g. "sca",
// "recon", "exploit"), derived from a gate action's prefix.
type ToolClass string

// ToolClassOf derives the tool class from a gate action: the segment before the
// first '.', e.g. "sca.scan" -> "sca", "recon.subfinder" -> "recon".
func ToolClassOf(action string) ToolClass {
	if i := strings.IndexByte(action, '.'); i >= 0 {
		return ToolClass(action[:i])
	}
	return ToolClass(action)
}

// Blackout is a time range during which NO tool may run (maintenance window,
// client business hours, etc.), enforced by the execution gate.
type Blackout struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Contains reports whether t falls within the blackout [From, To] (inclusive).
func (b Blackout) Contains(t time.Time) bool {
	return !t.Before(b.From) && !t.After(b.To)
}

// RoE is the minimal rules-of-engagement the execution gate consumes: which tool
// classes are permitted and when tools must not run. Deliberately small;
// richer rules can follow.
type RoE struct {
	// AllowedToolClasses restricts which tool classes may run. EMPTY means no
	// restriction (all classes allowed), so engagements created before RoE keep
	// working – operators opt INTO restriction by listing classes.
	AllowedToolClasses []ToolClass `json:"allowed_tool_classes,omitempty"`
	// Blackouts are time ranges during which no tool may run.
	Blackouts []Blackout `json:"blackouts,omitempty"`
	// Offensive holds the #418/#823 offensive-governance rules an offensive action (live recon, DAST,
	// adversary emulation, exploitation) is authorized against. It persists inside the same JSON RoE
	// column; an engagement without it refuses every offensive action (fail-closed).
	Offensive OffensiveRoE `json:"offensive,omitempty"`
}

// OffensiveRoE is the rules-of-engagement the offensive governance gate (#418) requires beyond scope and
// the authorization window: the contacts an operator reaches on incident, the highest risk class the
// engagement permits, and the asset exclusions the operator has reviewed. Every field is required before
// an offensive action is authorized, so a partially-filled OffensiveRoE keeps offensive work refused.
type OffensiveRoE struct {
	CustomerContact    string                    `json:"customer_contact,omitempty"`
	EmergencyContact   string                    `json:"emergency_contact,omitempty"`
	RiskCeiling        offensivepolicy.RiskClass `json:"risk_ceiling,omitempty"`
	ExcludedAssets     []string                  `json:"excluded_assets,omitempty"`
	ExclusionsReviewed bool                      `json:"exclusions_reviewed,omitempty"`
}

// Complete reports whether every offensive-RoE FIELD an authorization needs is set: both contacts, a
// risk ceiling that is an executable class (low/medium/high, never prohibited or unset), and an explicit
// exclusions review. It is a necessary condition for an authorized run, not the whole gate: the gate
// additionally requires a non-empty scope, an open authorization window, and the run's specific target to
// be in scope. So Complete() is never true when a run would be authorized-false, but it can be true while
// a run is still refused for scope or window; the UI reads it as offensive-RoE readiness, not run-ready.
func (o OffensiveRoE) Complete() bool {
	return strings.TrimSpace(o.CustomerContact) != "" &&
		strings.TrimSpace(o.EmergencyContact) != "" &&
		offensiveRiskCeilingValid(o.RiskCeiling) &&
		o.ExclusionsReviewed
}

// offensiveRiskCeilingValid accepts only the three executable classes as a ceiling. A "prohibited" or
// unset ceiling is not a permission level and must not read as one.
func offensiveRiskCeilingValid(c offensivepolicy.RiskClass) bool {
	switch c {
	case offensivepolicy.RiskLow, offensivepolicy.RiskMedium, offensivepolicy.RiskHigh:
		return true
	default:
		return false
	}
}

// Permits reports whether a tool of the given class may run at time t under these
// rules, returning a machine reason ("tool_not_allowed" / "blackout_window") when
// it may not.
func (r RoE) Permits(class ToolClass, t time.Time) (bool, string) {
	if len(r.AllowedToolClasses) > 0 {
		allowed := false
		for _, c := range r.AllowedToolClasses {
			if c == class {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, "tool_not_allowed"
		}
	}
	for _, b := range r.Blackouts {
		if b.Contains(t) {
			return false, "blackout_window"
		}
	}
	return true, ""
}

// SetRoE validates and sets the execution-gate rules of engagement (tool classes + blackouts), stamping
// UpdatedAt. Each blackout must have end >= start. It preserves any offensive RoE already set (that is
// managed separately via SetOffensiveRoE), so replacing the tool-class rules never silently drops the
// offensive-governance rules.
func (e *Engagement) SetRoE(roe RoE, now time.Time) error {
	for _, b := range roe.Blackouts {
		if b.To.Before(b.From) {
			return fmt.Errorf("%w: blackout end must not be before its start", shared.ErrValidation)
		}
	}
	roe.Offensive = e.RoE.Offensive
	e.RoE = roe
	e.Audit.UpdatedAt = now
	return nil
}

// SetOffensiveRoE validates and sets the offensive-governance rules of engagement, stamping UpdatedAt. A
// set risk ceiling must be an executable class (low/medium/high); an empty ceiling is allowed and simply
// leaves offensive work refused until it is filled. The tool-class rules are left untouched.
func (e *Engagement) SetOffensiveRoE(roe OffensiveRoE, now time.Time) error {
	if roe.RiskCeiling != "" && !offensiveRiskCeilingValid(roe.RiskCeiling) {
		return fmt.Errorf("%w: offensive risk ceiling %q must be low, medium, or high", shared.ErrValidation, roe.RiskCeiling)
	}
	e.RoE.Offensive = roe
	e.Audit.UpdatedAt = now
	return nil
}
