package engagement

import (
	"fmt"
	"strings"
	"time"

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

// SetRoE validates and sets the rules of engagement, stamping UpdatedAt. Each
// blackout must have end >= start.
func (e *Engagement) SetRoE(roe RoE, now time.Time) error {
	for _, b := range roe.Blackouts {
		if b.To.Before(b.From) {
			return fmt.Errorf("%w: blackout end must not be before its start", shared.ErrValidation)
		}
	}
	e.RoE = roe
	e.Audit.UpdatedAt = now
	return nil
}
