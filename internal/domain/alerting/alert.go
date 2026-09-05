// Package alerting is the domain of operator notifications: the alert a defender receives when the
// platform records something that needs a human, and the rule that decides which events qualify. It
// carries identifiers and a short summary only; a sink never receives raw telemetry or secrets.
package alerting

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Kind names the event an alert reports.
type Kind string

const (
	// KindIncidentCreated: correlation opened a new incident.
	KindIncidentCreated Kind = "incident.created"
	// KindTest: an operator asked the platform to prove the alert path works.
	KindTest Kind = "alert.test"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	return k == KindIncidentCreated || k == KindTest
}

// Alert is one notification. Link is a console path (not an absolute URL) so the receiver can prefix its
// own console origin.
type Alert struct {
	ID           shared.ID       `json:"id"`
	TenantID     shared.ID       `json:"tenant_id"`
	Kind         Kind            `json:"kind"`
	Severity     shared.Severity `json:"severity"`
	Title        string          `json:"title"`
	Summary      string          `json:"summary,omitempty"`
	EngagementID shared.ID       `json:"engagement_id,omitempty"`
	AssetID      shared.ID       `json:"asset_id,omitempty"`
	IncidentID   shared.ID       `json:"incident_id,omitempty"`
	Link         string          `json:"link,omitempty"`
	OccurredAt   time.Time       `json:"occurred_at"`
}

// Validate reports whether the alert is well formed.
func (a Alert) Validate() error {
	switch {
	case a.ID.IsZero():
		return fmt.Errorf("%w: alert id is required", shared.ErrValidation)
	case a.TenantID.IsZero():
		return fmt.Errorf("%w: alert tenant is required", shared.ErrValidation)
	case !a.Kind.Valid():
		return fmt.Errorf("%w: unknown alert kind %q", shared.ErrValidation, a.Kind)
	case !a.Severity.Valid():
		return fmt.Errorf("%w: unknown alert severity %q", shared.ErrValidation, a.Severity)
	case strings.TrimSpace(a.Title) == "":
		return fmt.Errorf("%w: alert title is required", shared.ErrValidation)
	case a.OccurredAt.IsZero():
		return fmt.Errorf("%w: alert time is required", shared.ErrValidation)
	}
	return nil
}

// Rule decides which alerts are delivered. MinSeverity is inclusive; an unknown severity never matches,
// because an event the platform could not rate is not something to page a human about.
type Rule struct {
	MinSeverity shared.Severity
}

// DefaultRule delivers medium and above.
func DefaultRule() Rule { return Rule{MinSeverity: shared.SeverityMedium} }

// Validate reports whether the rule is well formed.
func (r Rule) Validate() error {
	if !r.MinSeverity.Valid() || r.MinSeverity == shared.SeverityUnknown {
		return fmt.Errorf("%w: alert minimum severity %q is not one of critical, high, medium, low, info", shared.ErrValidation, r.MinSeverity)
	}
	return nil
}

// Matches reports whether the alert clears the rule. A test alert always matches so an operator can
// verify delivery regardless of the threshold.
func (r Rule) Matches(a Alert) bool {
	if a.Kind == KindTest {
		return true
	}
	if a.Severity == shared.SeverityUnknown || !a.Severity.Valid() {
		return false
	}
	return shared.SeverityRank(a.Severity) >= shared.SeverityRank(r.MinSeverity)
}
