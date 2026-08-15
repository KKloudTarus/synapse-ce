package sla

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RemediationStatus is independent of finding validity/triage. A finding can remain confirmed while
// its remediation moves open -> mitigating -> remediated, and accepting risk never relabels a real
// vulnerability as a false positive.
type RemediationStatus string

const (
	RemediationOpen         RemediationStatus = "open"
	RemediationMitigating   RemediationStatus = "mitigating"
	RemediationRemediated   RemediationStatus = "remediated"
	RemediationAcceptedRisk RemediationStatus = "accepted_risk"
)

func (s RemediationStatus) Valid() bool {
	return s == RemediationOpen || s == RemediationMitigating || s == RemediationRemediated || s == RemediationAcceptedRisk
}

// Lifecycle is the current human-owned remediation state. Machine risk refreshes may update the
// current AssessmentID but must preserve every other field. Version protects transitions from lost
// updates. Acceptance is effective only before AcceptanceExpiresAt.
type Lifecycle struct {
	TenantID            shared.ID         `json:"tenant_id"`
	EngagementID        shared.ID         `json:"engagement_id"`
	FindingID           shared.ID         `json:"finding_id"`
	AssessmentID        shared.ID         `json:"assessment_id"`
	Status              RemediationStatus `json:"status"`
	Version             int               `json:"version"`
	Reason              string            `json:"reason,omitempty"`
	CompensatingControl string            `json:"compensating_control,omitempty"`
	AcceptedBy          string            `json:"accepted_by,omitempty"`
	AcceptedAt          *time.Time        `json:"accepted_at,omitempty"`
	AcceptanceExpiresAt *time.Time        `json:"acceptance_expires_at,omitempty"`
	UpdatedBy           string            `json:"updated_by"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// NewLifecycle creates the default human workflow state alongside the first SLA assessment.
func NewLifecycle(a Assessment, now time.Time) (Lifecycle, error) {
	if err := a.Validate(); err != nil {
		return Lifecycle{}, err
	}
	if now.IsZero() {
		return Lifecycle{}, fmt.Errorf("%w: sla lifecycle time is required", shared.ErrValidation)
	}
	return Lifecycle{
		TenantID: a.TenantID, EngagementID: a.EngagementID, FindingID: a.FindingID,
		AssessmentID: a.ID, Status: RemediationOpen, Version: 1,
		UpdatedBy: "system:sla", UpdatedAt: now.UTC(),
	}, nil
}

func (s Lifecycle) Validate() error {
	if s.TenantID.IsZero() || s.EngagementID.IsZero() || s.FindingID.IsZero() || s.AssessmentID.IsZero() ||
		!s.Status.Valid() || s.Version < 1 || strings.TrimSpace(s.UpdatedBy) == "" || s.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: sla lifecycle is invalid", shared.ErrValidation)
	}
	if s.Status == RemediationAcceptedRisk {
		if strings.TrimSpace(s.Reason) == "" || strings.TrimSpace(s.CompensatingControl) == "" ||
			strings.TrimSpace(s.AcceptedBy) == "" || s.AcceptedAt == nil || s.AcceptanceExpiresAt == nil ||
			!s.AcceptanceExpiresAt.After(*s.AcceptedAt) {
			return fmt.Errorf("%w: accepted risk requires reason, control, human, and future expiry", shared.ErrValidation)
		}
	} else if s.AcceptedAt != nil || s.AcceptanceExpiresAt != nil || s.AcceptedBy != "" {
		return fmt.Errorf("%w: non-accepted sla lifecycle carries acceptance metadata", shared.ErrValidation)
	}
	return nil
}

// EffectiveStatus makes expiry fail-safe without relying on a background scheduler. The durable
// acceptance event stays auditable, while every read/gate treats an expired acceptance as open.
func (s Lifecycle) EffectiveStatus(now time.Time) RemediationStatus {
	if s.Status == RemediationAcceptedRisk && (s.AcceptanceExpiresAt == nil || !now.UTC().Before(s.AcceptanceExpiresAt.UTC())) {
		return RemediationOpen
	}
	return s.Status
}

// TransitionCommand is a human remediation decision guarded by ExpectedVersion.
type TransitionCommand struct {
	To                  RemediationStatus `json:"to"`
	Reason              string            `json:"reason"`
	CompensatingControl string            `json:"compensating_control,omitempty"`
	AcceptanceExpiresAt *time.Time        `json:"acceptance_expires_at,omitempty"`
	Actor               string            `json:"actor"`
	ExpectedVersion     int               `json:"expected_version"`
}

// LifecycleEvent is append-only evidence of one state transition.
type LifecycleEvent struct {
	TenantID            shared.ID         `json:"tenant_id"`
	ID                  shared.ID         `json:"id"`
	EngagementID        shared.ID         `json:"engagement_id"`
	FindingID           shared.ID         `json:"finding_id"`
	AssessmentID        shared.ID         `json:"assessment_id"`
	From                RemediationStatus `json:"from"`
	To                  RemediationStatus `json:"to"`
	Reason              string            `json:"reason"`
	CompensatingControl string            `json:"compensating_control,omitempty"`
	AcceptanceExpiresAt *time.Time        `json:"acceptance_expires_at,omitempty"`
	Actor               string            `json:"actor"`
	BeforeVersion       int               `json:"before_version"`
	AfterVersion        int               `json:"after_version"`
	At                  time.Time         `json:"at"`
}

// ApplyTransition validates a human-only decision and returns the next state plus append-only event.
// Remediated is terminal for manual transitions: a later intelligence re-exposure creates review work
// through #540 but never silently reopens the finding.
func ApplyTransition(current Lifecycle, eventID shared.ID, cmd TransitionCommand, now time.Time) (Lifecycle, LifecycleEvent, error) {
	if err := current.Validate(); err != nil {
		return Lifecycle{}, LifecycleEvent{}, err
	}
	cmd.Actor, cmd.Reason, cmd.CompensatingControl = strings.TrimSpace(cmd.Actor), strings.TrimSpace(cmd.Reason), strings.TrimSpace(cmd.CompensatingControl)
	if eventID.IsZero() || now.IsZero() || !cmd.To.Valid() || cmd.Reason == "" || cmd.ExpectedVersion != current.Version {
		if cmd.ExpectedVersion != current.Version {
			return Lifecycle{}, LifecycleEvent{}, fmt.Errorf("sla lifecycle changed since it was loaded: %w", shared.ErrConflict)
		}
		return Lifecycle{}, LifecycleEvent{}, fmt.Errorf("%w: sla transition identity, state, reason, and time are required", shared.ErrValidation)
	}
	if shared.IsMachineActor(cmd.Actor) {
		return Lifecycle{}, LifecycleEvent{}, fmt.Errorf("%w: sla remediation decisions require a human principal", shared.ErrValidation)
	}
	from := current.EffectiveStatus(now)
	if from == RemediationRemediated && cmd.To != RemediationRemediated {
		return Lifecycle{}, LifecycleEvent{}, fmt.Errorf("%w: remediated sla state cannot be silently reopened", shared.ErrValidation)
	}
	if from == cmd.To && !(current.Status == RemediationAcceptedRisk && from == RemediationOpen) {
		return Lifecycle{}, LifecycleEvent{}, fmt.Errorf("%w: sla transition must change effective state", shared.ErrValidation)
	}
	if cmd.To == RemediationAcceptedRisk {
		if cmd.CompensatingControl == "" || cmd.AcceptanceExpiresAt == nil || !cmd.AcceptanceExpiresAt.After(now.UTC()) {
			return Lifecycle{}, LifecycleEvent{}, fmt.Errorf("%w: accepted risk requires a compensating control and future expiry", shared.ErrValidation)
		}
	}

	next := current
	next.Status, next.Version, next.Reason = cmd.To, current.Version+1, cmd.Reason
	next.UpdatedBy, next.UpdatedAt = cmd.Actor, now.UTC()
	next.CompensatingControl, next.AcceptedBy, next.AcceptedAt, next.AcceptanceExpiresAt = "", "", nil, nil
	if cmd.To == RemediationAcceptedRisk {
		at, expiry := now.UTC(), cmd.AcceptanceExpiresAt.UTC()
		next.CompensatingControl, next.AcceptedBy = cmd.CompensatingControl, cmd.Actor
		next.AcceptedAt, next.AcceptanceExpiresAt = &at, &expiry
	}
	if err := next.Validate(); err != nil {
		return Lifecycle{}, LifecycleEvent{}, err
	}
	event := LifecycleEvent{
		TenantID: current.TenantID, ID: eventID, EngagementID: current.EngagementID, FindingID: current.FindingID,
		AssessmentID: current.AssessmentID, From: current.Status, To: cmd.To, Reason: cmd.Reason,
		CompensatingControl: cmd.CompensatingControl, AcceptanceExpiresAt: next.AcceptanceExpiresAt,
		Actor: cmd.Actor, BeforeVersion: current.Version, AfterVersion: next.Version, At: now.UTC(),
	}
	return next, event, nil
}

// View joins current immutable assessment and human lifecycle for API/CLI/report consumption.
type View struct {
	Assessment     Assessment        `json:"assessment"`
	Lifecycle      Lifecycle         `json:"lifecycle"`
	EffectiveState RemediationStatus `json:"effective_state"`
	Overdue        bool              `json:"overdue"`
	Expired        bool              `json:"acceptance_expired"`
}

// Current is the durable aggregate returned by SLA stores. Keeping the join explicit lets the
// use-case calculate time-sensitive expiry/overdue fields at read time rather than persisting values
// that become stale. It also gives adapters one shape for atomic current-assessment/lifecycle reads.
type Current struct {
	Assessment Assessment `json:"assessment"`
	Lifecycle  Lifecycle  `json:"lifecycle"`
}

// View calculates the time-sensitive projection of a durable current record.
func (c Current) View(now time.Time) (View, error) {
	return NewView(c.Assessment, c.Lifecycle, now)
}

func NewView(a Assessment, state Lifecycle, now time.Time) (View, error) {
	if err := a.Validate(); err != nil {
		return View{}, err
	}
	if err := state.Validate(); err != nil {
		return View{}, err
	}
	if a.TenantID != state.TenantID || a.EngagementID != state.EngagementID || a.FindingID != state.FindingID || state.AssessmentID != a.ID {
		return View{}, fmt.Errorf("%w: sla assessment and lifecycle ownership differ", shared.ErrValidation)
	}
	effective := state.EffectiveStatus(now)
	expired := state.Status == RemediationAcceptedRisk && effective == RemediationOpen
	overdue := effective != RemediationRemediated && effective != RemediationAcceptedRisk && !now.UTC().Before(a.Result.RemediateBy.UTC())
	return View{Assessment: a, Lifecycle: state, EffectiveState: effective, Overdue: overdue, Expired: expired}, nil
}
