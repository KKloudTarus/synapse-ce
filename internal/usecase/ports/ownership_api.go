package ports

import (
	"context"
	"encoding/json"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

type OwnershipPolicyHeader struct {
	ID            shared.ID `json:"id"`
	EngagementID  shared.ID `json:"engagement_id"`
	Repository    string    `json:"repository"`
	Revision      int       `json:"revision"`
	ActiveVersion int       `json:"active_version"`
	LatestVersion int       `json:"latest_version"`
}

type OwnershipInboxFilter struct {
	EngagementID shared.ID       `json:"engagement_id,omitempty"`
	TeamID       shared.ID       `json:"team_id,omitempty"`
	AssigneeID   shared.ID       `json:"assignee_id,omitempty"`
	MemberID     shared.ID       `json:"-"` // authenticated actor; never supplied by the client
	MyTeams      bool            `json:"my_teams,omitempty"`
	Unresolved   bool            `json:"unresolved,omitempty"`
	Severity     shared.Severity `json:"severity,omitempty"`
	Status       finding.Status  `json:"status,omitempty"`
	Kind         string          `json:"kind,omitempty"`
	SLAStatus    string          `json:"sla_status,omitempty"`
	DueBefore    *time.Time      `json:"due_before,omitempty"`
	After        shared.ID       `json:"-"`
	Limit        int             `json:"-"`
}

type OwnershipInboxItem struct {
	ID           shared.ID            `json:"id"`
	EngagementID shared.ID            `json:"engagement_id"`
	Title        string               `json:"title"`
	Severity     shared.Severity      `json:"severity"`
	Status       finding.Status       `json:"status"`
	Kind         string               `json:"kind"`
	Version      int                  `json:"version"`
	Assignment   ownership.Assignment `json:"assignment"`
	Resolution   ownership.Resolution `json:"resolution"`
	Reason       string               `json:"reason"`
	SLAStatus    string               `json:"sla_status,omitempty"`
	RemediateBy  *time.Time           `json:"remediate_by,omitempty"`
}
type OwnershipInboxPage struct {
	Items []OwnershipInboxItem `json:"items"`
	Total int                  `json:"total"`
	Next  string               `json:"next,omitempty"`
}

// OwnershipReader applies the same visibility as normal engagement reads:
// tenant predicate plus exclusion of hidden project/host scan contexts. Counts
// and pages must share that predicate. Authorization rechecks the persisted user.
type OwnershipReader interface {
	AuthorizeOwnership(context.Context, shared.ID, user.Permission) error
	VisibleOwnershipEngagement(context.Context, shared.ID) error
	ListOwnershipSnapshots(context.Context, shared.ID, shared.ID, int) ([]ownership.Snapshot, error)
	GetOwnershipPolicy(context.Context, shared.ID) (OwnershipPolicyHeader, error)
	ListOwnershipPolicies(context.Context, shared.ID, shared.ID, int) ([]OwnershipPolicyHeader, error)
	OwnershipInbox(context.Context, OwnershipInboxFilter) (OwnershipInboxPage, error)
	ReserveOwnershipBulk(context.Context, shared.ID, string, string, time.Time) error
}

// A run starter is wired only alongside its production worker. Admission must
// atomically persist the run and its queue obligation, never acknowledge a job
// that cannot be executed. API authorization/validation precedes this port.
type OwnershipRunRequest struct {
	Policy  OwnershipPolicyHeader
	Version ownership.PolicyVersion
	Actor   shared.ID
	Key     string
	Mode    string
	Filter  json.RawMessage
}
type OwnershipRunStarter interface {
	StartOwnershipRun(context.Context, OwnershipRunRequest) (OwnershipRun, error)
}

type FindingAssigneeWriter interface {
	SetLegacyAssignee(context.Context, shared.ID, shared.ID, string, string, int) (finding.Finding, error)
}
