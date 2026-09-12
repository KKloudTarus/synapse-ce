package ports

import (
	"context"
	"encoding/json"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type OwnershipMapping struct {
	Mapping  ownership.Mapping `json:"mapping"`
	Revision int               `json:"revision"`
}
type OwnershipAssetMapping struct {
	Mapping  ownership.AssetMapping `json:"mapping"`
	Revision int                    `json:"revision"`
}
type OwnershipPolicy struct {
	Version  ownership.PolicyVersion
	Revision int
}
type OwnershipActivation struct {
	PolicyID         shared.ID
	Version          int // zero deactivates; immutable versions remain readable
	ExpectedRevision int
	ExpectedHash     string
}

// OwnershipMutation is a single atomic assignment/decision/audit/outbox commit.
// Route requires an active policy and a live ownership.route job fence. The API
// must authorize the engagement; the repository also verifies user eligibility.
type OwnershipMutation struct {
	EngagementID             shared.ID
	Repository               string
	FindingID                shared.ID
	DecisionID               shared.ID
	Key                      string
	Actor                    string
	Kind                     string // assign, transfer, claim, clear, release, route
	TeamID                   shared.ID
	AssigneeID               shared.ID
	LegacyAssignee           string
	ExpectedFindingVersion   int
	ExpectedRevision         int
	ExpectedManualGeneration int64
	ExpectedBindingHash      string // empty only for compatibility/manual mutations
	PolicyID                 shared.ID
	PolicyVersion            int
	ExpectedPolicyRevision   int
	JobID                    string
	Fence                    int64
	Result                   ownership.Result
	Notify                   bool
	LegacyEndpoint           bool // legacy assignment always advances the finding version
	ClearAssignee            bool // transfer requires explicit consent to drop an assignee
	At                       time.Time
}

type OwnershipCurrent struct {
	Assignment      ownership.Assignment `json:"assignment"`
	FindingVersion  int                  `json:"finding_version"`
	FindingAssignee string               `json:"finding_assignee"` // authoritative legacy value; detects out-of-boundary writes
	Resolution      ownership.Resolution `json:"resolution"`
	Reason          string               `json:"reason"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

type OwnershipIntent struct {
	ID           shared.ID
	EngagementID shared.ID
	FindingID    shared.ID
	Kind         string
	SourceKey    string
	DecisionID   shared.ID
	Payload      json.RawMessage
	State        string
	CreatedAt    time.Time
}

type OwnershipRun struct {
	ID             shared.ID       `json:"id"`
	EngagementID   shared.ID       `json:"engagement_id"`
	PolicyID       shared.ID       `json:"policy_id"`
	PolicyVersion  int             `json:"policy_version"`
	PolicyRevision int             `json:"policy_revision"`
	PolicyHash     string          `json:"policy_hash"`
	Mode           string          `json:"mode"`
	State          string          `json:"state"`
	Revision       int             `json:"revision"`
	Cutoff         time.Time       `json:"cutoff"`
	Total          int             `json:"total"`
	Processed      int             `json:"processed"`
	Filter         json.RawMessage `json:"filter"`
	CreatedAt      time.Time       `json:"created_at"`
}
type OwnershipRunItem struct {
	Outcome           string           `json:"outcome,omitempty"`
	RunID             shared.ID        `json:"run_id"`
	EngagementID      shared.ID        `json:"engagement_id"`
	FindingID         shared.ID        `json:"finding_id"`
	FindingVersion    int              `json:"finding_version"`
	OwnershipRevision int              `json:"ownership_revision"`
	ManualGeneration  int64            `json:"manual_generation"`
	Result            ownership.Result `json:"result"`
}
type OwnershipHistoryCursor struct {
	Before   time.Time
	BeforeID shared.ID
	Limit    int
}

// Every operation requires shared.WithTenant context; row IDs in arguments never
// establish tenant authority. Implementations participate in TenantTransactionRunner.
type OwnershipRepository interface {
	CreateTeam(context.Context, ownership.Team) (ownership.Team, error)
	UpdateTeam(context.Context, ownership.Team, int) (ownership.Team, error)
	GetTeam(context.Context, shared.ID) (ownership.Team, error)
	ListTeams(context.Context, shared.ID, int) ([]ownership.Team, error)
	AddMember(context.Context, shared.ID, shared.ID, time.Time) error
	RemoveMember(context.Context, shared.ID, shared.ID) error
	ListMembers(context.Context, shared.ID, shared.ID, int) ([]ownership.Membership, error)
	SaveMapping(context.Context, shared.ID, OwnershipMapping) error
	DeleteMapping(context.Context, shared.ID, string, string, int) error
	ListMappings(context.Context, shared.ID, string, string, int) ([]OwnershipMapping, error)
	SaveAssetMapping(context.Context, OwnershipAssetMapping) error
	DeleteAssetMapping(context.Context, shared.ID, int) error
	ListAssetMappings(context.Context, shared.ID, int) ([]OwnershipAssetMapping, error)
	CreateSnapshot(context.Context, ownership.Snapshot) error
	GetSnapshot(context.Context, shared.ID) (ownership.Snapshot, error)
	CreatePolicyVersion(context.Context, ownership.PolicyVersion) error
	GetPolicyVersion(context.Context, shared.ID, int) (ownership.PolicyVersion, error)
	GetActivePolicy(context.Context, shared.ID, string) (OwnershipPolicy, error)
	ActivatePolicy(context.Context, OwnershipActivation) error
	GetAssignment(context.Context, shared.ID, shared.ID) (OwnershipCurrent, error)
	ApplyAssignment(context.Context, OwnershipMutation) (ownership.Decision, error)
	ListDecisions(context.Context, shared.ID, shared.ID, OwnershipHistoryCursor) ([]ownership.Decision, error)
	AppendIntent(context.Context, OwnershipIntent) error
	ListPendingIntents(context.Context, string, int) ([]OwnershipIntent, error)
	CompleteIntent(context.Context, shared.ID) error
	CreateRun(context.Context, OwnershipRun) error
	GetRun(context.Context, shared.ID) (OwnershipRun, error)
	SaveRunItems(context.Context, shared.ID, int, []OwnershipRunItem) error
	ListRunItems(context.Context, shared.ID, shared.ID, int) ([]OwnershipRunItem, error)
	SetRunState(context.Context, shared.ID, int, string) error
}
