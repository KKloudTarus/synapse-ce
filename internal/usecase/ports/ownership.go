package ports

import (
	"context"
	"encoding/json"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type OwnershipMapping struct {
	Mapping  ownership.Mapping
	Revision int
}
type OwnershipAssetMapping struct {
	Mapping  ownership.AssetMapping
	Revision int
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
	Kind                     string // assign, claim, clear, release, route
	TeamID                   shared.ID
	AssigneeID               shared.ID
	LegacyAssignee           string
	ExpectedFindingVersion   int
	ExpectedRevision         int
	ExpectedManualGeneration int64
	PolicyID                 shared.ID
	PolicyVersion            int
	ExpectedPolicyRevision   int
	JobID                    string
	Fence                    int64
	Result                   ownership.Result
	Notify                   bool
	At                       time.Time
}

type OwnershipCurrent struct {
	Assignment      ownership.Assignment
	FindingVersion  int
	FindingAssignee string // authoritative legacy value; detects out-of-boundary writes
	Resolution      ownership.Resolution
	Reason          string
	UpdatedAt       time.Time
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
	ID             shared.ID
	EngagementID   shared.ID
	PolicyID       shared.ID
	PolicyVersion  int
	PolicyRevision int
	PolicyHash     string
	Mode           string
	State          string
	Revision       int
	Cutoff         time.Time
	Total          int
	Processed      int
	Filter         json.RawMessage
	CreatedAt      time.Time
}
type OwnershipRunItem struct {
	RunID             shared.ID
	EngagementID      shared.ID
	FindingID         shared.ID
	FindingVersion    int
	OwnershipRevision int
	ManualGeneration  int64
	Result            ownership.Result
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
