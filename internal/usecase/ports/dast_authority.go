package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastprobe"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DASTRunJob is the original, atomically queued verifier configuration.
type DASTRunJob struct {
	TenantID shared.ID       `json:"tenant_id"`
	RunID    shared.ID       `json:"run_id"`
	Probe    dastprobe.Probe `json:"probe"`
}

// DASTApprovalConsumer binds a consumed approval to exactly one durable run.
// Durable callers must use this capability inside the custody transaction;
// absence must never fall back to the synchronous Consume operation.
type DASTApprovalConsumer interface {
	ConsumeForDASTRun(ctx context.Context, actionID, runID shared.ID) error
}

// DASTRunAuthorization contains persisted authority, never requester metadata.
// The evidence records are targeted indexed reads, not an engagement-wide scan.
type DASTRunAuthorization struct {
	Run         dastrun.Run
	Job         DASTRunJob
	Action      agent.ProposedAction
	Decision    agent.ApprovalDecision
	ConsumedBy  shared.ID
	Admission   evidence.Evidence
	Consumption evidence.Evidence
	GrantIssued bool
}

// DASTRunAuthority is the durable, single-use verifier grant boundary.
type DASTRunAuthority interface {
	GetDASTRunAuthorization(ctx context.Context, tenantID, runID shared.ID) (DASTRunAuthorization, error)
	// ClaimDASTRunGrant commits independently, rechecking the complete expected
	// authority and running owner under locks. Only one caller may succeed.
	// Success means committed; uncertain commit, lost response and restart must
	// never reset issuance. No signed token may escape before this returns nil.
	ClaimDASTRunGrant(ctx context.Context, expected DASTRunAuthorization, at time.Time) error
}

// DASTConsumptionEvidenceID gives each run one immutable indexed custody record.
func DASTConsumptionEvidenceID(runID shared.ID) shared.ID {
	return shared.ID(runID.String() + "-approval-consumed")
}

type DASTApprovalConsumption struct {
	TenantID     shared.ID `json:"tenant_id"`
	EngagementID shared.ID `json:"engagement_id"`
	RunID        shared.ID `json:"run_id"`
	ActionID     shared.ID `json:"action_id"`
	Actor        string    `json:"actor"`
	AdmissionID  shared.ID `json:"admission_id"`
}
