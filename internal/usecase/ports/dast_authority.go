package ports

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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

// DASTScanJob is the immutable secret-free payload atomically enqueued with a scan run.
type DASTScanJob struct {
	TenantID     shared.ID       `json:"tenant_id"`
	RunID        shared.ID       `json:"run_id"`
	Config       json.RawMessage `json:"config"`
	ConfigSHA256 string          `json:"config_sha256"`
	HelperPath   string          `json:"helper_path"`
	HelperSHA256 string          `json:"helper_sha256"`
}

// DASTScanExecution identifies the actual queue claim, not the approval's content digest.
type DASTScanExecution struct {
	TenantID shared.ID
	RunID    shared.ID
	JobID    string
	Fence    int64
}

// ExecutionID encodes the full claim identity for the egress authority boundary.
func (e DASTScanExecution) ExecutionID() (string, error) {
	if e.TenantID.IsZero() || len(e.TenantID.String()) > 200 || e.RunID.IsZero() || len(e.RunID.String()) > 200 || e.JobID == "" || len(e.JobID) > 200 || e.Fence < 1 {
		return "", fmt.Errorf("%w: invalid DAST scan execution", shared.ErrValidation)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	id := "v1." + base64.RawURLEncoding.EncodeToString(b)
	if len(id) > MaxEgressExecutionIDLength {
		return "", fmt.Errorf("%w: DAST scan execution is too long", shared.ErrValidation)
	}
	return id, nil
}

func ParseDASTScanExecutionID(id string) (DASTScanExecution, error) {
	var e DASTScanExecution
	if len(id) > MaxEgressExecutionIDLength || !strings.HasPrefix(id, "v1.") {
		return e, fmt.Errorf("%w: invalid DAST scan execution", shared.ErrValidation)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, "v1."))
	if err != nil {
		return e, fmt.Errorf("%w: invalid DAST scan execution", shared.ErrValidation)
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return DASTScanExecution{}, fmt.Errorf("%w: invalid DAST scan execution", shared.ErrValidation)
	}
	canonical, err := e.ExecutionID()
	if err != nil || canonical != id {
		return DASTScanExecution{}, fmt.Errorf("%w: invalid DAST scan execution", shared.ErrValidation)
	}
	return e, nil
}

// DASTScanRunStore binds start and terminal writes to the live queue claim.
// Implementations must compare the persisted job payload, kind, tenant, run and
// unexpired claim/fence in the same independent tenant transaction as the write.
type DASTScanRunStore interface {
	StartDASTScan(context.Context, DASTScanExecution, DASTScanJob) (bool, error)
	FinishDASTScan(context.Context, DASTScanExecution, dastrun.Run) (bool, error)
	// InterruptDASTScan terminalizes a previously started run under the current
	// live claim, never re-executes it. The caller must first acquire the leased
	// run lock; a live peer yields ErrRetryable. The store verifies the current
	// claim and that the persisted owner differs, without adopting that owner.
	InterruptDASTScan(context.Context, DASTScanExecution, time.Time) (bool, error)
	// FailDeadLetteredDASTScan resolves the run from the persisted job ID,
	// never from untrusted payload. It requires the same deadlettered queue
	// fence and preserves terminal rows and previous owner/approval/issuance.
	// An absent approval does not prevent failure-only cleanup. The failed job
	// is no longer a live owner and cannot publish or issue grants.
	FailDeadLetteredDASTScan(context.Context, QueuedJob, string, time.Time) (bool, error)
	// WithDASTScanOwner runs fn in an independent tenant transaction under a
	// locked, still-live job claim and running scan owned by this execution.
	// The callback's custody writes commit atomically with these checks. Callers
	// reauthorize scope and window before and after publication inside fn.
	WithDASTScanOwner(context.Context, DASTScanExecution, func(context.Context) error) error
}

type DASTScanAuthorization struct {
	Run         dastrun.Run
	Job         DASTScanJob
	Execution   DASTScanExecution
	Action      agent.ProposedAction
	Decision    agent.ApprovalDecision
	ConsumedBy  shared.ID
	Admission   evidence.Evidence
	Consumption evidence.Evidence
	GrantIssued bool
}

// DASTScanAuthority independently validates and irrevocably claims one scan grant.
type DASTScanAuthority interface {
	GetDASTScanAuthorization(context.Context, DASTScanExecution) (DASTScanAuthorization, error)
	// authorize is called inside the independent locked claim transaction just
	// before irreversible issuance. Implementations recheck claim/lease after it.
	ClaimDASTScanGrant(context.Context, DASTScanAuthorization, time.Time, func(context.Context) error) error
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
