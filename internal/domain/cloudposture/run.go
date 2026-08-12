package cloudposture

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RunStatus is the durable CSPM execution lifecycle.
type RunStatus string

const (
	RunQueued    RunStatus = "queued"
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunPartial   RunStatus = "partial"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

func (s RunStatus) Valid() bool {
	switch s {
	case RunQueued, RunRunning, RunSucceeded, RunPartial, RunFailed, RunCancelled:
		return true
	}
	return false
}

func (s RunStatus) Terminal() bool {
	return s == RunSucceeded || s == RunPartial || s == RunFailed || s == RunCancelled
}

type EvidenceReference struct {
	ScopeKey string    `json:"scope_key"`
	ID       shared.ID `json:"id"`
	Hash     string    `json:"hash"`
}

// Run is the durable, secret-free record returned by the CSPM API.
type Run struct {
	ID             shared.ID           `json:"id"`
	TenantID       shared.ID           `json:"-"`
	EngagementID   shared.ID           `json:"engagement_id"`
	Actor          string              `json:"actor"`
	Status         RunStatus           `json:"status"`
	Complete       bool                `json:"complete"`
	Assets         int                 `json:"assets"`
	Findings       int                 `json:"findings"`
	CoverageIssues []CoverageIssue     `json:"coverage_issues,omitempty"`
	ErrorCode      string              `json:"error_code,omitempty"`
	EvidenceRefs   []EvidenceReference `json:"evidence_refs,omitempty"`
	StartedAt      time.Time           `json:"started_at"`
	FinishedAt     *time.Time          `json:"finished_at,omitempty"`
}

func (r Run) Validate() error {
	if r.ID.IsZero() || r.TenantID.IsZero() || r.EngagementID.IsZero() || !r.Status.Valid() || r.StartedAt.IsZero() {
		return fmt.Errorf("%w: invalid CSPM run", shared.ErrValidation)
	}
	if r.Status.Terminal() != (r.FinishedAt != nil) {
		return fmt.Errorf("%w: CSPM terminal timestamp does not match status", shared.ErrValidation)
	}
	return nil
}
