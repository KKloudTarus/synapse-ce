// Package dastrun is the durable record of a governed DAST verification run. A DAST probe used to execute
// synchronously in the API request goroutine; this makes the run a durable, lease-executed job so the
// request returns immediately, the run survives a control-plane restart, and its outcome is pollable. The
// record is secret-free: it carries the verdict class and the sealed-evidence id, never the probe body or
// any response content.
package dastrun

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RunStatus is the durable DAST run lifecycle. A probe is a single verification, so there is no partial
// state: it is queued, running, then succeeded (the probe ran and produced a verdict) or failed.
type RunStatus string

const (
	RunQueued    RunStatus = "queued"
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
)

func (s RunStatus) Valid() bool {
	switch s {
	case RunQueued, RunRunning, RunSucceeded, RunFailed:
		return true
	}
	return false
}

func (s RunStatus) Terminal() bool { return s == RunSucceeded || s == RunFailed }

// Run is the durable, secret-free record the DAST run API returns.
type Run struct {
	ID           shared.ID `json:"id"`
	TenantID     shared.ID `json:"-"`
	EngagementID shared.ID `json:"engagement_id"`
	ActionID     shared.ID `json:"action_id"`
	Actor        string    `json:"actor"`
	Status       RunStatus `json:"status"`
	// Verdict is the verification's proof class (e.g. confirmed / refuted / inconclusive); empty until the
	// run reaches a terminal state.
	Verdict string `json:"verdict,omitempty"`
	// HTTPStatus is the probe's observed response status; zero until observed.
	HTTPStatus int `json:"http_status,omitempty"`
	// EvidenceID is the sealed evidence the run produced; zero when the run failed before sealing.
	EvidenceID shared.ID  `json:"evidence_id,omitempty"`
	ErrorCode  string     `json:"error_code,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// NewRun builds a queued run. The action is the consumed DAST approval the probe binds to.
func NewRun(id, tenantID, engagementID, actionID shared.ID, actor string, now time.Time) (Run, error) {
	if id.IsZero() || tenantID.IsZero() || engagementID.IsZero() || actionID.IsZero() || actor == "" || now.IsZero() {
		return Run{}, fmt.Errorf("%w: DAST run needs id, tenant, engagement, action, actor, and time", shared.ErrValidation)
	}
	return Run{ID: id, TenantID: tenantID, EngagementID: engagementID, ActionID: actionID, Actor: actor, Status: RunQueued, StartedAt: now.UTC()}, nil
}

// Start moves a queued run to running.
func (r *Run) Start() error {
	if r.Status != RunQueued {
		return fmt.Errorf("%w: DAST run %s is %s, not queued", shared.ErrConflict, r.ID, r.Status)
	}
	r.Status = RunRunning
	return nil
}

// Succeed records the verdict of a completed probe. A successful run always carries a sealed verdict and
// its evidence: a governed probe that produced no sealed evidence is not a success, so an empty verdict or
// evidence id is refused rather than recorded as a hollow success.
func (r *Run) Succeed(verdict string, httpStatus int, evidenceID shared.ID, now time.Time) error {
	if r.Status != RunRunning {
		return fmt.Errorf("%w: DAST run %s is %s, not running", shared.ErrConflict, r.ID, r.Status)
	}
	if verdict == "" || evidenceID.IsZero() {
		return fmt.Errorf("%w: DAST run %s cannot succeed without a verdict and sealed evidence", shared.ErrValidation, r.ID)
	}
	t := now.UTC()
	r.Status, r.Verdict, r.HTTPStatus, r.EvidenceID, r.FinishedAt = RunSucceeded, verdict, httpStatus, evidenceID, &t
	return nil
}

// Fail records a terminal failure with a machine reason.
func (r *Run) Fail(code string, now time.Time) {
	t := now.UTC()
	r.Status, r.ErrorCode, r.FinishedAt = RunFailed, code, &t
}

// Validate enforces the record invariants.
func (r Run) Validate() error {
	if r.ID.IsZero() || r.TenantID.IsZero() || r.EngagementID.IsZero() || r.ActionID.IsZero() || r.Actor == "" || !r.Status.Valid() || r.StartedAt.IsZero() {
		return fmt.Errorf("%w: invalid DAST run", shared.ErrValidation)
	}
	if r.Status.Terminal() != (r.FinishedAt != nil) {
		return fmt.Errorf("%w: DAST run terminal timestamp does not match status %s", shared.ErrValidation, r.Status)
	}
	if r.Status == RunSucceeded && (r.Verdict == "" || r.EvidenceID.IsZero()) {
		return fmt.Errorf("%w: a succeeded DAST run must carry a verdict and sealed evidence", shared.ErrValidation)
	}
	return nil
}
