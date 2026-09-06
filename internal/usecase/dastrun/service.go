// Package dastrun turns a governed DAST verification probe from a synchronous request-thread execution
// into a durable, lease-executed job. The API Submits a run (persist + enqueue atomically) and returns
// immediately; a worker claims the job and runs the SAME approval-gated, evidence-sealing probe the
// in-process path ran, then records the verdict on the durable run. The approval's single-use consume and
// its evidence seal are unchanged: they still happen exactly once, inside the probe, now on the worker.
package dastrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	ddast "github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// JobKind is the durable job kind for a DAST verification run.
const JobKind = "dast_run"

// Prober runs one governed DAST probe against a consumed approval. *dastworkflow.Service satisfies it.
type Prober interface {
	Run(ctx context.Context, actor string, engagementID, actionID shared.ID, probe dastrunner.Probe) (dastrunner.Result, error)
}

// jobPayload travels with the durable job. It carries the tenant (cross-checked against the ctx tenant),
// the run id, and the probe to execute. The probe binds to the consumed approval by digest, so carrying
// it on the internal queue is safe; it is never persisted on the secret-free run record.
type jobPayload struct {
	TenantID shared.ID        `json:"tenant_id"`
	RunID    shared.ID        `json:"run_id"`
	Probe    dastrunner.Probe `json:"probe"`
}

// Service submits and reads DAST runs (API) and executes them (worker).
type Service struct {
	runs     ports.DASTRunStore
	enqueuer ports.DASTRunEnqueuer
	prober   Prober // nil on the API side (submit/read only); required on the worker
	audit    ports.AuditLogger
	clock    ports.Clock
	ids      ports.IDGenerator
}

// NewService validates dependencies. prober may be nil for a submit/read-only (API) service; it is
// required to execute jobs on the worker.
func NewService(runs ports.DASTRunStore, prober Prober, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if runs == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: DAST run service is missing a dependency", shared.ErrValidation)
	}
	enqueuer, ok := runs.(ports.DASTRunEnqueuer)
	if !ok {
		return nil, fmt.Errorf("%w: DAST run store must support atomic enqueue", shared.ErrValidation)
	}
	return &Service{runs: runs, enqueuer: enqueuer, prober: prober, audit: audit, clock: clock, ids: ids}, nil
}

// Submit persists a queued run and its durable job atomically, then returns the run. The probe is not
// executed here; the worker does, and the worker is where the approval is enforced: prober.Run admits
// through the safety gate, requires the approval decision to be approved, binds the probe to it by digest,
// and consumes it once before probing. Submit does not re-check the approval, so a run for a missing or
// unapproved action enqueues and then fails on the worker rather than at the edge.
func (s *Service) Submit(ctx context.Context, engagementID, actionID shared.ID, actor string, probe dastrunner.Probe) (ddast.Run, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant == "" {
		return ddast.Run{}, fmt.Errorf("%w: DAST run submit requires a tenant in context", shared.ErrValidation)
	}
	// Reject a malformed or credential-bearing target at the edge, before the probe is persisted on the
	// durable job, so an invalid URL fails in-request and never sits at rest in the jobs payload.
	if err := dastrunner.ValidateURL(probe.URL); err != nil {
		return ddast.Run{}, err
	}
	run, err := ddast.NewRun(s.ids.NewID(), tenant, engagementID, actionID, actor, s.clock.Now())
	if err != nil {
		return ddast.Run{}, err
	}
	payload, err := json.Marshal(jobPayload{TenantID: tenant, RunID: run.ID, Probe: probe})
	if err != nil {
		return ddast.Run{}, fmt.Errorf("marshal DAST job: %w", err)
	}
	if err := s.enqueuer.EnqueueDASTRun(ctx, run, JobKind, payload); err != nil {
		_ = s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "dast.run_submit_failed", Target: engagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"run": run.ID.String()}})
		return ddast.Run{}, fmt.Errorf("enqueue DAST run: %w", err)
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "dast.run_submitted", Target: engagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"run": run.ID.String(), "action": actionID.String()}})
	return run, nil
}

// GetRun reads a run's status, tenant-scoped.
func (s *Service) GetRun(ctx context.Context, tenantID, runID shared.ID) (ddast.Run, error) {
	return s.runs.GetDASTRun(shared.WithTenant(ctx, tenantID), tenantID, runID)
}

// RunJob is the worker handler. It loads the run and drives it to a terminal state exactly once, then
// completes the job. The run's own status is the redelivery marker:
//
//   - terminal: a prior delivery already finished it. No-op.
//   - running: a prior delivery started the probe and died before recording the outcome. The probe may
//     have already consumed the single-use approval and moved the judgment score, so it is NEVER
//     re-executed (re-running would double-probe, and re-admitting a consumed approval returns forbidden
//     and would overwrite a real success with a false failure). The run is terminalized "interrupted"
//     via the FinishRun compare-and-set; the operator re-submits, and the approval, if it was never
//     consumed, is still valid.
//   - queued: this delivery owns execution. With no prober (this worker has no live scoped egress) the
//     run is failed "egress_unavailable" so it is operator-visible instead of orphaned in the queue.
//     With a prober, the run is marked running (the redelivery marker above) and the probe executes.
//
// A probe-level error terminalizes the run rather than returning it for retry: the run is running, so the
// queue cannot safely retry it, and a transient pre-consume error is indistinguishable from a
// post-consume one without re-admitting a possibly-consumed approval. The operator re-submits. Only a
// store or tenant error is returned to the queue.
func (s *Service) RunJob(ctx context.Context, payload []byte) error {
	var p jobPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("%w: malformed DAST job", shared.ErrValidation)
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant != p.TenantID {
		return fmt.Errorf("%w: DAST job tenant mismatch", shared.ErrValidation)
	}
	run, err := s.runs.GetDASTRun(ctx, tenant, p.RunID)
	if err != nil {
		return err
	}
	if run.Status.Terminal() {
		return nil // already finished on an earlier delivery
	}
	if run.Status == ddast.RunRunning {
		// A started-but-unrecorded prior attempt. Do not re-run; terminalize deterministically.
		run.Fail("interrupted", s.clock.Now())
		won, ferr := s.runs.FinishRun(ctx, tenant, run)
		if ferr != nil {
			return ferr
		}
		if won {
			_ = s.audit.Record(ctx, ports.AuditEntry{Actor: run.Actor, Action: "dast.run_interrupted", Target: run.EngagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"run": run.ID.String()}})
		}
		return nil
	}
	// run.Status == RunQueued: claim execution with a compare-and-set BEFORE doing anything else. Whoever
	// wins queued -> running owns the run; a redelivered or lease-overlapping worker that loses returns
	// without touching it. This is why both the probe and the no-egress branches sit AFTER the claim: a
	// blind SaveDASTRun here would overwrite a running row a capable peer is already probing (terminal
	// immutability only freezes succeeded/failed), letting a stale worker clobber a live run or hit the
	// target for a run that is already owned.
	if err := run.Start(); err != nil {
		return err
	}
	won, err := s.runs.StartRun(ctx, tenant, run)
	if err != nil {
		return err
	}
	if !won {
		return nil // another delivery owns this run
	}
	if s.prober == nil {
		// This worker has no live scoped egress, so it cannot probe. Having won the claim, it fails the run
		// visibly through the FinishRun CAS instead of orphaning it at queued; the approval, if unconsumed,
		// stays valid for a re-submit. This assumes a homogeneous worker fleet (the norm): a probe cannot
		// run without egress, so a deployment offering DAST runs no egress-less workers. In a heterogeneous
		// fleet an egress-less worker can win the claim for a run a capable peer could have executed; the
		// run fails egress_unavailable and the operator re-submits, which is recoverable, not a lost or
		// clobbered outcome.
		run.Fail("egress_unavailable", s.clock.Now())
		if _, err := s.runs.FinishRun(ctx, tenant, run); err != nil {
			return err
		}
		_ = s.audit.Record(ctx, ports.AuditEntry{Actor: run.Actor, Action: "dast.run_failed", Target: run.EngagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"run": run.ID.String(), "reason": "egress_unavailable"}})
		return nil
	}
	result, runErr := s.prober.Run(ctx, run.Actor, run.EngagementID, run.ActionID, p.Probe)
	if runErr != nil {
		// A transport-level probe error can still carry sealed evidence (the runner seals before returning
		// the error). Preserve the sealed-evidence id and observed status on the failed run so the operator
		// can reach the hash-chained custody record.
		if !result.Evidence.IsZero() {
			run.EvidenceID, run.HTTPStatus = result.Evidence, result.Status
		}
		run.Fail(errorCode(runErr), s.clock.Now())
		won, err := s.runs.FinishRun(ctx, tenant, run)
		if err != nil {
			return err // could not record the failure: let the queue retry the record
		}
		if won {
			_ = s.audit.Record(ctx, ports.AuditEntry{Actor: run.Actor, Action: "dast.run_failed", Target: run.EngagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"run": run.ID.String(), "reason": errorCode(runErr)}})
		}
		return nil // terminal: the approval is consumed, so a retry cannot help
	}
	if err := run.Succeed(string(result.Proof), result.Status, result.Evidence, s.clock.Now()); err != nil {
		// A nil-error result missing its proof class or sealed evidence is not a valid success. The
		// approval is already consumed, so this cannot be retried: terminalize it as a failure rather than
		// returning the error to the queue (which the running-redelivery guard would only turn into
		// "interrupted" anyway).
		run.Fail("invalid_result", s.clock.Now())
		if _, ferr := s.runs.FinishRun(ctx, tenant, run); ferr != nil {
			return ferr
		}
		_ = s.audit.Record(ctx, ports.AuditEntry{Actor: run.Actor, Action: "dast.run_failed", Target: run.EngagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"run": run.ID.String(), "reason": "invalid_result"}})
		return nil
	}
	won, err = s.runs.FinishRun(ctx, tenant, run)
	if err != nil {
		return err
	}
	if won {
		_ = s.audit.Record(ctx, ports.AuditEntry{Actor: run.Actor, Action: "dast.run_completed", Target: run.EngagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"run": run.ID.String(), "verdict": string(result.Proof)}})
	}
	return nil
}

// FailStrandedJob records a run as failed when its job is dead-lettered, so a stranded run does not sit in
// a non-terminal state forever. It writes through SaveDASTRun rather than the FinishRun CAS on purpose: a
// dead-lettered run may be either queued (never started) or running (started by this same worker), and
// FinishRun can only terminalize from running, so it would orphan a queued stranded run. The blind write
// is safe because the worker calls OnDeadLetter only AFTER its fenced queue.Deadletter succeeds, which
// proves this worker still holds the claim at the current fence; no other worker owns the job, so no live
// run of another worker can be clobbered. SaveDASTRun's terminal-immutability still guards the case where a
// terminal outcome was recorded between the Terminal() check and the write.
func (s *Service) FailStrandedJob(ctx context.Context, payload []byte, cause error) error {
	var p jobPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("%w: malformed DAST job", shared.ErrValidation)
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant != p.TenantID {
		return fmt.Errorf("%w: DAST job tenant mismatch", shared.ErrValidation)
	}
	run, err := s.runs.GetDASTRun(ctx, tenant, p.RunID)
	if err != nil {
		return err
	}
	if run.Status.Terminal() {
		return nil
	}
	run.Fail("dead_lettered", s.clock.Now())
	return s.runs.SaveDASTRun(ctx, run)
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, shared.ErrForbidden):
		return "forbidden"
	case errors.Is(err, shared.ErrValidation):
		return "invalid"
	case errors.Is(err, shared.ErrNotFound):
		return "not_found"
	case errors.Is(err, shared.ErrConflict):
		return "conflict"
	default:
		return "run_failed"
	}
}
