package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	devidence "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	drecon "github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// reconStarter is the narrow slice of the recon use-case the executor drives: start a run and
// poll it. The concrete *recon.Service satisfies it; the orchestrator stays off usecase/recon.
type reconStarter interface {
	Start(ctx context.Context, actor string, engagementID shared.ID, tool, target string) (drecon.Run, error)
	Get(ctx context.Context, id shared.ID) (drecon.Run, error)
}

// evidenceLister reads the engagement's evidence chain (to recover a finished run's sealed
// raw output, which recon stores only as a terminal_log link – not in the run record).
type evidenceLister interface {
	List(ctx context.Context, engagementID shared.ID) ([]devidence.Evidence, error)
}

// ReconExecutor is the production Executor: it runs an admitted action by dispatching
// to the sandboxed recon use-case and polling the run to completion, then recovers the sealed
// tool output to feed back to the model. A TOOL-LEVEL failure (run failed, live recon
// disabled, scope re-check) is returned as an Observation – fed back so the model can adapt,
// NOT a hard error that aborts the whole agent run. Only orchestration failures (context
// cancelled, the run record cannot be polled) return an error.
//
// IMPORTANT (composition): the recon service handed here MUST be dispatcher-backed (in-process
// pool), not queue-backed – otherwise an agent running on the same worker that must also claim
// the recon job would self-deadlock (the blocking poll starves the claim loop). The agent and
// HTTP recon therefore use distinct recon.Service instances, or run on separate workers.
type ReconExecutor struct {
	recon    reconStarter
	evidence evidenceLister
	clock    ports.Clock
	poll     time.Duration // poll interval while a run is in flight
	timeout  time.Duration // max wall-clock to wait for a run to finish
}

var _ Executor = (*ReconExecutor)(nil)

// NewReconExecutor validates deps and applies poll/timeout defaults.
func NewReconExecutor(recon reconStarter, evidence evidenceLister, clock ports.Clock, poll, timeout time.Duration) (*ReconExecutor, error) {
	if recon == nil || evidence == nil || clock == nil {
		return nil, fmt.Errorf("%w: recon executor is missing a dependency", shared.ErrValidation)
	}
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &ReconExecutor{recon: recon, evidence: evidence, clock: clock, poll: poll, timeout: timeout}, nil
}

// Execute runs the admitted recon action and returns the (raw) observation. The orchestrator
// redacts + caps + fences the Output before it re-enters the transcript or is sealed.
func (e *ReconExecutor) Execute(ctx context.Context, adm safety.AdmittedAction) (Observation, error) {
	p := adm.Action()
	tool := reconToolName(p)
	if tool == "" {
		return Observation{Summary: "no recon tool resolved for " + p.Action}, nil
	}
	actor := "agent:" + p.SessionID.String() // agent attribution (matches Session.AgentActor)

	run, err := e.recon.Start(ctx, actor, p.EngagementID, tool, p.Target.Value)
	if err != nil {
		// A tool-level refusal (out of scope/window, live recon disabled, bad target) is fed
		// back so the model can adapt – it does not abort the agent run.
		return Observation{Summary: fmt.Sprintf("recon %s could not start: %s", tool, err.Error()),
			Output: []byte(err.Error())}, nil
	}

	run, err = e.await(ctx, run.ID)
	if err != nil {
		return Observation{}, err // orchestration failure (ctx cancelled / poll error)
	}
	switch run.Status {
	case drecon.StatusFailed:
		return Observation{Summary: fmt.Sprintf("recon %s failed at %s: %s", tool, run.Stage, run.Error),
			Output: []byte(run.Error)}, nil
	case drecon.StatusSucceeded:
		out := e.sealedOutput(ctx, p.EngagementID, run.EvidenceID)
		return Observation{
			Summary: fmt.Sprintf("recon %s: %d in-scope result(s)", tool, run.ResultCount),
			Output:  out,
		}, nil
	default:
		return Observation{Summary: fmt.Sprintf("recon %s did not finish (status=%s)", tool, run.Status)}, nil
	}
}

// await polls the run until it reaches a terminal status, the deadline passes, or ctx ends.
func (e *ReconExecutor) await(ctx context.Context, runID shared.ID) (drecon.Run, error) {
	deadline := e.clock.Now().Add(e.timeout)
	for {
		run, err := e.recon.Get(ctx, runID)
		if err != nil {
			return drecon.Run{}, fmt.Errorf("poll recon run: %w", err)
		}
		if run.Status.Terminal() {
			return run, nil
		}
		if e.clock.Now().After(deadline) {
			run.Status = drecon.StatusFailed
			run.Stage = "timeout"
			run.Error = "recon run did not finish within the executor deadline"
			return run, nil
		}
		select {
		case <-ctx.Done():
			return drecon.Run{}, ctx.Err()
		case <-time.After(e.poll):
		}
	}
}

// sealedOutput recovers a finished run's raw tool output from its sealed terminal_log link.
// Best effort: an empty/missing link yields nil output (the summary still carries the count).
func (e *ReconExecutor) sealedOutput(ctx context.Context, engagementID, evidenceID shared.ID) []byte {
	if evidenceID == "" {
		return nil
	}
	items, err := e.evidence.List(ctx, engagementID)
	if err != nil {
		return nil
	}
	for _, it := range items {
		if it.ID == evidenceID {
			return it.Content
		}
	}
	return nil
}

// reconToolName resolves the recon tool registry key from a proposed action. The argv's first
// element is the tool binary (== its registry key, e.g. "subfinder"); fall back to stripping
// the "recon." prefix from the audit verb.
func reconToolName(p agent.ProposedAction) string {
	if len(p.Argv) > 0 && p.Argv[0] != "" {
		return p.Argv[0]
	}
	return strings.TrimPrefix(p.Action, "recon.")
}
