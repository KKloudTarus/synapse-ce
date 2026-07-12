// Package recon orchestrates reconnaissance runs. It is the typed Go
// control flow the safety model requires: the operator picks a registered tool
// + an in-scope target, and the service authorizes through the ONE shared execution
// guard, derives argv from the target (never free-form strings), runs it bounded
// via the ToolRunner, seals the raw output into the evidence chain, and re-checks
// every discovered host against scope. Live recon is lab-only behind
// the engagement's explicit LiveReconEnabled flag.
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Dispatcher runs a task asynchronously on a bounded worker pool (satisfied by
// platform/jobs.Pool). Defined here so the use case does not import the pool.
type Dispatcher interface {
	Submit(task func(context.Context)) error
}

// evidenceKindTerminalLog tags recon tool output sealed into the evidence chain.
const evidenceKindTerminalLog = "terminal_log"

// evidenceKindContainment tags the per-run containment posture: metadata proving
// HOW a tool was confined (sandbox tier, egress enforcement, caps). It never affects
// argv/output/parsing – it is sealed alongside the terminal log so a reader can verify
// the containment under which the run executed.
const evidenceKindContainment = "containment_profile"

// evidenceKindConnectLog tags the eBPF connect-log: every outbound connect() the
// tool attempted, with an allowed/denied verdict – a forensic record of what the tool
// reached for, including out-of-scope attempts the kernel egress filter dropped.
const evidenceKindConnectLog = "connect_log"

// containmentProfile is the sealed record of a run's confinement.
type containmentProfile struct {
	Sandboxed          bool   `json:"sandboxed"`
	Tier               string `json:"tier,omitempty"`
	EgressEnforced     bool   `json:"egress_enforced"`
	EgressAllowRules   int    `json:"egress_allow_rules,omitempty"`
	EgressAllowDomains int    `json:"egress_allow_domains,omitempty"`
	CapNetRaw          bool   `json:"cap_net_raw"`
}

// Summary is a one-line, operator-facing description of the confinement posture.
func (p containmentProfile) Summary() string {
	if !p.Sandboxed {
		return "unsandboxed (dev)"
	}
	s := "sandboxed"
	if p.EgressEnforced {
		dests := p.EgressAllowRules + p.EgressAllowDomains
		s += fmt.Sprintf("-live · egress-restricted to scope (%d destination(s))", dests)
	} else {
		s += " · network-isolated"
	}
	if p.CapNetRaw {
		s += " · CAP_NET_RAW"
	}
	return s
}

// buildContainmentProfile summarizes how this run is confined.
func (s *Service) buildContainmentProfile(tool ports.ReconTool, egress *ports.EgressPolicy) containmentProfile {
	p := containmentProfile{Sandboxed: s.sandboxed, CapNetRaw: tool.CapabilitySensitive()}
	if s.sandboxed {
		p.Tier = "bubblewrap"
	}
	if egress != nil {
		p.EgressEnforced = true
		for _, r := range egress.Rules {
			if r.Allow {
				p.EgressAllowRules++
			}
		}
		p.EgressAllowDomains = len(egress.AllowDomains) + len(egress.AllowDomainRules)
	}
	return p
}

// Service orchestrates recon runs.
type Service struct {
	guard       *execution.Guard
	runner      ports.ToolRunner
	runs        ports.ReconRunStore
	evidence    *evidence.Service
	engagements ports.EngagementRepository
	logs        ports.LogStream
	dispatcher  Dispatcher
	clock       ports.Clock
	ids         ports.IDGenerator
	tools       map[string]ports.ReconTool
	timeout     time.Duration
	maxOut      int
	// allowCapabilitySensitive is a dev override for capability-sensitive tools (naabu –
	// raw sockets) when no sandbox is configured. The supported path is the
	// sandbox: when sandboxed is true, capability-sensitive tools are permitted *because*
	// they run sandboxed + egress-restricted, so this stays false in prod.
	allowCapabilitySensitive bool
	// sandboxed reports that the tool runner is the egress-capable SandboxRunner.
	// When true, capability-sensitive tools are allowed and each run carries a
	// scope-derived egress policy (compileEgress).
	sandboxed bool
	// compileEgress turns an engagement scope into a kernel egress policy for a run. A
	// func (not a usecase import) so recon depends only inward (domain + ports). Set
	// alongside sandboxed; nil leaves runs network-isolated.
	compileEgress func(engagement.Scope) ports.EgressPolicy
	// jobQueue, when set, makes Start defer each run to the durable queue instead
	// of the in-process dispatcher – so queued recon survives a restart and can be claimed
	// by the worker. nil keeps the in-process dispatcher (dev / single-process).
	jobQueue ports.JobQueue
	// runLock, when set, guards a single active execution per run: an at-least-once
	// redelivery that arrives while a run is still executing is skipped, so a live scan is
	// never duplicated. nil = no cross-delivery guard (only the terminal-status check).
	runLock ports.RunLocker
}

// SetRunLock guards against duplicate concurrent execution of the same run under
// at-least-once queue redelivery.
func (s *Service) SetRunLock(l ports.RunLocker) { s.runLock = l }

// JobKind is the queue Kind for a recon run.
const JobKind = "recon"

// reconJob is the durable-queue payload for one recon run.
type reconJob struct {
	Actor  string `json:"actor"`
	RunID  string `json:"run_id"`
	Tool   string `json:"tool"`
	Target string `json:"target"`
}

// SetQueue routes recon runs through the durable job queue: Start enqueues, and a
// worker claims + calls RunJob. Optional – without it, the in-process dispatcher is used.
func (s *Service) SetQueue(q ports.JobQueue) { s.jobQueue = q }

// RunJob executes a recon run claimed from the durable queue (the worker handler calls
// this). A malformed payload is a hard error (the job dead-letters); a tool/run failure
// is recorded on the run itself (not a job error), so the job completes.
func (s *Service) RunJob(ctx context.Context, payload []byte) error {
	var j reconJob
	if err := json.Unmarshal(payload, &j); err != nil {
		return fmt.Errorf("%w: malformed recon job payload: %v", shared.ErrValidation, err)
	}
	if err := engagement.ValidateTargetValue(j.Target); err != nil {
		return fmt.Errorf("%w: invalid recon job target: %v", shared.ErrValidation, err)
	}
	target := engagement.Target{Kind: engagement.InferTargetKind(j.Target), Value: j.Target}
	normalized, err := engagement.NormalizeTarget(target, false)
	if err != nil {
		return fmt.Errorf("%w: invalid recon job target: %v", shared.ErrValidation, err)
	}
	target = normalized
	// single-active-execution lease (re-audit fix – held at the JOB boundary so a lock
	// ERROR returns an error and the queue REDELIVERS, never silently completing a
	// never-executed authorized scan). A held lease (ok=false) means another delivery is
	// running it → complete this delivery (nil).
	runCtx := ctx
	switch lock := s.runLock.(type) {
	case ports.LeaseRunLocker:
		// Row lease: run under a context cancelled if the lease is LOST, so a stolen/expired
		// lease ABORTS the in-flight tool instead of double-running against a live host.
		leaseCtx, release, ok, lerr := lock.TryLockLeased(ctx, j.RunID)
		if lerr != nil {
			return fmt.Errorf("run lock unavailable for %s (will retry): %w", j.RunID, lerr)
		}
		if !ok {
			return nil
		}
		defer release()
		runCtx = leaseCtx
	case ports.RunLocker:
		release, ok, lerr := lock.TryLock(ctx, j.RunID)
		if lerr != nil {
			return fmt.Errorf("run lock unavailable for %s (will retry): %w", j.RunID, lerr)
		}
		if !ok {
			return nil // another worker is executing this run; nothing to do
		}
		defer release()
	}
	s.execute(runCtx, j.Actor, shared.ID(j.RunID), j.Tool, target)
	// Lease lost mid-run (runCtx cancelled, but NOT a parent shutdown): the in-flight tool was
	// aborted via runCtx – finalize the run failed + audit the abort.
	if runCtx.Err() != nil && ctx.Err() == nil {
		s.finalizeLeaseLost(j, target)
	}
	return nil
}

// finalizeLeaseLost records a recon run whose lease was lost mid-execution: mark it failed on a
// FRESH context (the run's own context is cancelled, so execute's finishFailed Save may not have
// persisted) when not already terminal, and write an append-only audit entry attributing the
// abort – a lost lease means another worker may now own the host, so we stopped.
func (s *Service) finalizeLeaseLost(j reconJob, target engagement.Target) {
	bg := context.Background()
	run, err := s.runs.Get(bg, shared.ID(j.RunID))
	if err != nil {
		return
	}
	if !run.Status.Terminal() {
		fin := s.clock.Now()
		run.Status = recon.StatusFailed
		run.Stage = "lease-lost"
		run.Error = "run lease lost mid-execution – aborted (another worker may have reclaimed the host)"
		run.FinishedAt = &fin
		_ = s.runs.Save(bg, run)
	}
	s.guard.AuditDenial(bg, execution.Request{
		Actor: j.Actor, EngagementID: run.EngagementID, Action: "recon", Target: target,
		Metadata: map[string]string{"tool": j.Tool, "run": j.RunID, "outcome": "lease_lost"},
	}, "lease_lost")
}

// FailStrandedJob marks the run behind a DEAD-LETTERED recon job failed if it has not already
// reached a terminal state, so a crash/lock-error that exhausts the retries does not leave the
// run lingering `running`/`queued` with no terminal record (there is no stale-run reclaim
// sweep). It is the worker's DeadLetterer hook. It takes the run lease so it never races a live
// redelivery (symmetry with the agent path) and no-ops when the run is terminal or held.
func (s *Service) FailStrandedJob(ctx context.Context, payload []byte, cause error) error {
	var j reconJob
	if err := json.Unmarshal(payload, &j); err != nil {
		return fmt.Errorf("%w: malformed recon job payload: %v", shared.ErrValidation, err)
	}
	runID := shared.ID(j.RunID)
	if s.runLock != nil {
		release, ok, lerr := s.runLock.TryLock(ctx, j.RunID)
		if lerr != nil {
			return fmt.Errorf("run lock for %s: %w", j.RunID, lerr)
		}
		if !ok {
			return nil // a live delivery owns this run
		}
		defer release()
	}
	run, err := s.runs.Get(ctx, runID)
	if err != nil {
		return fmt.Errorf("load stranded run %s: %w", runID, err)
	}
	if run.Status.Terminal() {
		return nil
	}
	msg := "recon job dead-lettered after exhausting retries"
	if cause != nil {
		// Redact before it persists to run.Error – uniform with the agent path and the rest of
		// this file's error sinks (the cause is Go-internal today, but never persist raw).
		msg = redact.String(cause.Error(), nil)
	}
	s.finishFailed(ctx, &run, "dead-letter", msg)
	return nil
}

// SweepStaleRuns reclaims recon runs a crashed worker left `running` past staleFor WITHOUT a
// dead-letter event (the dead-letter hook only fires when a JOB dead-letters; a run whose job
// row was lost or never dead-lettered has no such event). It uses the run lease as the liveness
// signal: if TryLock succeeds the prior owner is gone (lease free/expired) → the run is stranded
// → finalize it failed; a held lease means a live owner is still running it → skip. Requires the
// lease lock – without it a stranded run cannot be told from a live one, so it no-ops. Returns
// the number of runs reclaimed.
func (s *Service) SweepStaleRuns(ctx context.Context, staleFor time.Duration) (int, error) {
	if s.runLock == nil {
		return 0, nil
	}
	if staleFor <= 0 {
		staleFor = 15 * time.Minute
	}
	runs, err := s.runs.ListStaleRunning(ctx, s.clock.Now().Add(-staleFor), 100)
	if err != nil {
		return 0, fmt.Errorf("list stale runs: %w", err)
	}
	n := 0
	for i := range runs {
		run := runs[i]
		release, ok, lerr := s.runLock.TryLock(ctx, run.ID.String())
		if lerr != nil || !ok {
			continue // can't acquire (DB hiccup) or a live owner holds it → leave for next pass
		}
		// Re-read under the lock: a final delivery may have just finished it.
		if fresh, gerr := s.runs.Get(ctx, run.ID); gerr == nil && fresh.Status.Terminal() {
			release()
			continue
		}
		s.finishFailed(ctx, &run, "swept", "run stranded running past staleFor with no live owner – reclaimed by sweeper")
		release()
		n++
	}
	return n, nil
}

// SetSandboxEnforcement marks recon as running on the egress-capable sandbox:
// capability-sensitive tools become permitted (because contained) and every run is given
// a scope-derived egress policy via compile. With this unset, the interim posture holds
// (capability-sensitive refused unless the dev override; runs network-isolated).
func (s *Service) SetSandboxEnforcement(compile func(engagement.Scope) ports.EgressPolicy) {
	s.sandboxed, s.compileEgress = true, compile
}

// NewService validates its dependencies and returns the recon service.
func NewService(guard *execution.Guard, runner ports.ToolRunner, runs ports.ReconRunStore, ev *evidence.Service, engagements ports.EngagementRepository, logs ports.LogStream, dispatcher Dispatcher, clock ports.Clock, ids ports.IDGenerator, tools map[string]ports.ReconTool, timeout time.Duration, maxOut int, allowCapabilitySensitive bool) (*Service, error) {
	if guard == nil || runner == nil || runs == nil || ev == nil || engagements == nil || logs == nil || dispatcher == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: recon service is missing a dependency", shared.ErrValidation)
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("%w: recon service needs at least one tool", shared.ErrValidation)
	}
	return &Service{guard: guard, runner: runner, runs: runs, evidence: ev, engagements: engagements, logs: logs, dispatcher: dispatcher, clock: clock, ids: ids, tools: tools, timeout: timeout, maxOut: maxOut, allowCapabilitySensitive: allowCapabilitySensitive}, nil
}

// ToolInfo describes a registered tool for the UI catalog.
type ToolInfo struct {
	Name                string   `json:"name"`
	Action              string   `json:"action"`
	CapabilitySensitive bool     `json:"capabilitySensitive"`
	AcceptedKinds       []string `json:"acceptedKinds"`
}

var allKinds = []engagement.TargetKind{
	engagement.TargetDomain, engagement.TargetIP, engagement.TargetCIDR,
	engagement.TargetURL, engagement.TargetRepo, engagement.TargetImage,
}

// Tools lists the registered recon tools (sorted) so the UI can populate its
// launcher and show which tools are capability-sensitive (lab-only).
func (s *Service) Tools() []ToolInfo {
	out := make([]ToolInfo, 0, len(s.tools))
	for _, t := range s.tools {
		ti := ToolInfo{Name: t.Name(), Action: t.Action(), CapabilitySensitive: t.CapabilitySensitive()}
		for _, k := range allKinds {
			if t.Accepts(k) {
				ti.AcceptedKinds = append(ti.AcceptedKinds, string(k))
			}
		}
		out = append(out, ti)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Start validates the request, records a queued run, and dispatches it to the
// worker pool, returning the run immediately. Synchronous fast-fail checks
// (unknown tool, live-recon disabled, wrong target kind, out of scope) surface to
// the caller; the worker re-authorizes through the guard before executing.
func (s *Service) Start(ctx context.Context, actor string, engagementID shared.ID, toolName, targetValue string) (recon.Run, error) {
	value := strings.TrimSpace(targetValue)
	target := engagement.Target{Kind: engagement.InferTargetKind(value), Value: value}

	tool, ok := s.tools[toolName]
	if !ok {
		// No tool object to name the action; audit the refused attempt explicitly.
		s.guard.AuditDenial(ctx, execution.Request{Actor: actor, EngagementID: engagementID, Action: "recon", Target: target, Metadata: map[string]string{"tool": toolName, "stage": "submit"}}, "unknown_tool")
		return recon.Run{}, fmt.Errorf("%w: unknown recon tool %q", shared.ErrValidation, toolName)
	}
	if err := s.checkCapability(tool); err != nil {
		return recon.Run{}, s.denySubmit(ctx, actor, engagementID, tool, target, "capability_sensitive", err)
	}
	// Internal execution read (see ports.GetByID): recon.Start is reached only via the
	// withEngTenant-wrapped HTTP route (tenant already checked at the edge) or the internal agent
	// orchestrator, and is itself authorized by the scope/window/RoE execution gate below.
	eng, err := s.engagements.GetByID(ctx, engagementID)
	if err != nil {
		return recon.Run{}, fmt.Errorf("load engagement: %w", err)
	}
	if !eng.LiveReconEnabled {
		return recon.Run{}, s.denySubmit(ctx, actor, engagementID, tool, target, "live_recon_disabled",
			fmt.Errorf("%w: live recon is not enabled for this engagement (lab-only)", shared.ErrForbidden))
	}
	if err := engagement.ValidateTargetValue(value); err != nil {
		return recon.Run{}, s.denySubmit(ctx, actor, engagementID, tool, target, "invalid_target", err)
	}
	normalized, err := engagement.NormalizeTarget(target, false)
	if err != nil {
		return recon.Run{}, s.denySubmit(ctx, actor, engagementID, tool, target, "invalid_target", err)
	}
	target = normalized
	if !tool.Accepts(target.Kind) {
		return recon.Run{}, s.denySubmit(ctx, actor, engagementID, tool, target, "wrong_target_kind",
			fmt.Errorf("%w: %s does not accept %s targets", shared.ErrValidation, toolName, target.Kind))
	}
	// Fast scope pre-check (the guard re-checks authoritatively in the worker).
	if !eng.Scope.AllowsTarget(target) {
		return recon.Run{}, s.denySubmit(ctx, actor, engagementID, tool, target, "out_of_scope",
			fmt.Errorf("%w: target is not in the engagement scope", shared.ErrForbidden))
	}

	now := s.clock.Now()
	run := recon.Run{
		ID:           s.ids.NewID(),
		EngagementID: engagementID,
		Tool:         toolName,
		Target:       target.Value,
		Status:       recon.StatusQueued,
		Stage:        "queued",
		StartedAt:    now,
	}
	if err := s.runs.Save(ctx, run); err != nil {
		return recon.Run{}, fmt.Errorf("save run: %w", err)
	}
	// Durable queue when configured: enqueue the run so a worker claims + executes
	// it (survives restart; runs under the worker's sandbox/egress/privilege). Otherwise
	// the in-process dispatcher runs it (dev / single-process).
	if s.jobQueue != nil {
		payload, err := json.Marshal(reconJob{Actor: actor, RunID: run.ID.String(), Tool: toolName, Target: target.Value})
		if err != nil {
			s.finishFailed(ctx, &run, "queue", "marshal job: "+err.Error())
			return run, fmt.Errorf("marshal recon job: %w", err)
		}
		if _, err := s.jobQueue.Enqueue(ctx, JobKind, payload); err != nil {
			s.finishFailed(ctx, &run, "queue", "enqueue: "+err.Error())
			return run, fmt.Errorf("enqueue recon run: %w", err)
		}
		return run, nil
	}
	if err := s.dispatcher.Submit(func(wctx context.Context) {
		s.execute(wctx, actor, run.ID, toolName, target)
	}); err != nil {
		s.finishFailed(ctx, &run, "queue", "could not queue run: "+err.Error())
		return run, fmt.Errorf("enqueue run: %w", err)
	}
	return run, nil
}

// Get returns a single run.
func (s *Service) Get(ctx context.Context, id shared.ID) (recon.Run, error) {
	return s.runs.Get(ctx, id)
}

// List returns an engagement's runs.
func (s *Service) List(ctx context.Context, engagementID shared.ID) ([]recon.Run, error) {
	return s.runs.ListByEngagement(ctx, engagementID)
}

// execute is the worker body: re-authorize through the guard, run the tool bounded,
// seal output as evidence, and keep only in-scope discovered assets. All progress
// is published to the log stream; the stream is closed when the run finishes.
func (s *Service) execute(ctx context.Context, actor string, runID shared.ID, toolName string, target engagement.Target) {
	rid := runID.String()
	defer s.logs.Close(rid)

	run, err := s.runs.Get(ctx, runID)
	if err != nil {
		return // the run record is gone; nothing to update
	}
	// Idempotency (audit): the durable queue is at-least-once, so a redelivery
	// (lease expiry / crash / heartbeat failure) can re-invoke this for a run a prior
	// delivery already finished. Recon executes against REAL hosts and seals + audits, so
	// re-running would duplicate the live scan, the audit entry, and the evidence links. If
	// the run is already terminal, skip – the worker then Completes the job.
	if run.Status.Terminal() {
		s.logs.Publish(rid, "run already finished (duplicate at-least-once delivery) – skipping re-execution")
		return
	}
	tool := s.tools[toolName]

	run.Status = recon.StatusRunning
	run.Stage = "authorizing"
	s.saveRun(ctx, &run)
	s.logs.Publish(rid, fmt.Sprintf("recon %s on %s", tool.Name(), target.Value))

	// Defense-in-depth: re-check capability-sensitivity + the lab-only flag against
	// the live engagement before any process starts.
	if err := s.checkCapability(tool); err != nil {
		s.finishFailed(ctx, &run, "authorize", err.Error())
		return
	}
	eng, err := s.engagements.GetByID(ctx, run.EngagementID)
	if err != nil {
		s.finishFailed(ctx, &run, "authorize", "load engagement: "+err.Error())
		return
	}
	if !eng.LiveReconEnabled {
		s.finishFailed(ctx, &run, "authorize", "live recon disabled for this engagement")
		return
	}

	// THE gate: scope + window + RoE + append-only audit, before exec.
	if _, err := s.guard.Authorize(ctx, execution.Request{
		Actor:        actor,
		EngagementID: run.EngagementID,
		Action:       tool.Action(),
		Target:       target,
		Metadata:     map[string]string{"tool": tool.Name(), "kind": string(target.Kind)},
	}); err != nil {
		s.finishFailed(ctx, &run, "authorize", err.Error())
		return
	}

	spec, err := tool.BuildArgs(target)
	if err != nil {
		s.finishFailed(ctx, &run, "build-args", err.Error())
		return
	}
	spec.Timeout = s.timeout
	spec.MaxOutputBytes = s.maxOut
	// on the sandbox, attach the scope-derived egress policy so the tool can
	// reach only in-scope destinations (kernel-enforced). The SandboxRunner runs it in a
	// filtered netns; off the sandbox this is nil (runs stay network-isolated / refused).
	if s.sandboxed && s.compileEgress != nil {
		policy := s.compileEgress(eng.Scope)
		spec.EgressPolicy = &policy
	}
	// record the containment posture on the run (operator-facing) and seal it
	// into evidence (provable). Metadata only – never changes argv/output.
	profile := s.buildContainmentProfile(tool, spec.EgressPolicy)
	run.Containment = profile.Summary()
	if cp, mErr := json.Marshal(profile); mErr == nil {
		if _, sErr := s.evidence.Seal(ctx, run.EngagementID, evidenceKindContainment, cp, actor); sErr != nil {
			s.logs.Publish(rid, "WARN: containment profile seal failed: "+sErr.Error())
		}
	}

	run.Stage = "running " + tool.Binary()
	s.saveRun(ctx, &run)
	s.logs.Publish(rid, "$ "+spec.Name+" "+strings.Join(spec.Args, " "))

	res, runErr := s.runner.Run(ctx, spec)

	// Seal whatever output we captured into the evidence chain – even on failure,
	// the attempt is recorded.
	output := make([]byte, 0, len(res.Stdout)+len(res.Stderr))
	output = append(output, res.Stdout...)
	output = append(output, res.Stderr...)
	if ev, sErr := s.evidence.Seal(ctx, run.EngagementID, evidenceKindTerminalLog, output, actor); sErr == nil {
		run.EvidenceID = ev.ID
	} else {
		s.logs.Publish(rid, "WARN: evidence seal failed: "+sErr.Error())
	}
	if res.Truncated {
		s.logs.Publish(rid, "WARN: tool output truncated at the size cap")
	}
	// seal the connect-log (kernel-observed outbound attempts, incl. dropped
	// out-of-scope ones) as a forensic artifact. Empty unless this was an egress run with
	// the eBPF logger active. Never fails the run – observability.
	if len(res.ConnectLog) > 0 {
		if cl, mErr := json.Marshal(res.ConnectLog); mErr == nil {
			if _, sErr := s.evidence.Seal(ctx, run.EngagementID, evidenceKindConnectLog, cl, actor); sErr != nil {
				s.logs.Publish(rid, "WARN: connect-log seal failed: "+sErr.Error())
			} else {
				denied := 0
				for _, c := range res.ConnectLog {
					if !c.Allowed {
						denied++
					}
				}
				s.logs.Publish(rid, fmt.Sprintf("egress: %d connect attempt(s) logged (%d out-of-scope)", len(res.ConnectLog), denied))
			}
		}
	}
	// Proactively attest + externally anchor the advanced evidence head: a head the
	// worker just sealed becomes tamper-PROOF at seal time, not only on a later API read. Verify
	// re-checks the chain, ed25519-attests, and RFC-3161-anchors the head – all best-effort and
	// bounded. Skipped when no signer/TSA is wired (avoids a chain read with no attestation).
	if s.evidence.AttestationEnabled() {
		if _, aerr := s.evidence.Verify(ctx, run.EngagementID); aerr != nil {
			s.logs.Publish(rid, "WARN: evidence head anchor failed: "+aerr.Error())
		}
	}

	if runErr != nil {
		s.finishFailed(ctx, &run, "run", runErr.Error())
		return
	}

	results, err := tool.Parse(res.Stdout)
	if err != nil {
		s.finishFailed(ctx, &run, "parse", err.Error())
		return
	}

	// every discovered asset is re-validated against scope before it
	// is kept; out-of-scope discoveries are dropped and logged, never acted on.
	inScope := 0
	for _, r := range results {
		if eng.Scope.Allows(r.Value) {
			inScope++
			line := fmt.Sprintf("[in-scope] %s %s", r.Kind, r.Value)
			if r.Detail != "" {
				line += "  (" + r.Detail + ")"
			}
			s.logs.Publish(rid, line)
		} else {
			s.logs.Publish(rid, "[dropped: out of scope] "+r.Value)
		}
	}

	run.ResultCount = inScope
	run.Status = recon.StatusSucceeded
	run.Stage = "done"
	fin := s.clock.Now()
	run.FinishedAt = &fin
	s.saveRun(ctx, &run)
	s.logs.Publish(rid, fmt.Sprintf("done – %d in-scope result(s)", inScope))
}

// finishFailed marks a run failed, persists it, and reports the error on the log
// stream (the stream is closed by execute's deferred Close).
func (s *Service) finishFailed(ctx context.Context, run *recon.Run, stage, msg string) {
	run.Status = recon.StatusFailed
	run.Stage = stage
	run.Error = msg
	fin := s.clock.Now()
	run.FinishedAt = &fin
	s.saveRun(ctx, run)
	s.logs.Publish(run.ID.String(), "ERROR ("+stage+"): "+msg)
}

// saveRun persists a run and surfaces a persistence failure on the log stream so a
// dropped write is not invisible (the run record + audit could otherwise diverge).
func (s *Service) saveRun(ctx context.Context, run *recon.Run) {
	if err := s.runs.Save(ctx, *run); err != nil {
		s.logs.Publish(run.ID.String(), "WARN: failed to persist run state: "+err.Error())
	}
}

// denySubmit audits a submit-time recon denial through the one gate (append-only
// audit: no silent denial) and returns the original error.
func (s *Service) denySubmit(ctx context.Context, actor string, engagementID shared.ID, tool ports.ReconTool, target engagement.Target, reason string, err error) error {
	s.guard.AuditDenial(ctx, execution.Request{
		Actor:        actor,
		EngagementID: engagementID,
		Action:       tool.Action(),
		Target:       target,
		Metadata:     map[string]string{"tool": tool.Name(), "kind": string(target.Kind), "stage": "submit"},
	}, reason)
	return err
}

// checkCapability enforces the containment rule: a capability-sensitive tool (raw sockets)
// stays behind the sandbox; until it exists, it runs only if explicitly allowed.
func (s *Service) checkCapability(tool ports.ReconTool) error {
	// a capability-sensitive tool is permitted when it runs on the
	// sandbox (contained + egress-restricted), or via the explicit dev override.
	// Otherwise it stays refused (the interim posture).
	if tool.CapabilitySensitive() && !s.sandboxed && !s.allowCapabilitySensitive {
		return fmt.Errorf("%w: %s is capability-sensitive and requires the sandbox; enable SYNAPSE_SANDBOX_ENABLED", shared.ErrForbidden, tool.Name())
	}
	return nil
}
