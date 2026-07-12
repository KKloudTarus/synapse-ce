package recon

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/signing"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ---- test doubles ----

type syncDispatcher struct{}

func (syncDispatcher) Submit(task func(context.Context)) error {
	task(context.Background())
	return nil
}

type fakeRunner struct {
	res ports.ToolResult
	err error
}

func (f fakeRunner) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	return f.res, f.err
}

type fakeTool struct {
	name    string
	accepts engagement.TargetKind
	capSens bool
	results []recon.Result
}

func (f fakeTool) Name() string                         { return f.name }
func (f fakeTool) Binary() string                       { return f.name }
func (f fakeTool) Action() string                       { return "recon." + f.name }
func (f fakeTool) Accepts(k engagement.TargetKind) bool { return k == f.accepts }
func (f fakeTool) CapabilitySensitive() bool            { return f.capSens }
func (f fakeTool) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{Name: f.name, Args: []string{"-d", t.Value}}, nil
}
func (f fakeTool) Parse([]byte) ([]recon.Result, error) { return f.results, nil }

type recordingAudit struct {
	mu      sync.Mutex
	entries []ports.AuditEntry
}

func (a *recordingAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}
func (a *recordingAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (g *seqIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID("id-" + string(rune('0'+g.n)))
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// ---- harness ----

type harness struct {
	svc   *Service
	eng   *memory.EngagementRepository
	runs  *memory.ReconRunRepository
	audit *recordingAudit
	ev    *evidenceuc.Service
	tool  fakeTool
}

func newHarness(t *testing.T, runner ports.ToolRunner, tool fakeTool, allowCap bool) *harness {
	t.Helper()
	clock := fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}
	audit := &recordingAudit{}
	engRepo := memory.NewEngagementRepository()
	guard, err := execution.NewGuard(engRepo, clock, audit)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	ev, err := evidenceuc.NewService(memory.NewEvidenceStore(), blob.NewMemory(), audit, clock, &seqIDs{})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	runs := memory.NewReconRunRepository()
	svc, err := NewService(guard, runner, runs, ev, engRepo, logstream.NewBroker(0), syncDispatcher{}, clock, &seqIDs{}, map[string]ports.ReconTool{tool.name: tool}, time.Minute, 1<<20, allowCap)
	if err != nil {
		t.Fatalf("recon service: %v", err)
	}
	return &harness{svc: svc, eng: engRepo, runs: runs, audit: audit, ev: ev, tool: tool}
}

// seedEngagement creates engagement "e1" in scope with the given live-recon flag.
func (h *harness) seedEngagement(t *testing.T, liveRecon bool) {
	t.Helper()
	eng := &engagement.Engagement{
		ID:     "e1",
		Name:   "lab",
		Status: engagement.StatusActive,
		Scope: engagement.Scope{InScope: []engagement.Target{
			{Kind: engagement.TargetDomain, Value: "example.com"},
			{Kind: engagement.TargetDomain, Value: "*.example.com"},
		}},
		LiveReconEnabled: liveRecon,
	}
	if err := h.eng.Create(context.Background(), eng); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
}

func subfinderTool() fakeTool {
	return fakeTool{
		name:    "subfinder",
		accepts: engagement.TargetDomain,
		results: []recon.Result{
			{Kind: recon.ResultSubdomain, Value: "www.example.com"},
			{Kind: recon.ResultSubdomain, Value: "api.example.com"},
			{Kind: recon.ResultSubdomain, Value: "evil.attacker.test"}, // out of scope
		},
	}
}

// ---- tests ----

func TestStartHappyPathSealsEvidenceAndDropsOutOfScope(t *testing.T) {
	h := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("raw tool output")}}, subfinderTool(), false)
	h.seedEngagement(t, true)

	run, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "example.com")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	got, err := h.runs.Get(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if got.Status != recon.StatusSucceeded {
		t.Fatalf("status = %s, error = %q", got.Status, got.Error)
	}
	if got.ResultCount != 2 {
		t.Errorf("ResultCount = %d, want 2 in-scope (evil.attacker.test dropped)", got.ResultCount)
	}
	if got.EvidenceID == "" {
		t.Error("expected the tool output to be sealed into the evidence chain")
	}
	if !h.audit.has("recon.subfinder") {
		t.Error("expected an allow audit entry for recon.subfinder")
	}
}

func TestStartBlockedWhenLiveReconDisabled(t *testing.T) {
	h := newHarness(t, fakeRunner{}, subfinderTool(), false)
	h.seedEngagement(t, false) // lab-only flag OFF

	_, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "example.com")
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("want ErrForbidden when live recon disabled, got %v", err)
	}
}

func TestStartRejectsOutOfScopeTarget(t *testing.T) {
	h := newHarness(t, fakeRunner{}, subfinderTool(), false)
	h.seedEngagement(t, true)

	_, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "not-mine.test")
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("want ErrForbidden for out-of-scope target, got %v", err)
	}
}

func TestStartRejectsUnknownToolAndWrongKind(t *testing.T) {
	h := newHarness(t, fakeRunner{}, subfinderTool(), false)
	h.seedEngagement(t, true)

	if _, err := h.svc.Start(context.Background(), "alice", "e1", "nope", "example.com"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown tool: want ErrValidation, got %v", err)
	}
	// subfinder accepts only domains; an IP target is the wrong kind.
	if _, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "203.0.113.5"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("wrong kind: want ErrValidation, got %v", err)
	}
}

func TestWorkerGateDenialOutsideWindow(t *testing.T) {
	h := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("x")}}, subfinderTool(), false)
	// In scope + live recon on, but the authorization window has expired.
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	eng := &engagement.Engagement{
		ID: "e1", Name: "lab", Status: engagement.StatusActive,
		Scope:            engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "example.com"}}},
		LiveReconEnabled: true,
		AuthorizedTo:     &past,
	}
	if err := h.eng.Create(context.Background(), eng); err != nil {
		t.Fatal(err)
	}

	run, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "example.com")
	if err != nil {
		t.Fatalf("start should enqueue (window is checked in the worker via the guard): %v", err)
	}
	got, _ := h.runs.Get(context.Background(), run.ID)
	if got.Status != recon.StatusFailed {
		t.Fatalf("expired window must fail the run, got %s", got.Status)
	}
	if !h.audit.has("recon.subfinder.denied") {
		t.Error("expected a .denied audit entry from the gate")
	}
}

func TestRunnerErrorStillSealsOutput(t *testing.T) {
	h := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("partial"), Stderr: []byte("boom")}, err: errors.New("binary not found")}, subfinderTool(), false)
	h.seedEngagement(t, true)

	run, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "example.com")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	got, _ := h.runs.Get(context.Background(), run.ID)
	if got.Status != recon.StatusFailed {
		t.Errorf("status = %s, want failed", got.Status)
	}
	if got.EvidenceID == "" {
		t.Error("output must be sealed even when the run fails")
	}
	if !strings.Contains(got.Error, "binary not found") {
		t.Errorf("error not propagated: %q", got.Error)
	}
}

func TestToolsCatalog(t *testing.T) {
	h := newHarness(t, fakeRunner{}, subfinderTool(), false)
	tools := h.svc.Tools()
	if len(tools) != 1 || tools[0].Name != "subfinder" {
		t.Fatalf("tools = %+v", tools)
	}
	if len(tools[0].AcceptedKinds) == 0 {
		t.Error("tool should advertise accepted kinds")
	}
}

func naabuTool() fakeTool {
	return fakeTool{name: "naabu", accepts: engagement.TargetDomain, capSens: true}
}

func TestCapabilitySensitiveToolGated(t *testing.T) {
	// Default interim posture: a capability-sensitive tool is refused
	// even with live recon on and an in-scope target.
	off := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("x")}}, naabuTool(), false)
	off.seedEngagement(t, true)
	if _, err := off.svc.Start(context.Background(), "alice", "e1", "naabu", "example.com"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("capability-sensitive tool must be forbidden by default, got %v", err)
	}

	// Explicitly allowed: it runs.
	on := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("x")}}, naabuTool(), true)
	on.seedEngagement(t, true)
	run, err := on.svc.Start(context.Background(), "alice", "e1", "naabu", "example.com")
	if err != nil {
		t.Fatalf("with capability-sensitive allowed, naabu should run: %v", err)
	}
	got, _ := on.runs.Get(context.Background(), run.ID)
	if got.Status != recon.StatusSucceeded {
		t.Errorf("status = %s, error = %q", got.Status, got.Error)
	}
}

func TestSubmitDenialsAreAudited(t *testing.T) {
	cases := []struct {
		name     string
		tool     fakeTool
		live     bool
		target   string
		toolName string
		action   string
	}{
		{"out_of_scope", subfinderTool(), true, "not-mine.test", "subfinder", "recon.subfinder.denied"},
		{"live_recon_disabled", subfinderTool(), false, "example.com", "subfinder", "recon.subfinder.denied"},
		{"capability_sensitive", naabuTool(), true, "example.com", "naabu", "recon.naabu.denied"},
		{"wrong_kind", subfinderTool(), true, "203.0.113.5", "subfinder", "recon.subfinder.denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, fakeRunner{}, tc.tool, false)
			h.seedEngagement(t, tc.live)
			if _, err := h.svc.Start(context.Background(), "alice", "e1", tc.toolName, tc.target); err == nil {
				t.Fatalf("%s: expected a denial", tc.name)
			}
			if !h.audit.has(tc.action) {
				t.Errorf("%s: submit-time denial must be audited (%s)", tc.name, tc.action)
			}
		})
	}
}

// capturingRunner records the spec it was handed, to assert the egress policy attaches.
type capturingRunner struct {
	res  ports.ToolResult
	spec ports.ToolSpec
}

func (c *capturingRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	c.spec = spec
	return c.res, nil
}

// TestSandboxEnforcementAllowsCapToolAndAttachesEgress covers the gate flip: with
// sandbox enforcement on, a capability-sensitive tool is permitted (because contained)
// and its run carries the scope-derived egress policy.
func TestSandboxEnforcementAllowsCapToolAndAttachesEgress(t *testing.T) {
	cr := &capturingRunner{res: ports.ToolResult{Stdout: []byte("x")}}
	h := newHarness(t, cr, naabuTool(), false) // allowCap=false: only the sandbox path can permit naabu
	h.seedEngagement(t, true)

	// Without sandbox enforcement, the capability-sensitive tool is refused.
	if _, err := h.svc.Start(context.Background(), "alice", "e1", "naabu", "example.com"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("without sandbox, a capability tool must be refused, got %v", err)
	}

	// Enable sandbox enforcement with a scope-derived egress compiler.
	h.svc.SetSandboxEnforcement(func(engagement.Scope) ports.EgressPolicy {
		return ports.EgressPolicy{Rules: []ports.EgressRule{{Allow: true, Net: netip.MustParsePrefix("203.0.113.0/24")}}}
	})
	run, err := h.svc.Start(context.Background(), "alice", "e1", "naabu", "example.com")
	if err != nil {
		t.Fatalf("with sandbox enforcement, naabu should run: %v", err)
	}
	if got, _ := h.runs.Get(context.Background(), run.ID); got.Status != recon.StatusSucceeded {
		t.Errorf("status = %s, error = %q", got.Status, got.Error)
	}
	if cr.spec.EgressPolicy == nil || len(cr.spec.EgressPolicy.Rules) == 0 {
		t.Error("a sandboxed run must carry the scope-derived egress policy")
	}
}

// TestStartViaDurableQueue covers durable queueing: with a queue set, Start enqueues the run (no
// in-process execution); a worker that claims the job + calls RunJob executes it.
func TestStartViaDurableQueue(t *testing.T) {
	h := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("x")}}, subfinderTool(), false)
	h.seedEngagement(t, true)
	q := memory.NewJobQueue(&seqIDs{}, nil)
	h.svc.SetQueue(q)

	run, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "example.com")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// Enqueued – not executed in-process.
	if got, _ := h.runs.Get(context.Background(), run.ID); got.Status != recon.StatusQueued {
		t.Fatalf("run should be queued (not yet executed), got %s", got.Status)
	}
	// The worker claims the job and runs it.
	job, err := q.Claim(context.Background(), time.Minute)
	if err != nil || job == nil || job.Kind != JobKind {
		t.Fatalf("expected a recon job on the queue, got %+v err=%v", job, err)
	}
	if err := h.svc.RunJob(context.Background(), job.Payload); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if got, _ := h.runs.Get(context.Background(), run.ID); got.Status != recon.StatusSucceeded {
		t.Errorf("after RunJob, status = %s, error = %q", got.Status, got.Error)
	}
}

func TestRunJobRejectsMalformedPayload(t *testing.T) {
	h := newHarness(t, fakeRunner{}, subfinderTool(), false)
	if err := h.svc.RunJob(context.Background(), []byte("{not json")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed payload must be ErrValidation, got %v", err)
	}
}

// TestFailStrandedJobFinalizesRun covers the worker DeadLetterer hook for recon: when a recon
// job is dead-lettered, the backing run is driven to terminal `failed` instead of being left
// stranded `queued`/`running` with no terminal record (there is no stale-run reclaim sweep).
func TestFailStrandedJobFinalizesRun(t *testing.T) {
	h := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("x")}}, subfinderTool(), false)
	h.seedEngagement(t, true)
	q := memory.NewJobQueue(&seqIDs{}, nil)
	h.svc.SetQueue(q)

	run, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "example.com")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	job, err := q.Claim(context.Background(), time.Minute)
	if err != nil || job == nil {
		t.Fatalf("expected a recon job on the queue, got %+v err=%v", job, err)
	}
	// Simulate the worker giving up: the DeadLetterer hook finalizes the run.
	if err := h.svc.FailStrandedJob(context.Background(), job.Payload, errors.New("boom")); err != nil {
		t.Fatalf("FailStrandedJob: %v", err)
	}
	got, _ := h.runs.Get(context.Background(), run.ID)
	if got.Status != recon.StatusFailed {
		t.Fatalf("a dead-lettered recon run must be finalized failed, got %s", got.Status)
	}
	// Idempotent: a second finalize (at-least-once delivery) is a no-op, no error.
	if err := h.svc.FailStrandedJob(context.Background(), job.Payload, errors.New("boom")); err != nil {
		t.Fatalf("second FailStrandedJob must be a no-op, got %v", err)
	}
}

// TestSweepStaleRunsReclaims covers the stale-run sweeper: a run stranded `running` past
// staleFor with no live owner (acquirable lease) is finalized failed; a fresh running run and
// a run with a live lease are left alone.
func TestSweepStaleRunsReclaims(t *testing.T) {
	h := newHarness(t, fakeRunner{}, subfinderTool(), false)
	h.svc.SetRunLock(memory.NewRunLock())
	ctx := context.Background()
	// clock Now() = 2026-06-21 12:00; staleFor 5m ⇒ olderThan = 11:55.
	stale := recon.Run{ID: "run-stale", EngagementID: "e1", Tool: "subfinder", Target: "x", Status: recon.StatusRunning, StartedAt: time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)}
	fresh := recon.Run{ID: "run-fresh", EngagementID: "e1", Tool: "subfinder", Target: "y", Status: recon.StatusRunning, StartedAt: time.Date(2026, 6, 21, 11, 59, 30, 0, time.UTC)}
	if err := h.runs.Save(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if err := h.runs.Save(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	n, err := h.svc.SweepStaleRuns(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 stranded run reclaimed, got %d", n)
	}
	if got, _ := h.runs.Get(ctx, "run-stale"); got.Status != recon.StatusFailed {
		t.Fatalf("stale run must be finalized failed, got %q", got.Status)
	}
	if got, _ := h.runs.Get(ctx, "run-fresh"); got.Status != recon.StatusRunning {
		t.Fatalf("a fresh running run must NOT be swept, got %q", got.Status)
	}
}

func TestSweepStaleRunsSkipsLiveOwner(t *testing.T) {
	h := newHarness(t, fakeRunner{}, subfinderTool(), false)
	lock := memory.NewRunLock()
	h.svc.SetRunLock(lock)
	ctx := context.Background()
	stale := recon.Run{ID: "run-live", EngagementID: "e1", Status: recon.StatusRunning, StartedAt: time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)}
	if err := h.runs.Save(ctx, stale); err != nil {
		t.Fatal(err)
	}
	rel, ok, _ := lock.TryLock(ctx, "run-live") // a live owner holds the lease
	if !ok {
		t.Fatal("precondition: lease should be free")
	}
	defer rel()
	n, err := h.svc.SweepStaleRuns(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a run whose lease a live owner holds must NOT be swept, got %d", n)
	}
	if got, _ := h.runs.Get(ctx, "run-live"); got.Status != recon.StatusRunning {
		t.Fatalf("a live run must stay running, got %q", got.Status)
	}
}

// ctxRunner honors ctx cancellation (unlike fakeRunner) so a cancelled lease context aborts
// the tool run – used by the lease-loss test.
type ctxRunner struct{}

func (ctxRunner) Run(ctx context.Context, _ ports.ToolSpec) (ports.ToolResult, error) {
	if ctx.Err() != nil {
		return ports.ToolResult{}, ctx.Err()
	}
	return ports.ToolResult{Stdout: []byte("ok")}, nil
}

// fakeLeaseLock implements ports.LeaseRunLocker; TryLockLeased returns an already-cancelled
// lease context to simulate the lease being lost (stolen/expired) the moment the run starts.
type fakeLeaseLock struct{}

func (fakeLeaseLock) TryLock(context.Context, string) (func(), bool, error) {
	return func() {}, true, nil
}
func (fakeLeaseLock) TryLockLeased(ctx context.Context, _ string) (context.Context, func(), bool, error) {
	c, cancel := context.WithCancel(ctx)
	cancel() // lease already lost
	return c, func() {}, true, nil
}

// TestRunJobAbortsOnLeaseLoss covers lease-loss handling: when the run lease is lost
// mid-execution (the lease context is cancelled), the in-flight tool aborts, the run is
// finalized failed, and an attributable audit entry (reason=lease_lost) is recorded – so a
// stolen lease never leaves a silently-double-run or a stranded `running` row.
func TestRunJobAbortsOnLeaseLoss(t *testing.T) {
	h := newHarness(t, ctxRunner{}, subfinderTool(), false)
	h.seedEngagement(t, true)
	h.svc.SetRunLock(fakeLeaseLock{})
	ctx := context.Background()
	run := recon.Run{ID: "run-1", EngagementID: "e1", Tool: "subfinder", Target: "example.com", Status: recon.StatusRunning, StartedAt: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}
	if err := h.runs.Save(ctx, run); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(reconJob{Actor: "alice", RunID: "run-1", Tool: "subfinder", Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.RunJob(ctx, payload); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	got, _ := h.runs.Get(ctx, "run-1")
	if got.Status != recon.StatusFailed {
		t.Fatalf("a run whose lease was lost mid-execution must end failed, got %q", got.Status)
	}
	leaseLost := false
	for _, e := range h.audit.entries {
		if e.Metadata["reason"] == "lease_lost" {
			leaseLost = true
		}
	}
	if !leaseLost {
		t.Error("lease loss must record an audit entry with reason=lease_lost")
	}
}

// TestReconProactivelyAnchorsHead covers head-anchoring: when chain-head attestation is wired, the
// recon worker attests (and would RFC-3161-anchor) the evidence head it just sealed – at seal
// time, not only on a later API read – so a worker-sealed head is tamper-proof immediately.
func TestReconProactivelyAnchorsHead(t *testing.T) {
	h := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("sub.example.com\n")}}, subfinderTool(), false)
	h.seedEngagement(t, true)
	signer, err := signing.NewEd25519Signer(nil) // ephemeral test attestation key
	if err != nil {
		t.Fatal(err)
	}
	h.ev.SetSigner(signer.WithContext(evdom.AttestationContextEvidence))

	ctx := context.Background()
	if _, err := h.svc.Start(ctx, "alice", "e1", "subfinder", "example.com"); err != nil {
		t.Fatalf("start: %v", err)
	}
	// The run sealed its terminal_log and proactively attested the advanced head.
	rep, err := h.ev.Verify(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Head == "" {
		t.Fatal("expected a sealed evidence head after the run")
	}
	if rep.Attestation == nil {
		t.Fatal("the worker must attest the evidence head it sealed")
	}
}

// TestRunRecordsContainmentPosture covers posture recording: a completed run records its confinement
// posture (operator-facing) – "unsandboxed (dev)" off the sandbox, "sandboxed-live …"
// when egress-enforced.
func TestRunRecordsContainmentPosture(t *testing.T) {
	// Unsandboxed (no SetSandboxEnforcement).
	h := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("x")}}, subfinderTool(), false)
	h.seedEngagement(t, true)
	run, err := h.svc.Start(context.Background(), "alice", "e1", "subfinder", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := h.runs.Get(context.Background(), run.ID)
	if got.Containment != "unsandboxed (dev)" {
		t.Errorf("unsandboxed run posture = %q", got.Containment)
	}

	// Sandboxed-live with a scope egress policy.
	h2 := newHarness(t, fakeRunner{res: ports.ToolResult{Stdout: []byte("x")}}, subfinderTool(), false)
	h2.seedEngagement(t, true)
	h2.svc.SetSandboxEnforcement(func(engagement.Scope) ports.EgressPolicy {
		return ports.EgressPolicy{Rules: []ports.EgressRule{{Allow: true, Net: netip.MustParsePrefix("203.0.113.0/24")}}}
	})
	run2, err := h2.svc.Start(context.Background(), "alice", "e1", "subfinder", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	got2, _ := h2.runs.Get(context.Background(), run2.ID)
	if !strings.HasPrefix(got2.Containment, "sandboxed-live") || !strings.Contains(got2.Containment, "egress-restricted") {
		t.Errorf("sandboxed run posture = %q, want sandboxed-live egress-restricted", got2.Containment)
	}

	profile := h2.svc.buildContainmentProfile(subfinderTool(), &ports.EgressPolicy{
		AllowDomainRules: []ports.DomainRule{{Host: "example.com", Ports: []uint16{443}}},
	})
	if profile.EgressAllowDomains != 1 || !strings.Contains(profile.Summary(), "1 destination(s)") {
		t.Errorf("structured URL hostname omitted from containment profile: %+v / %q", profile, profile.Summary())
	}
}
