package dastworkflow

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeAudit struct{}

func (fakeAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID {
	s.n++
	return shared.ID("id-" + string(rune('0'+s.n)))
}

type fakeRunner struct {
	calls int
	out   []byte
}

func (r *fakeRunner) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	r.calls++
	return ports.ToolResult{Stdout: r.out, ExitCode: 0}, nil
}

type fakeApplier struct {
	calls []dastverifier.Result
}

type fakeScanSession struct {
	result dastcrawl.Result
	err    error
	calls  int
}

func (f *fakeScanSession) CrawlWithRate(context.Context, safety.AdmittedAction, string, string, dastsession.Config, dastcrawl.Input, dastcrawl.Limits, int, int) (dastcrawl.Result, error) {
	f.calls++
	return f.result, f.err
}

type fakeScanEvaluator struct {
	findings []ports.DASTFinding
	verify   error
	calls    int
}

func (f *fakeScanEvaluator) Evaluate([]ports.DASTObservation, []string) ([]ports.DASTFinding, error) {
	return f.findings, nil
}

func (f *fakeScanEvaluator) VerifyProof(ports.DASTProof) error {
	f.calls++
	return f.verify
}

type fakeScanJudgments struct {
	proposed []judgment.Judgment
}

func (f *fakeScanJudgments) Propose(_ context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	j, err := judgment.New(shared.ID(fmt.Sprintf("judgment-%d", len(f.proposed)+1)), engagementID, capability, subjectKind, subjectID, claim, proposer, time.Unix(1, 0))
	if err == nil {
		f.proposed = append(f.proposed, j)
	}
	return j, err
}

type fakeScanVerifier struct {
	results []dastverifier.Result
}

func (f *fakeScanVerifier) Apply(_ context.Context, _ shared.ID, result dastverifier.Result) (judgment.Judgment, error) {
	f.results = append(f.results, result)
	return judgment.Judgment{ID: result.JudgmentID, State: judgment.StateConfirmed}, nil
}

func (a *fakeApplier) Apply(_ context.Context, engagementID shared.ID, r dastverifier.Result) (judgment.Judgment, error) {
	a.calls = append(a.calls, r)
	return judgment.Judgment{ID: r.JudgmentID, EngagementID: engagementID, Capability: judgment.CapSAST, State: judgment.StateConfirmed, EvidenceScore: r.Score}, nil
}

func workflowForTest(t *testing.T, runner *fakeRunner, applier *fakeApplier) (*Service, *memory.ApprovalStore) {
	t.Helper()
	now := time.Unix(1_700_100_000, 0).UTC()
	eng, _ := engagement.New("eng-1", "", "Acme", "Acme", now)
	eng.Status = engagement.StatusActive
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = eng.SetAuthorizationWindow(&from, &to, "UTC", now)
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetURL, Value: "https://203.0.113.10/"}}}
	repo := memory.NewEngagementRepository()
	if err := repo.Create(context.Background(), eng); err != nil {
		t.Fatal(err)
	}
	audit := fakeAudit{}
	clock := fakeClock{now}
	ids := &seqIDs{}
	guard, err := execution.NewGuard(repo, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	approvalStore := memory.NewApprovalStore()
	approvals, err := approval.NewService(approvalStore, audit, clock, agent.ModeAuto, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, approvals, ev)
	if err != nil {
		t.Fatal(err)
	}
	dr, err := dastrunner.NewService(runner, ev, applier, "curl", time.Second, 4096)
	if err != nil {
		t.Fatal(err)
	}
	wf, err := NewService(gate, approvals, approvalStore, dr, ev, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	wf.evidence = ev
	return wf, approvalStore
}

func testProbe() dastrunner.Probe {
	return dastrunner.Probe{
		JudgmentID: "j-1", URL: "https://203.0.113.10/search?q=synapse-canary", Method: "GET",
		ExpectedStatus: 200, ExpectedBodyContains: "synapse-canary",
		ScoreIfConfirmed: 85, ScoreIfRefuted: 30, ExpectedVersion: 2,
		Rationale: "approved safe canary verifier",
	}
}

func TestProposeAlwaysQueuesIntrusiveApproval(t *testing.T) {
	wf, store := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	prop, err := wf.Propose(context.Background(), "alice", "eng-1", testProbe())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if prop.Action.Risk != agent.RiskIntrusive || prop.Decision.State != agent.ApprovalPending {
		t.Fatalf("DAST proof proposal must be intrusive + pending even in auto mode: %+v %+v", prop.Action, prop.Decision)
	}
	pending, _ := store.Pending(context.Background(), "eng-1")
	if len(pending) != 1 || pending[0].ID != prop.Action.ID {
		t.Fatalf("approval store should contain the pending DAST action, got %+v", pending)
	}
}

func TestDeniedApprovalDoesNotRun(t *testing.T) {
	runner := &fakeRunner{out: []byte("synapse-canary\nSYNAPSE_HTTP_STATUS:200\n")}
	wf, _ := workflowForTest(t, runner, &fakeApplier{})
	prop, _ := wf.Propose(context.Background(), "alice", "eng-1", testProbe())
	if _, err := wf.Decide(context.Background(), "bob", "eng-1", prop.Action.ID, false, "no live proof"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if _, err := wf.Run(context.Background(), "alice", "eng-1", prop.Action.ID, testProbe()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("denied DAST action must not run, got %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("denied DAST action reached runner %d time(s)", runner.calls)
	}
}

func TestApprovedRunExecutesAndAppliesProof(t *testing.T) {
	runner := &fakeRunner{out: []byte("synapse-canary\nSYNAPSE_HTTP_STATUS:200\n")}
	applier := &fakeApplier{}
	wf, _ := workflowForTest(t, runner, applier)
	prop, _ := wf.Propose(context.Background(), "alice", "eng-1", testProbe())
	if _, err := wf.Decide(context.Background(), "bob", "eng-1", prop.Action.ID, true, "scoped safe verifier approved"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, err := wf.Run(context.Background(), "alice", "eng-1", prop.Action.ID, testProbe())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Proof != dastverifier.ProofClassRuntimeConfirmed || runner.calls != 1 {
		t.Fatalf("approved run should execute once and confirm proof, result=%+v calls=%d", got, runner.calls)
	}
	if len(applier.calls) != 1 || applier.calls[0].Verifier != "bob" || applier.calls[0].Score != 85 {
		t.Fatalf("proof should be applied under human verifier bob at score 85: %+v", applier.calls)
	}
}

func TestRunRejectsMismatchedProbeURL(t *testing.T) {
	wf, _ := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	prop, _ := wf.Propose(context.Background(), "alice", "eng-1", testProbe())
	if _, err := wf.Decide(context.Background(), "bob", "eng-1", prop.Action.ID, true, "ok"); err != nil {
		t.Fatal(err)
	}
	p := testProbe()
	p.URL = "https://203.0.113.11/search?q=synapse-canary"
	if _, err := wf.Run(context.Background(), "alice", "eng-1", prop.Action.ID, p); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatched run URL must be ErrValidation, got %v", err)
	}
}

func TestProposeRejectsSensitiveQuery(t *testing.T) {
	wf, _ := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	probe := testProbe()
	probe.URL = "https://203.0.113.10/search?api_key=secret"
	if _, err := wf.Propose(context.Background(), "alice", "eng-1", probe); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("sensitive query accepted: %v", err)
	}
}

func TestRunBindsFullProbeAndConsumesApproval(t *testing.T) {
	runner := &fakeRunner{out: []byte("synapse-canary\nSYNAPSE_HTTP_STATUS:200\n")}
	wf, _ := workflowForTest(t, runner, &fakeApplier{})
	probe := testProbe()
	prop, _ := wf.Propose(context.Background(), "alice", "eng-1", probe)
	if _, err := wf.Decide(context.Background(), "bob", "eng-1", prop.Action.ID, true, "ok"); err != nil {
		t.Fatal(err)
	}
	changed := probe
	changed.ExpectedStatus = 201
	if _, err := wf.Run(context.Background(), "alice", "eng-1", prop.Action.ID, changed); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("changed probe accepted: %v", err)
	}
	if _, err := wf.Run(context.Background(), "alice", "eng-1", prop.Action.ID, probe); err != nil {
		t.Fatal(err)
	}
	if _, err := wf.Run(context.Background(), "alice", "eng-1", prop.Action.ID, probe); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("repeated approval ran: %v", err)
	}
}
