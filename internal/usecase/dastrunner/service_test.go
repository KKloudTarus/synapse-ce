package dastrunner

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeAudit struct{ entries []ports.AuditEntry }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID {
	s.n++
	return shared.ID("id-" + string(rune('0'+s.n)))
}

type fakeRunner struct {
	spec ports.ToolSpec
	out  []byte
	err  error
}

func (r *fakeRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	r.spec = spec
	return ports.ToolResult{Stdout: r.out, ExitCode: 0}, r.err
}

type fakeApplier struct {
	calls []dastverifier.Result
}

func (a *fakeApplier) Apply(_ context.Context, engagementID shared.ID, r dastverifier.Result) (judgment.Judgment, error) {
	a.calls = append(a.calls, r)
	return judgment.Judgment{ID: r.JudgmentID, EngagementID: engagementID, Capability: judgment.CapSAST, State: judgment.StateConfirmed, EvidenceScore: r.Score}, nil
}

func admittedAction(t *testing.T, mode agent.ApprovalMode, risk agent.RiskClass) safety.AdmittedAction {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	eng, _ := engagement.New("eng-1", "", "Acme", "Acme", now)
	eng.Status = engagement.StatusActive
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = eng.SetAuthorizationWindow(&from, &to, "UTC", now)
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetURL, Value: "https://app.acme.test/search?q=synapse-canary"}}}
	repo := memory.NewEngagementRepository()
	if err := repo.Create(context.Background(), eng); err != nil {
		t.Fatal(err)
	}
	audit := &fakeAudit{}
	guard, err := execution.NewGuard(repo, fakeClock{now}, audit)
	if err != nil {
		t.Fatal(err)
	}
	appr, err := approval.NewService(memory.NewApprovalStore(), audit, fakeClock{now}, mode, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, fakeClock{now}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	p := agent.ProposedAction{
		ID: "act-1", SessionID: "sess-1", EngagementID: "eng-1",
		Tool: ToolRunDASTVerifier, Action: ActionSafeHTTPProbe,
		Target: engagement.Target{Kind: engagement.TargetURL, Value: "https://app.acme.test/search?q=synapse-canary"},
		Argv:   []string{"curl", "https://app.acme.test/search?q=synapse-canary"},
		Risk:   risk,
	}
	adm, err := gate.Admit(context.Background(), p, "alice")
	if errors.Is(err, safety.ErrPendingApproval) {
		if _, derr := appr.Decide(context.Background(), "bob", p.ID, true, "approved scoped verifier"); derr != nil {
			t.Fatal(derr)
		}
		adm, err = gate.Admit(context.Background(), p, "alice")
	}
	if err != nil {
		t.Fatalf("admit action: %v", err)
	}
	return adm
}

func newServiceForTest(t *testing.T, runner *fakeRunner, applier *fakeApplier) *Service {
	t.Helper()
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, &fakeAudit{}, fakeClock{time.Unix(1_700_000_001, 0).UTC()}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(runner, ev, applier, "curl", time.Second, 4096)
	if err != nil {
		t.Fatal(err)
	}
	svc.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	return svc
}

func TestExecuteSafeHTTPProbeSealsAndAppliesVerifierResult(t *testing.T) {
	runner := &fakeRunner{out: []byte("hello synapse-canary\nSYNAPSE_HTTP_STATUS:200\n")}
	applier := &fakeApplier{}
	svc := newServiceForTest(t, runner, applier)
	got, err := svc.Execute(context.Background(), admittedAction(t, agent.ModeManual, agent.RiskIntrusive), Probe{
		JudgmentID: "j-1", URL: "https://app.acme.test/search?q=synapse-canary", Method: "GET",
		ExpectedStatus: 200, ExpectedBodyContains: "synapse-canary", ScoreIfConfirmed: 85, ScoreIfRefuted: 30,
		ExpectedVersion: 4, Rationale: "approved canary reflected without sensitive extraction",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Proof != dastverifier.ProofClassRuntimeConfirmed || got.Status != 200 || got.Evidence == "" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if runner.spec.Name != "curl" || runner.spec.Args[len(runner.spec.Args)-1] != "https://app.acme.test/search?q=synapse-canary" {
		t.Fatalf("runner spec should be argv-only curl against the admitted URL: %+v", runner.spec)
	}
	if runner.spec.EgressPolicy == nil || len(runner.spec.EgressPolicy.Rules) != 1 || runner.spec.EgressPolicy.Rules[0].Net.Addr() != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("runner spec should carry pinned-IP egress policy: %+v", runner.spec.EgressPolicy)
	}
	if runner.spec.EgressExecutionKind != "dast-verifier" || runner.spec.EgressExecutionID != "j-1" {
		t.Fatalf("execution identity = %q/%q", runner.spec.EgressExecutionKind, runner.spec.EgressExecutionID)
	}
	if len(applier.calls) != 1 {
		t.Fatalf("want one verifier apply call, got %d", len(applier.calls))
	}
	call := applier.calls[0]
	if call.Verifier != "bob" || call.Score != 85 || call.ProofClass != dastverifier.ProofClassRuntimeConfirmed || call.ExpectedVersion != 4 {
		t.Fatalf("verifier result lost custody fields: %+v", call)
	}
}

func TestExecuteRejectsAutoApprovedRuntimeProof(t *testing.T) {
	runner := &fakeRunner{out: []byte("ok\nSYNAPSE_HTTP_STATUS:200\n")}
	applier := &fakeApplier{}
	svc := newServiceForTest(t, runner, applier)
	_, err := svc.Execute(context.Background(), admittedAction(t, agent.ModeAuto, agent.RiskActive), Probe{
		JudgmentID: "j-1", URL: "https://app.acme.test/search?q=synapse-canary", Method: "GET",
	})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("auto-approved runtime proof must be forbidden, got %v", err)
	}
	if len(applier.calls) != 0 {
		t.Fatalf("auto-approved runtime proof must not reach verifier applier: %+v", applier.calls)
	}
}

func TestExecuteFailClosedValidation(t *testing.T) {
	runner := &fakeRunner{}
	applier := &fakeApplier{}
	svc := newServiceForTest(t, runner, applier)
	adm := admittedAction(t, agent.ModeManual, agent.RiskIntrusive)
	cases := []Probe{
		{JudgmentID: "", URL: "https://app.acme.test/search?q=synapse-canary", Method: "GET"},
		{JudgmentID: "j", URL: "file:///etc/passwd", Method: "GET"},
		{JudgmentID: "j", URL: "https://app.acme.test/search?q=synapse-canary", Method: "POST"},
		{JudgmentID: "j", URL: "https://other.test/search?q=synapse-canary", Method: "GET"},
	}
	for _, tc := range cases {
		if _, err := svc.Execute(context.Background(), adm, tc); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("Execute(%+v): want ErrValidation, got %v", tc, err)
		}
	}
	if len(applier.calls) != 0 {
		t.Fatalf("invalid probes must not reach verifier applier: %+v", applier.calls)
	}
}

func TestExecuteRejectsInternalResolvedProbeHost(t *testing.T) {
	runner := &fakeRunner{out: []byte("ok\nSYNAPSE_HTTP_STATUS:200\n")}
	applier := &fakeApplier{}
	svc := newServiceForTest(t, runner, applier)
	svc.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	_, err := svc.Execute(context.Background(), admittedAction(t, agent.ModeManual, agent.RiskIntrusive), Probe{
		JudgmentID: "j-1", URL: "https://app.acme.test/search?q=synapse-canary", Method: "GET",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("internal resolved probe host must be rejected, got %v", err)
	}
	if runner.spec.Name != "" {
		t.Fatalf("forbidden resolved hosts must not reach runner: %+v", runner.spec)
	}
}

func TestCurlArgsUseConfiguredTimeoutAndPinnedResolve(t *testing.T) {
	u, err := parseProbeURL("https://app.acme.test:8443/search?q=synapse-canary")
	if err != nil {
		t.Fatal(err)
	}
	args := curlArgs("GET", u.String(), u, netip.MustParseAddr("203.0.113.10"), 3*time.Second)
	want := map[string]bool{"--max-time": false, "3": false, "--resolve": false, "app.acme.test:8443:203.0.113.10": false}
	for _, arg := range args {
		if _, ok := want[arg]; ok {
			want[arg] = true
		}
	}
	for arg, seen := range want {
		if !seen {
			t.Fatalf("curl args missing %q: %+v", arg, args)
		}
	}
}
