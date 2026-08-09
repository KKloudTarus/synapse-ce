package dastworkflow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

func validScanConfig() ScanConfig {
	return ScanConfig{Target: "https://203.0.113.10", Crawler: dastcrawl.Input{Target: "https://203.0.113.10"}, Session: dastsession.Config{Scheme: dastsession.SchemeBearer, Credentials: []dastsession.CredentialBinding{{Name: "token", Reference: "token"}}, LoginRequest: dastsession.Request{Method: "GET", Path: "/"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/"}, Success: dastsession.SuccessSignal{StatusCode: 200}}}
}

func TestScanConfigCanonicalizesDefaultsAndRejectsSecrets(t *testing.T) {
	canonical, err := validScanConfig().canonical(DefaultScanCeilings())
	if err != nil || len(canonical) == 0 {
		t.Fatalf("canonical=%q err=%v", canonical, err)
	}
	bad := validScanConfig()
	bad.Session.Credentials[0].Reference = "{{secret:token}}"
	if _, err := bad.canonical(DefaultScanCeilings()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("secret placeholder err=%v", err)
	}
	for name, mutate := range map[string]func(*ScanConfig){
		"reauth":      func(c *ScanConfig) { c.Session.MaxReauth = DefaultScanCeilings().MaxReauth + 1 },
		"rate":        func(c *ScanConfig) { c.RatePerSec = DefaultScanCeilings().RatePerSec + 1 },
		"concurrency": func(c *ScanConfig) { c.Concurrency = DefaultScanCeilings().Concurrency + 1 },
		"depth":       func(c *ScanConfig) { c.Limits.Depth = DefaultScanCeilings().Limits.Depth + 1 },
		"pages":       func(c *ScanConfig) { c.Limits.Pages = DefaultScanCeilings().Limits.Pages + 1 },
		"requests":    func(c *ScanConfig) { c.Limits.Requests = DefaultScanCeilings().Limits.Requests + 1 },
		"wall clock":  func(c *ScanConfig) { c.Limits.WallClock = DefaultScanCeilings().Limits.WallClock + time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			bad := validScanConfig()
			mutate(&bad)
			if _, err := bad.canonical(DefaultScanCeilings()); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("canonical err=%v", err)
			}
		})
	}
}

func TestRunScanRequiresMatchingDigest(t *testing.T) {
	wf, _ := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	if err := wf.SetScan(nil, "", nil, nil, nil, nil, nil, DefaultScanCeilings()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("SetScan err=%v", err)
	}
	if _, err := wf.RunScan(context.Background(), "alice", "eng-1", "missing", validScanConfig()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("RunScan err=%v", err)
	}
}

func TestRunScanPromotesOnlyAfterDistinctProofVerification(t *testing.T) {
	wf, store := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	config := validScanConfig()
	config.Crawler.Seeds = []dastsurface.Request{{Method: "GET", URL: config.Target + "/"}}
	proof := ports.DASTProof{
		CheckID: "security-headers", Version: 1, NormalizedEndpoint: config.Target + "/",
		Observation: ports.DASTClosedObservation{Method: "GET", Status: 200, BodySHA256: strings.Repeat("a", 64), Signature: "missing:strict-transport-security"},
		Hash:        strings.Repeat("b", 64),
	}
	session := &fakeScanSession{result: dastcrawl.Result{Observations: []ports.DASTObservation{{Method: "GET", URL: config.Target + "/", Status: 200}}}}
	evaluator := &fakeScanEvaluator{findings: []ports.DASTFinding{{CheckID: proof.CheckID, CWE: "CWE-693", Version: 1, Endpoint: proof.NormalizedEndpoint, Proof: proof}}}
	judgments := &fakeScanJudgments{}
	verifier := &fakeScanVerifier{}
	if err := wf.SetScan(session, "synapse-dast-helper", wf.evidence, evaluator, evaluator, judgments, verifier, DefaultScanCeilings()); err != nil {
		t.Fatal(err)
	}
	proposal, err := wf.ProposeScan(context.Background(), "alice", "eng-1", config)
	if err != nil && !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("propose: %v", err)
	}
	if err := store.Decide(context.Background(), agent.ApprovalDecision{ActionID: proposal.Action.ID, State: agent.ApprovalApproved, DecidedBy: "bob", DecidedAt: time.Unix(1_700_100_000, 0)}); err != nil {
		t.Fatal(err)
	}
	result, err := wf.RunScan(context.Background(), "alice", "eng-1", proposal.Action.ID, config)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if session.calls != 1 || evaluator.calls != 1 || len(judgments.proposed) != 1 || len(verifier.results) != 1 || len(result.Proofs) != 1 {
		t.Fatalf("session=%d proof_checks=%d judgments=%d verdicts=%d proofs=%d", session.calls, evaluator.calls, len(judgments.proposed), len(verifier.results), len(result.Proofs))
	}
	claim, ok := judgments.proposed[0].Claim.(judgment.DASTClaim)
	if !ok || claim.ProofEvidenceID == "" || judgments.proposed[0].ProposedBy == scanVerifierIdentity || verifier.results[0].Verifier != scanVerifierIdentity {
		t.Fatalf("distinct verifier custody failed: judgment=%+v result=%+v", judgments.proposed[0], verifier.results[0])
	}
}

func TestRunScanRejectsProofBeforeJudgmentPromotion(t *testing.T) {
	wf, store := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	config := validScanConfig()
	proof := ports.DASTProof{CheckID: "security-headers", Version: 1, NormalizedEndpoint: config.Target, Observation: ports.DASTClosedObservation{Method: "GET", Status: 200, BodySHA256: strings.Repeat("a", 64)}, Hash: "bad"}
	session := &fakeScanSession{}
	evaluator := &fakeScanEvaluator{findings: []ports.DASTFinding{{CheckID: proof.CheckID, CWE: "CWE-693", Endpoint: config.Target, Proof: proof}}, verify: shared.ErrValidation}
	judgments := &fakeScanJudgments{}
	verifier := &fakeScanVerifier{}
	if err := wf.SetScan(session, "synapse-dast-helper", wf.evidence, evaluator, evaluator, judgments, verifier, DefaultScanCeilings()); err != nil {
		t.Fatal(err)
	}
	proposal, err := wf.ProposeScan(context.Background(), "alice", "eng-1", config)
	if err != nil && !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("propose: %v", err)
	}
	if err := store.Decide(context.Background(), agent.ApprovalDecision{ActionID: proposal.Action.ID, State: agent.ApprovalApproved, DecidedBy: "bob", DecidedAt: time.Unix(1_700_100_000, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := wf.RunScan(context.Background(), "alice", "eng-1", proposal.Action.ID, config); err == nil {
		t.Fatal("invalid proof was accepted")
	}
	if len(judgments.proposed) != 0 || len(verifier.results) != 0 {
		t.Fatalf("invalid proof reached promotion: judgments=%d verdicts=%d", len(judgments.proposed), len(verifier.results))
	}
}

func TestRunScanDoesNotPromoteIncompleteObservations(t *testing.T) {
	wf, store := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	config := validScanConfig()
	proof := ports.DASTProof{CheckID: "security-headers", Version: 1, NormalizedEndpoint: config.Target, Observation: ports.DASTClosedObservation{Method: "GET", Status: 200, BodySHA256: strings.Repeat("a", 64), Signature: "missing:strict-transport-security"}, Hash: strings.Repeat("b", 64)}
	session := &fakeScanSession{result: dastcrawl.Result{Incomplete: true, Reason: "session_lost", Observations: []ports.DASTObservation{{Method: "GET", URL: config.Target, Status: 200}}}}
	evaluator := &fakeScanEvaluator{findings: []ports.DASTFinding{{CheckID: proof.CheckID, CWE: "CWE-693", Endpoint: config.Target, Proof: proof}}}
	judgments := &fakeScanJudgments{}
	verifier := &fakeScanVerifier{}
	if err := wf.SetScan(session, "synapse-dast-helper", wf.evidence, evaluator, evaluator, judgments, verifier, DefaultScanCeilings()); err != nil {
		t.Fatal(err)
	}
	proposal, err := wf.ProposeScan(context.Background(), "alice", "eng-1", config)
	if err != nil && !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatal(err)
	}
	if proposal.Action.Argv[1] != "run" {
		t.Fatalf("approved argv=%v", proposal.Action.Argv)
	}
	if err := store.Decide(context.Background(), agent.ApprovalDecision{ActionID: proposal.Action.ID, State: agent.ApprovalApproved, DecidedBy: "bob", DecidedAt: time.Unix(1_700_100_000, 0)}); err != nil {
		t.Fatal(err)
	}
	result, err := wf.RunScan(context.Background(), "alice", "eng-1", proposal.Action.ID, config)
	if err != nil || !result.Incomplete || result.Reason != "session_lost" || evaluator.calls != 0 || len(judgments.proposed) != 0 || len(verifier.results) != 0 {
		t.Fatalf("result=%+v evaluator=%d judgments=%d verifier=%d err=%v", result, evaluator.calls, len(judgments.proposed), len(verifier.results), err)
	}
}

func TestRunScanDoesNotPromoteCleanObservations(t *testing.T) {
	wf, store := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	config := validScanConfig()
	session := &fakeScanSession{result: dastcrawl.Result{Observations: []ports.DASTObservation{{
		Method: "GET", URL: config.Target + "/", Status: 200, BodySHA256: strings.Repeat("a", 64),
		Headers: []string{"Strict-Transport-Security: max-age=1", "Set-Cookie: Secure; HttpOnly; SameSite=Lax"},
	}}}}
	evaluator := &fakeScanEvaluator{}
	judgments := &fakeScanJudgments{}
	verifier := &fakeScanVerifier{}
	if err := wf.SetScan(session, "synapse-dast-helper", wf.evidence, evaluator, evaluator, judgments, verifier, DefaultScanCeilings()); err != nil {
		t.Fatal(err)
	}
	proposal, err := wf.ProposeScan(context.Background(), "alice", "eng-1", config)
	if err != nil && !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("propose: %v", err)
	}
	if err := store.Decide(context.Background(), agent.ApprovalDecision{ActionID: proposal.Action.ID, State: agent.ApprovalApproved, DecidedBy: "bob", DecidedAt: time.Unix(1_700_100_000, 0)}); err != nil {
		t.Fatal(err)
	}
	result, err := wf.RunScan(context.Background(), "alice", "eng-1", proposal.Action.ID, config)
	if err != nil || len(result.Proofs) != 0 || len(judgments.proposed) != 0 || len(verifier.results) != 0 {
		t.Fatalf("result=%+v judgments=%d verdicts=%d err=%v", result, len(judgments.proposed), len(verifier.results), err)
	}
}

func TestRunScanSealsApprovalConsumption(t *testing.T) {
	wf, store := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	config := validScanConfig()
	evaluator := &fakeScanEvaluator{}
	if err := wf.SetScan(&fakeScanSession{}, "synapse-dast-helper", wf.evidence, evaluator, evaluator, &fakeScanJudgments{}, &fakeScanVerifier{}, DefaultScanCeilings()); err != nil {
		t.Fatal(err)
	}
	proposal, err := wf.ProposeScan(context.Background(), "alice", "eng-1", config)
	if err != nil && !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatal(err)
	}
	if err := store.Decide(context.Background(), agent.ApprovalDecision{ActionID: proposal.Action.ID, State: agent.ApprovalApproved, DecidedBy: "bob", DecidedAt: time.Unix(1_700_100_000, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := wf.RunScan(context.Background(), "alice", "eng-1", proposal.Action.ID, config); err != nil {
		t.Fatal(err)
	}
	items, err := wf.evidence.List(context.Background(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		if item.Kind == "agent_approval_consumed" && item.CreatedBy == "alice" && strings.Contains(string(item.Content), proposal.Action.ID.String()) {
			found = true
		}
	}
	if !found {
		t.Fatalf("approval consumption evidence missing: %+v", items)
	}
	if _, err := wf.RunScan(context.Background(), "alice", "eng-1", proposal.Action.ID, config); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("second run err=%v", err)
	}
	items, err = wf.evidence.List(context.Background(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	records := 0
	for _, item := range items {
		if item.Kind == "agent_approval_consumed" && strings.Contains(string(item.Content), proposal.Action.ID.String()) {
			records++
		}
	}
	if records != 1 {
		t.Fatalf("consumption records=%d want=1", records)
	}
}
