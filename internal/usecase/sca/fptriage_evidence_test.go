package sca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
	"time"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type aiEvidenceScriptStore struct {
	items          map[shared.ID][]evdom.Evidence
	headCalls      int
	appendCalls    int
	headFailures   map[int]error
	appendFailures map[int]error
	conflictCalls  int
	appendAlways   error
}

func newAIEvidenceScriptStore() *aiEvidenceScriptStore {
	return &aiEvidenceScriptStore{
		items:          map[shared.ID][]evdom.Evidence{},
		headFailures:   map[int]error{},
		appendFailures: map[int]error{},
	}
}

func (s *aiEvidenceScriptStore) Head(_ context.Context, engagementID shared.ID) (string, error) {
	s.headCalls++
	if err := s.headFailures[s.headCalls]; err != nil {
		return "", err
	}
	chain := s.items[engagementID]
	if len(chain) == 0 {
		return "", nil
	}
	return chain[len(chain)-1].Hash, nil
}

func (s *aiEvidenceScriptStore) Append(_ context.Context, items []evdom.Evidence) error {
	s.appendCalls++
	if s.appendCalls <= s.conflictCalls {
		return fmt.Errorf("scripted parent conflict: %w", shared.ErrConflict)
	}
	if err := s.appendFailures[s.appendCalls]; err != nil {
		return err
	}
	if s.appendAlways != nil {
		return s.appendAlways
	}
	for _, item := range items {
		s.items[item.EngagementID] = append(s.items[item.EngagementID], item)
	}
	return nil
}

func (s *aiEvidenceScriptStore) ListByEngagement(_ context.Context, engagementID shared.ID) ([]evdom.Evidence, error) {
	out := make([]evdom.Evidence, len(s.items[engagementID]))
	copy(out, s.items[engagementID])
	return out, nil
}

func (s *aiEvidenceScriptStore) LookupSealedForFinding(_ context.Context, engagementID, findingID shared.ID, kind string) (evdom.Evidence, bool, error) {
	chain := s.items[engagementID]
	for i := len(chain) - 1; i >= 0; i-- {
		e := chain[i]
		if e.FindingID == findingID && e.Kind == kind {
			return e, true, nil
		}
	}
	return evdom.Evidence{}, false, nil
}

type aiEvidenceTestClock struct{ now time.Time }

func (c aiEvidenceTestClock) Now() time.Time { return c.now }

type aiEvidenceTestIDs struct{ n int }

func (g *aiEvidenceTestIDs) NewID() shared.ID {
	g.n++
	return shared.ID("ai-evidence-" + strconv.Itoa(g.n))
}

type aiEvidenceTestAudit struct {
	entries []ports.AuditEntry
	err     error
	ctxErr  error
}

func (a *aiEvidenceTestAudit) Record(ctx context.Context, entry ports.AuditEntry) error {
	a.ctxErr = ctx.Err()
	if a.err != nil {
		return a.err
	}
	a.entries = append(a.entries, entry)
	return nil
}

func newAIEvidenceService(t *testing.T, store ports.EvidenceStore, audit *aiEvidenceTestAudit) *Service {
	t.Helper()
	clock := aiEvidenceTestClock{now: time.Unix(1_700_000_000, 0).UTC()}
	vault, err := evidenceuc.NewService(store, nil, audit, clock, &aiEvidenceTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return &Service{evidence: vault, audit: audit, clock: clock}
}

func aiEvidenceGateExemptResult(t *testing.T) *ScanResult {
	t.Helper()
	result := &ScanResult{
		Target: "repo",
		Findings: []finding.Finding{{
			DedupKey: "safe-medium",
			Kind:     finding.KindSAST,
			Class:    finding.ClassFirstParty,
			Scope:    sbom.ScopeProduction,
			Severity: shared.SeverityMedium,
			CWE:      "CWE-327",
		}},
		AITriage:       []ports.AICritique{verifiedCritique("safe-medium")},
		AITriageBudget: &AITriageBudget{MaxFindings: 1, EligibleFindings: 1, AttemptedFindings: 1},
	}
	applyAIGatePolicy(result, true, aiTriageModeEnforce)
	if got := result.AIGateExemptKeys(); len(got) != 1 || !got["safe-medium"] {
		t.Fatalf("test setup: expected one authorized AI exemption, got %v", got)
	}
	return result
}

func assertAIEvidenceRevoked(t *testing.T, result *ScanResult) {
	t.Helper()
	if len(result.Findings) != 1 || result.Findings[0].DedupKey != "safe-medium" {
		t.Fatalf("evidence failure must retain the finding: %+v", result.Findings)
	}
	if got := result.AIGateExemptKeys(); len(got) != 0 {
		t.Fatalf("evidence failure must revoke all AI gate authority: %v", got)
	}
	if len(result.AITriage) != 1 {
		t.Fatalf("critique must be retained, got %d", len(result.AITriage))
	}
	critique := result.AITriage[0]
	if critique.GateExempt || !critique.ReviewRequired || critique.PolicyReason != aiPolicyEvidenceSealFailed {
		t.Fatalf("revoked critique = %+v", critique)
	}
	if critique.PolicyVersion != aiTriagePolicyVersion {
		t.Fatalf("revocation changed policy identity: %q", critique.PolicyVersion)
	}
	if result.AITriageBudget == nil || result.AITriageBudget.EvidenceSealFailures != 1 || result.AITriageBudget.EvidenceRevokedExemptions != 1 {
		t.Fatalf("evidence failure metrics = %+v", result.AITriageBudget)
	}
	warnings := 0
	for _, warning := range result.SourceWarnings {
		if warning == aiEvidenceSealFailureWarning {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatalf("operator warning count = %d, want 1; warnings=%v", warnings, result.SourceWarnings)
	}
}

func assertTypedAIEvidenceFailure(t *testing.T, ref shared.ID, err error, revoked int) *AIEvidenceSealError {
	t.Helper()
	if err == nil || !ref.IsZero() {
		t.Fatalf("evidence failure must stop before persistence: ref=%q err=%v", ref, err)
	}
	var typed *AIEvidenceSealError
	if !errors.As(err, &typed) || typed.RevokedExemptions != revoked {
		t.Fatalf("want AIEvidenceSealError with %d revoked exemption(s), got %T %v", revoked, err, err)
	}
	return typed
}

func assertSingleAIEvidenceAudit(t *testing.T, audit *aiEvidenceTestAudit, engagementID shared.ID) {
	t.Helper()
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1: %+v", len(audit.entries), audit.entries)
	}
	entry := audit.entries[0]
	if entry.Action != aiEvidenceSealFailureAuditAction || entry.Target != engagementID.String() ||
		entry.Metadata["evidence_seal_failures"] != "1" || entry.Metadata["revoked_exemptions"] != "1" {
		t.Fatalf("unexpected AI evidence audit entry: %+v", entry)
	}
}

func assertNoEvidence(t *testing.T, store *aiEvidenceScriptStore, engagementID shared.ID) {
	t.Helper()
	items, err := store.ListByEngagement(context.Background(), engagementID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("failed scan must not create a second/recovery evidence link: %+v", items)
	}
}

func TestAIEvidenceSuccessfulSealPreservesAuthorizedExemption(t *testing.T) {
	store := newAIEvidenceScriptStore()
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	result := aiEvidenceGateExemptResult(t)
	engagementID := shared.ID("eng-success")

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", engagementID, time.Unix(100, 0).UTC(), result)
	if err != nil || ref.IsZero() {
		t.Fatalf("successful evidence seal: ref=%q err=%v", ref, err)
	}
	if got := result.AIGateExemptKeys(); len(got) != 1 || !got["safe-medium"] {
		t.Fatalf("successful seal must preserve authorized exemption: %v", got)
	}
	items, err := store.ListByEngagement(context.Background(), engagementID)
	if err != nil || len(items) != 1 {
		t.Fatalf("evidence items=%d err=%v", len(items), err)
	}
	var payload scanEvidencePayload
	if err := json.Unmarshal(items[0].Content, &payload); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	if len(payload.AITriage) != 1 || !payload.AITriage[0].GateExempt || payload.AITriage[0].PolicyReason != aiPolicyVerifiedConsensus {
		t.Fatalf("authorized exemption was not sealed exactly: %+v", payload.AITriage)
	}
}

func TestAIEvidenceSealFailureRevokesOnVaultHeadTimeout(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.headFailures[1] = context.DeadlineExceeded
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	result := aiEvidenceGateExemptResult(t)
	engagementID := shared.ID("eng-head")

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", engagementID, time.Unix(100, 0).UTC(), result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("typed error must preserve vault failure: %v", err)
	}
	if store.headCalls != 1 || store.appendCalls != 0 {
		t.Fatalf("outer layer retried evidence unexpectedly: heads=%d appends=%d", store.headCalls, store.appendCalls)
	}
	assertAIEvidenceRevoked(t, result)
	assertSingleAIEvidenceAudit(t, audit, engagementID)
	assertNoEvidence(t, store, engagementID)
}

func TestAIEvidenceFailureAuditSurvivesCanceledRequestContext(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.headFailures[1] = context.Canceled
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	result := aiEvidenceGateExemptResult(t)
	engagementID := shared.ID("eng-canceled")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ref, err := svc.sealEvidenceFailClosed(ctx, "operator", engagementID, time.Unix(100, 0).UTC(), result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("typed error must preserve request cancellation: %v", err)
	}
	assertAIEvidenceRevoked(t, result)
	assertSingleAIEvidenceAudit(t, audit, engagementID)
	if audit.ctxErr != nil {
		t.Fatalf("failure audit inherited canceled request context: %v", audit.ctxErr)
	}
}

func TestAIEvidenceSealFailureRevokesOnStorageFailureWithoutOuterRetry(t *testing.T) {
	store := newAIEvidenceScriptStore()
	storageErr := errors.New("storage unavailable")
	store.appendFailures[1] = storageErr
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	result := aiEvidenceGateExemptResult(t)
	engagementID := shared.ID("eng-storage")

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", engagementID, time.Unix(100, 0).UTC(), result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if !errors.Is(err, storageErr) {
		t.Fatalf("typed error must preserve storage failure: %v", err)
	}
	if store.appendCalls != 1 {
		t.Fatalf("generic Append failure must never be retried by the pipeline: appends=%d", store.appendCalls)
	}
	assertAIEvidenceRevoked(t, result)
	assertSingleAIEvidenceAudit(t, audit, engagementID)
	assertNoEvidence(t, store, engagementID)
}

func TestAIEvidenceSealFailureRevokesAfterChainHeadConflictExhaustion(t *testing.T) {
	store := newAIEvidenceScriptStore()
	// Evidence.Service owns bounded parent-conflict retries. Seventeen conflicts exhaust that
	// loop; #391 must revoke authority and return the error rather than starting a second loop.
	store.conflictCalls = 17
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	result := aiEvidenceGateExemptResult(t)
	engagementID := shared.ID("eng-conflict")

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", engagementID, time.Unix(100, 0).UTC(), result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("typed error must preserve chain-head conflict: %v", err)
	}
	if store.appendCalls != 17 {
		t.Fatalf("pipeline added an outer conflict retry: appends=%d, want 17 evidence-service attempts", store.appendCalls)
	}
	assertAIEvidenceRevoked(t, result)
	assertSingleAIEvidenceAudit(t, audit, engagementID)
	assertNoEvidence(t, store, engagementID)
}

func TestAIEvidenceAuditFailureJoinsOriginalSealError(t *testing.T) {
	store := newAIEvidenceScriptStore()
	storageErr := errors.New("storage unavailable")
	store.appendFailures[1] = storageErr
	auditErr := errors.New("audit unavailable")
	audit := &aiEvidenceTestAudit{err: auditErr}
	svc := newAIEvidenceService(t, store, audit)
	result := aiEvidenceGateExemptResult(t)

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-audit", time.Unix(100, 0).UTC(), result)
	assertTypedAIEvidenceFailure(t, ref, err, 1)
	if !errors.Is(err, storageErr) || !errors.Is(err, auditErr) {
		t.Fatalf("audit failure must retain both causes: %v", err)
	}
	if store.appendCalls != 1 {
		t.Fatalf("audit failure unexpectedly retried evidence: appends=%d", store.appendCalls)
	}
	assertAIEvidenceRevoked(t, result)
}

func TestAIEvidenceFailureAccountingIsIdempotentAfterRevocation(t *testing.T) {
	store := newAIEvidenceScriptStore()
	store.appendAlways = errors.New("storage unavailable")
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	result := aiEvidenceGateExemptResult(t)
	engagementID := shared.ID("eng-repeat")

	_, _ = svc.sealEvidenceFailClosed(context.Background(), "operator", engagementID, time.Unix(100, 0).UTC(), result)
	firstMetric := result.AITriageBudget.EvidenceSealFailures
	firstRevoked := result.AITriageBudget.EvidenceRevokedExemptions
	firstAudits := len(audit.entries)
	firstWarnings := len(result.SourceWarnings)

	_, err := svc.sealEvidenceFailClosed(context.Background(), "operator", engagementID, time.Unix(100, 0).UTC(), result)
	if err == nil {
		t.Fatal("evidence outage must remain fatal after authority was already revoked")
	}
	var typed *AIEvidenceSealError
	if errors.As(err, &typed) {
		t.Fatalf("already-revoked retry should preserve the underlying #386 error, got %+v", typed)
	}
	if result.AITriageBudget.EvidenceSealFailures != firstMetric || result.AITriageBudget.EvidenceRevokedExemptions != firstRevoked {
		t.Fatalf("retry double-counted metrics: %+v", result.AITriageBudget)
	}
	if len(audit.entries) != firstAudits || len(result.SourceWarnings) != firstWarnings {
		t.Fatalf("retry duplicated audit/warning: audits=%d warnings=%v", len(audit.entries), result.SourceWarnings)
	}
}

func TestEvidenceFailureWithoutAIExemptionPreservesGeneralFailClosedBehavior(t *testing.T) {
	store := newAIEvidenceScriptStore()
	storageErr := errors.New("storage unavailable")
	store.appendFailures[1] = storageErr
	audit := &aiEvidenceTestAudit{}
	svc := newAIEvidenceService(t, store, audit)
	result := &ScanResult{Findings: []finding.Finding{{DedupKey: "ordinary"}}}

	ref, err := svc.sealEvidenceFailClosed(context.Background(), "operator", "eng-ordinary", time.Unix(100, 0).UTC(), result)
	if err == nil || !ref.IsZero() || !errors.Is(err, storageErr) {
		t.Fatalf("non-AI evidence failure must remain the original #386 failure: ref=%q err=%v", ref, err)
	}
	var typed *AIEvidenceSealError
	if errors.As(err, &typed) {
		t.Fatalf("non-AI failure unexpectedly entered AI recovery: %+v", typed)
	}
	if len(audit.entries) != 0 || result.AITriageBudget != nil || len(result.SourceWarnings) != 0 {
		t.Fatalf("non-AI failure mutated AI state: audits=%d budget=%+v warnings=%v", len(audit.entries), result.AITriageBudget, result.SourceWarnings)
	}
}

func TestRevokeAIGateExemptionsClearsForgedPositiveFlags(t *testing.T) {
	result := &ScanResult{AITriage: []ports.AICritique{
		{DedupKey: "forged", GateExempt: true, PolicyVersion: "forged", PolicyReason: "forged"},
		{DedupKey: "ordinary", GateExempt: false, PolicyReason: aiPolicyShadowMode},
	}}
	if got := revokeAIGateExemptions(result); got != 1 {
		t.Fatalf("revoked=%d, want 1", got)
	}
	if result.AITriage[0].GateExempt || !result.AITriage[0].ReviewRequired || result.AITriage[0].PolicyReason != aiPolicyEvidenceSealFailed {
		t.Fatalf("forged positive flag survived revocation: %+v", result.AITriage[0])
	}
	if result.AITriage[1].PolicyReason != aiPolicyShadowMode {
		t.Fatalf("non-exempt critique was mutated: %+v", result.AITriage[1])
	}
}

func TestScanPipelinesUseFailClosedAIEvidenceBoundary(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "service.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, function := range []string{"runPipeline", "runImportedSBOMPipeline"} {
		var target *ast.FuncDecl
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == function {
				target = fn
				break
			}
		}
		if target == nil {
			t.Fatalf("%s not found", function)
		}
		failClosedCalls, rawSealCalls := 0, 0
		ast.Inspect(target.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch selector.Sel.Name {
			case "sealEvidenceFailClosed", "sealEvidenceFailClosedWithID":
				failClosedCalls++
			case "sealEvidence":
				rawSealCalls++
			}
			return true
		})
		if failClosedCalls != 1 || rawSealCalls != 0 {
			t.Fatalf("%s evidence boundary: failClosed=%d raw=%d, want 1/0", function, failClosedCalls, rawSealCalls)
		}
	}
}
