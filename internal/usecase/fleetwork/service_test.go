package fleetwork

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeIDs struct{ n int }

func (g *fakeIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("wo-%d", g.n)) }

type fakeAudit struct {
	n       int
	onceN   int
	onceErr error
	entries []ports.AuditEntry
}

type issueAuditFailureStore struct {
	ports.WorkOrderAuditStore
	err error
}

func (s issueAuditFailureStore) IssueWithAudit(context.Context, *workorder.WorkOrder, ports.FleetAuditIntent) (*workorder.WorkOrder, ports.FleetAuditIntent, error) {
	return nil, ports.FleetAuditIntent{}, s.err
}

func (a *fakeAudit) Record(context.Context, ports.AuditEntry) error { a.n++; return nil }
func (a *fakeAudit) RecordOnce(_ context.Context, entry ports.AuditEntry) error {
	a.onceN++
	a.entries = append(a.entries, entry)
	if a.onceErr != nil {
		err := a.onceErr
		a.onceErr = nil
		return err
	}
	return nil
}

type fakeAuthorizer struct {
	err      error
	requests []ports.ExecutionRequest
}

func (a *fakeAuthorizer) Authorize(_ context.Context, req ports.ExecutionRequest) (time.Time, error) {
	a.requests = append(a.requests, req)
	return time.Unix(1000, 0).UTC(), a.err
}

// compile-time check that the concrete signer satisfies the port (the package itself is
// deliberately stdlib-only, so the assertion lives here where ports is already imported).
var _ ports.WorkOrderSigner = (*worksign.Signer)(nil)

func newSvc(t *testing.T) *Service {
	t.Helper()
	signer, err := worksign.New([]byte("test-key-32-bytes-000000000000000"))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	svc, err := NewService(memory.NewWorkOrderStore(), signer, &fakeAudit{}, fakeClock{t: time.Unix(1000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	svc.SetExecutionAuthorizer(&fakeAuthorizer{})
	return svc
}

func issueInput(idem string, bucket int64) IssueInput {
	return IssueInput{
		TenantID: "t1", AssetID: "as1", AgentID: "ag1", Capability: "scan.source",
		AuthorizationID: "eng1", IdempotencyKey: idem, NotAfter: time.Unix(9999, 0).UTC(), TimeBucket: bucket,
	}
}

func responseIssueInput(t *testing.T, private ed25519.PrivateKey, idem string, bucket int64) IssueInput {
	t.Helper()
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Unix(1000, 0).UTC()
	command := fleetagent.ResponseCommand{
		ProtocolVersion: fleetagent.ResponseCommandProtocolVersion, CommandID: "command-1", TenantID: "t1",
		AgentID: "ag1", AssetID: "as1", EngagementID: "eng1", Action: action, ActionDigest: digest,
		AttemptKey: idem, VerificationChallenge: strings.Repeat("a", 64),
		AuthorizationTarget: engagement.Target{Kind: engagement.TargetDomain, Value: "process-1"}, Target: responsesaga.TargetFingerprint{
			Kind: responsesaga.FingerprintProcess, ProcessAssetID: "as1", ProcessEntityID: "process-1",
		},
		IssuedAt: issuedAt, NotAfter: time.Unix(9999, 0).UTC(), SigningKeyID: evidence.KeyFingerprint(private.Public().(ed25519.PublicKey)),
	}
	command.Signature = fleetagent.SignResponseCommand(private, command)
	return IssueInput{
		TenantID: "t1", AssetID: "as1", AgentID: "ag1", Capability: workorder.CapabilityResponseProcess,
		AuthorizationID: "eng1", IdempotencyKey: idem, NotAfter: command.NotAfter, TimeBucket: bucket,
		ResponseCommand: &command,
	}
}

func TestIssueSignsAndVerifies(t *testing.T) {
	svc := newSvc(t)
	wo, err := svc.Issue(context.Background(), "actor", issueInput("idem1", 1))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if wo.Signature == "" {
		t.Fatalf("issued order must be signed")
	}
	if !svc.Verify(wo) {
		t.Fatalf("issued order must verify")
	}
	// Tampering with an authorising field invalidates the signature.
	wo.Capability = "scan.host"
	if svc.Verify(wo) {
		t.Fatalf("tampered order must not verify")
	}
}

func TestIssueLeavesPendingAuditIntentAfterDeliveryFailure(t *testing.T) {
	signer, err := worksign.New([]byte("test-key-32-bytes-000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	store := memory.NewWorkOrderStore()
	audit := &fakeAudit{onceErr: errors.New("audit unavailable")}
	svc, err := NewService(store, signer, audit, fakeClock{t: time.Unix(1000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	input := issueInput("pending-audit", 91)
	if _, err := svc.Issue(context.Background(), "actor", input); err == nil {
		t.Fatal("audit delivery failure must be returned")
	}
	order, err := store.GetByIdempotencyKey(context.Background(), input.TenantID, input.IdempotencyKey)
	if err != nil || order.State != workorder.StateIssued {
		t.Fatalf("atomically issued order missing: order=%+v err=%v", order, err)
	}
	pending, err := store.ListPendingFleetAudits(shared.WithTenant(context.Background(), input.TenantID))
	if err != nil || len(pending) != 1 || pending[0].Entry.Target != order.ID.String() {
		t.Fatalf("pending audit intent=%+v err=%v", pending, err)
	}
}

func TestIssueDoesNotPersistOrderWhenAtomicAuditWriteFails(t *testing.T) {
	signer, err := worksign.New([]byte("test-key-32-bytes-000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	backing := memory.NewWorkOrderStore()
	svc, err := NewService(issueAuditFailureStore{WorkOrderAuditStore: backing, err: errors.New("outbox unavailable")}, signer, &fakeAudit{}, fakeClock{t: time.Unix(1000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	input := issueInput("atomic-failure", 92)
	if _, err := svc.Issue(context.Background(), "actor", input); err == nil {
		t.Fatal("atomic persistence failure must be returned")
	}
	if _, err := backing.GetByIdempotencyKey(context.Background(), input.TenantID, input.IdempotencyKey); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("order persisted despite failed atomic audit write: %v", err)
	}
}

func TestIssueIdempotent(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	first, err := svc.Issue(ctx, "actor", issueInput("idem1", 1))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := svc.Issue(ctx, "actor", issueInput("idem1", 1))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("idempotent issue must return the same order: %q vs %q", first.ID, second.ID)
	}
}

func TestIssueCarriesSignedHighPriorityResponseCommand(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(t)
	ctx := context.Background()
	input := responseIssueInput(t, private, "response-attempt-1", 2)
	order, err := svc.Issue(ctx, "actor", input)
	if err != nil {
		t.Fatalf("issue response order: %v", err)
	}
	if order.Priority != workorder.ResponsePriority || order.ResponseCommand == nil || !svc.Verify(order) {
		t.Fatalf("response order is not signed/high-priority: %+v", order)
	}

	tampered := responseIssueInput(t, private, "response-attempt-1", 2)
	tampered.ResponseCommand.HaltGeneration++
	tampered.ResponseCommand.Signature = fleetagent.SignResponseCommand(private, *tampered.ResponseCommand)
	if _, err := svc.Issue(ctx, "actor", tampered); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("idempotency key reuse with another response command must conflict, got %v", err)
	}
}

func TestCompleteResponsePersistsExactResultIdempotently(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(t)
	ctx := context.Background()
	order, err := svc.Issue(ctx, "operator", responseIssueInput(t, private, "response-result-1", 3))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); err != nil {
		t.Fatal(err)
	}
	result := fleetagent.ResponseExecutionResult{
		AttemptKey: order.ResponseCommand.AttemptKey, CommandDigest: fleetagent.ResponseCommandDigest(*order.ResponseCommand),
		LeaseID: claimed[0].LeaseID, State: fleetagent.ResponseExecutionApplied, ObservedRadius: "state_changing",
		AffectedCount: 1, CompletedAt: time.Unix(1001, 0).UTC(),
	}
	const reason = "response command applied; awaiting independent verification"
	if err := svc.CompleteResponse(ctx, "agent", "t1", order.ID, result, reason); err != nil {
		t.Fatalf("complete response: %v", err)
	}
	svc.clock = fakeClock{t: order.NotAfter.Add(time.Second)}
	if err := svc.CompleteResponse(ctx, "agent", "t1", order.ID, result, reason); err != nil {
		t.Fatalf("exact terminal retry after expiry must remain idempotent: %v", err)
	}
	stored, err := svc.GetByID(ctx, "t1", order.ID)
	if err != nil || stored.State != workorder.StateSucceeded || stored.ResponseResult == nil ||
		!fleetagent.SameResponseExecutionResult(*stored.ResponseResult, result) {
		t.Fatalf("stored response result=%+v err=%v", stored, err)
	}
	changed := result
	changed.AffectedCount = 2
	if err := svc.CompleteResponse(ctx, "agent", "t1", order.ID, changed, reason); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed terminal retry must conflict, got %v", err)
	}
}

func TestCompleteResponseExactRetryRepairsFailedAuditDelivery(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := worksign.New([]byte("test-key-32-bytes-000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	audit := &fakeAudit{}
	svc, err := NewService(memory.NewWorkOrderStore(), signer, audit, fakeClock{t: time.Unix(1000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetExecutionAuthorizer(&fakeAuthorizer{})
	ctx := context.Background()
	order, err := svc.Issue(ctx, "operator", responseIssueInput(t, private, "response-result-audit-retry", 30))
	if err != nil {
		t.Fatal(err)
	}
	audit.onceErr = errors.New("audit unavailable")
	issueAuditCount := audit.onceN
	claimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); err != nil {
		t.Fatal(err)
	}
	result := fleetagent.ResponseExecutionResult{
		AttemptKey: order.ResponseCommand.AttemptKey, CommandDigest: fleetagent.ResponseCommandDigest(*order.ResponseCommand),
		LeaseID: claimed[0].LeaseID, State: fleetagent.ResponseExecutionApplied, ObservedRadius: "state_changing",
		AffectedCount: 1, CompletedAt: time.Unix(1001, 0).UTC(),
	}
	const reason = "response command applied; awaiting independent verification"
	if err := svc.CompleteResponse(ctx, "agent", "t1", order.ID, result, reason); err == nil {
		t.Fatal("first completion must report failed audit delivery")
	}
	stored, err := svc.GetByID(ctx, "t1", order.ID)
	if err != nil || stored.ResponseResult == nil {
		t.Fatalf("terminal result must remain durable across audit outage: stored=%+v err=%v", stored, err)
	}
	if err := svc.CompleteResponse(ctx, "agent", "t1", order.ID, result, reason); err != nil {
		t.Fatalf("exact retry must repair audit delivery: %v", err)
	}
	if audit.onceN != issueAuditCount+2 || len(audit.entries) != issueAuditCount+2 ||
		audit.entries[issueAuditCount].Metadata["idempotency_key"] != audit.entries[issueAuditCount+1].Metadata["idempotency_key"] ||
		!audit.entries[issueAuditCount].At.Equal(audit.entries[issueAuditCount+1].At) {
		t.Fatalf("audit retries must carry one deterministic identity: %+v", audit.entries)
	}
}

func TestResponseTerminalTransitionRequiresStructuredResult(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(t)
	ctx := context.Background()
	order, err := svc.Issue(ctx, "operator", responseIssueInput(t, private, "response-transition-1", 4))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateSucceeded, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("response terminal transition without result must fail, got %v", err)
	}
}

func TestCompleteResponseRejectsExpiredLease(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(t)
	ctx := context.Background()
	order, err := svc.Issue(ctx, "operator", responseIssueInput(t, private, "response-expired-result", 31))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); err != nil {
		t.Fatal(err)
	}
	svc.clock = fakeClock{t: claimed[0].LeaseUntil}
	result := fleetagent.ResponseExecutionResult{
		AttemptKey: order.ResponseCommand.AttemptKey, CommandDigest: fleetagent.ResponseCommandDigest(*order.ResponseCommand),
		LeaseID: claimed[0].LeaseID, State: fleetagent.ResponseExecutionApplied, ObservedRadius: "state_changing",
		AffectedCount: 1, CompletedAt: claimed[0].LeaseUntil.Add(-time.Second),
	}
	if err := svc.CompleteResponse(ctx, "agent", "t1", order.ID, result, "late result"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("late terminal result error=%v, want forbidden", err)
	}
	stored, err := svc.GetByID(ctx, "t1", order.ID)
	if err != nil || stored.ResponseResult != nil || stored.State != workorder.StateRunning {
		t.Fatalf("late result mutated order: %+v err=%v", stored, err)
	}
}

func TestClaimPrioritizesResponseOrders(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(t)
	ctx := context.Background()
	if _, err := svc.Issue(ctx, "actor", issueInput("inventory-1", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Issue(ctx, "actor", responseIssueInput(t, private, "response-1", 2)); err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Claim(ctx, "actor", "t1", "ag1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].Capability != workorder.CapabilityResponseProcess {
		t.Fatalf("first claim=%+v, want response order", claimed)
	}
}

func TestTransitionExpiresClaimedOrderBeforeExecution(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	order, err := svc.Issue(ctx, "actor", issueInput("expires-before-progress", 3))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	svc.clock = fakeClock{t: time.Unix(9999, 0).UTC()}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("expired progress must fail closed, got %v", err)
	}
	stored, err := svc.GetByID(ctx, "t1", order.ID)
	if err != nil || stored.State != workorder.StateExpired {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
}

func TestIssueInFlightConflict(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	if _, err := svc.Issue(ctx, "actor", issueInput("idem1", 1)); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Different idempotency key, same (asset, capability, bucket) while the first is live.
	_, err := svc.Issue(ctx, "actor", issueInput("idem2", 1))
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected in-flight conflict, got %v", err)
	}
}

func TestClaimIsAddressed(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	if _, err := svc.Issue(ctx, "actor", issueInput("idem1", 1)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Another agent claims nothing.
	got, err := svc.Claim(ctx, "actor", "t1", "ag2", 10)
	if err != nil {
		t.Fatalf("claim ag2: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ag2 must not claim ag1's order, got %d", len(got))
	}
	// The addressed agent claims it and it becomes claimed.
	got, err = svc.Claim(ctx, "actor", "t1", "ag1", 10)
	if err != nil {
		t.Fatalf("claim ag1: %v", err)
	}
	if len(got) != 1 || got[0].State != workorder.StateClaimed {
		t.Fatalf("ag1 should claim one order into claimed, got %+v", got)
	}
	// Re-claim returns nothing (already claimed).
	got, err = svc.Claim(ctx, "actor", "t1", "ag1", 10)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("no issued orders left to claim, got %d", len(got))
	}
}

func TestExpiredRunningLeaseIsReclaimedAndFencesStaleResult(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	order, err := svc.Issue(ctx, "actor", issueInput("lease-reclaim", 1))
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, first[0].LeaseID, workorder.StateRunning, ""); err != nil {
		t.Fatalf("start first lease: %v", err)
	}
	svc.clock = fakeClock{t: first[0].LeaseUntil.Add(time.Second)}
	second, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(second) != 1 || second[0].LeaseID == first[0].LeaseID {
		t.Fatalf("reclaimed order=%+v first=%+v err=%v", second, first, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, first[0].LeaseID, workorder.StateRunning, ""); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("stale lease transition must fail closed, got %v", err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, second[0].LeaseID, workorder.StateRunning, ""); err != nil {
		t.Fatalf("current lease transition: %v", err)
	}
}

func TestRunningOrderExpiresWhenAuthorizationEnds(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	order, err := svc.Issue(ctx, "actor", issueInput("running-auth-expiry", 32))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); err != nil {
		t.Fatal(err)
	}
	svc.clock = fakeClock{t: order.NotAfter}
	reclaimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(reclaimed) != 0 {
		t.Fatalf("expired running order was reclaimed: %+v err=%v", reclaimed, err)
	}
	stored, err := svc.GetByID(ctx, "t1", order.ID)
	if err != nil || stored.State != workorder.StateExpired {
		t.Fatalf("expired running order=%+v err=%v", stored, err)
	}
}

func TestResponseTransitionReauthorizesAtExecutionBoundary(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(t)
	guard := &fakeAuthorizer{err: fmt.Errorf("%w: engagement scope was revoked", shared.ErrForbidden)}
	svc.SetExecutionAuthorizer(guard)
	ctx := context.Background()
	order, err := svc.Issue(ctx, "operator", responseIssueInput(t, private, "response-reauthorize", 33))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("revoked authorization must block endpoint execution, got %v", err)
	}
	stored, err := svc.GetByID(ctx, "t1", order.ID)
	if err != nil || stored.State != workorder.StateRefused {
		t.Fatalf("denied response order=%+v err=%v", stored, err)
	}
	if len(guard.requests) != 1 || guard.requests[0].Action != "response.stop_process" ||
		guard.requests[0].Target != order.ResponseCommand.AuthorizationTarget || guard.requests[0].EngagementID != "eng1" {
		t.Fatalf("execution authorization request is not command-bound: %+v", guard.requests)
	}
}

func TestResponseTransitionRequiresExecutionAuthorizer(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(t)
	svc.SetExecutionAuthorizer(nil)
	ctx := context.Background()
	order, err := svc.Issue(ctx, "operator", responseIssueInput(t, private, "response-no-authorizer", 34))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Claim(ctx, "agent", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "agent", "t1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("missing execution authorizer must fail closed, got %v", err)
	}
	stored, err := svc.GetByID(ctx, "t1", order.ID)
	if err != nil || stored.State != workorder.StateClaimed {
		t.Fatalf("failed authorization mutated order: %+v err=%v", stored, err)
	}
}

func TestTransitionRules(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	wo, err := svc.Issue(ctx, "actor", issueInput("idem1", 1))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Illegal: issued -> succeeded.
	if err := svc.Transition(ctx, "actor", "t1", wo.ID, "", workorder.StateSucceeded, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected illegal-transition validation error, got %v", err)
	}
	// Legal: claim -> running -> succeeded.
	claimed, err := svc.Claim(ctx, "actor", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 || claimed[0].ID != wo.ID {
		t.Fatalf("claim: orders=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "actor", "t1", wo.ID, claimed[0].LeaseID, workorder.StateRunning, ""); err != nil {
		t.Fatalf("claimed->running: %v", err)
	}
	if err := svc.Transition(ctx, "actor", "t1", wo.ID, claimed[0].LeaseID, workorder.StateSucceeded, ""); err != nil {
		t.Fatalf("running->succeeded: %v", err)
	}
	// Refusal requires a reason.
	wo2, _ := svc.Issue(ctx, "actor", issueInput("idem2", 2))
	claimed, err = svc.Claim(ctx, "actor", "t1", "ag1", 1)
	if err != nil || len(claimed) != 1 || claimed[0].ID != wo2.ID {
		t.Fatalf("claim second order: orders=%+v err=%v", claimed, err)
	}
	if err := svc.Transition(ctx, "actor", "t1", wo2.ID, claimed[0].LeaseID, workorder.StateRefused, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("refusal without reason must fail, got %v", err)
	}
	if err := svc.Transition(ctx, "actor", "t1", wo2.ID, claimed[0].LeaseID, workorder.StateRefused, "unsupported capability"); err != nil {
		t.Fatalf("refusal with reason: %v", err)
	}
}
