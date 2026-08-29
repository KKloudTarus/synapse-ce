package privacypolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const testTenant = shared.ID("tenant-privacy-1")

type privacyPolicyStoreFake struct {
	mu            sync.RWMutex
	policies      map[string]privacy.Assignment
	digestVersion map[string]string
	active        map[shared.ID]string
	activations   map[shared.ID][]privacy.Activation
	operations    map[string]privacy.Activation
	pending       map[fakePrivacyAuditKey]ports.FleetAuditIntent
}

func newPrivacyPolicyStoreFake() *privacyPolicyStoreFake {
	return &privacyPolicyStoreFake{
		policies:      make(map[string]privacy.Assignment),
		digestVersion: make(map[string]string),
		active:        make(map[shared.ID]string),
		activations:   make(map[shared.ID][]privacy.Activation),
		operations:    make(map[string]privacy.Activation),
		pending:       make(map[fakePrivacyAuditKey]ports.FleetAuditIntent),
	}
}

func (s *privacyPolicyStoreFake) PutPrivacyPolicy(ctx context.Context, assignment privacy.Assignment) (bool, error) {
	tenantID, err := fakePrivacyTenant(ctx, assignment.TenantID)
	if err != nil {
		return false, err
	}
	assignment.TenantID = tenantID
	if err := assignment.Validate(); err != nil {
		return false, err
	}
	key := fakePrivacyPolicyKey(tenantID, assignment.Policy.Version)
	digestKey := fakePrivacyPolicyKey(tenantID, assignment.Digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.policies[key]; ok {
		if !privacy.SameAssignment(existing, assignment) {
			return false, shared.ErrConflict
		}
		return false, nil
	}
	if version, ok := s.digestVersion[digestKey]; ok && version != assignment.Policy.Version {
		return false, shared.ErrConflict
	}
	s.policies[key] = assignment
	s.digestVersion[digestKey] = assignment.Policy.Version
	return true, nil
}

func (s *privacyPolicyStoreFake) ActivatePrivacyPolicy(ctx context.Context, activation privacy.Activation) (privacy.Activation, error) {
	tenantID, err := fakePrivacyTenant(ctx, activation.TenantID)
	if err != nil {
		return privacy.Activation{}, err
	}
	activation.TenantID = tenantID
	validation := activation
	if validation.Revision == 0 {
		validation.Revision = 1
	}
	if err := validation.Validate(); err != nil {
		return privacy.Activation{}, err
	}
	operationKey := fakePrivacyPolicyKey(tenantID, activation.OperationID.String())
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.operations[operationKey]; ok {
		if existing.PolicyDigest != activation.PolicyDigest || existing.PolicyVersion != activation.PolicyVersion || existing.ActivatedBy != activation.ActivatedBy {
			return privacy.Activation{}, shared.ErrConflict
		}
		return existing, nil
	}
	assignment, ok := s.policies[fakePrivacyPolicyKey(tenantID, activation.PolicyVersion)]
	if !ok || assignment.Digest != activation.PolicyDigest {
		return privacy.Activation{}, shared.ErrNotFound
	}
	activation.Revision = uint64(len(s.activations[tenantID]) + 1)
	s.activations[tenantID] = append(s.activations[tenantID], activation)
	s.operations[operationKey] = activation
	s.active[tenantID] = activation.PolicyVersion
	return activation, nil
}

func (s *privacyPolicyStoreFake) ActivatePrivacyPolicyWithAudit(ctx context.Context, activation privacy.Activation, intent ports.FleetAuditIntent) (privacy.Activation, ports.FleetAuditIntent, error) {
	admitted, err := s.ActivatePrivacyPolicy(ctx, activation)
	if err != nil {
		return privacy.Activation{}, ports.FleetAuditIntent{}, err
	}
	// Mirror the real adapters: clone before mutating, so the caller's own intention
	// cannot silently track what this store committed.
	intent, err = intent.Normalize()
	if err != nil {
		return privacy.Activation{}, ports.FleetAuditIntent{}, err
	}
	intent.Entry.At = admitted.ActivatedAt
	intent.Entry.Metadata["revision"] = fmt.Sprintf("%d", admitted.Revision)
	tenantID, err := fakePrivacyTenant(ctx, activation.TenantID)
	if err != nil {
		return privacy.Activation{}, ports.FleetAuditIntent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fakePrivacyAuditKey{tenant: tenantID, id: intent.ID}
	if existing, ok := s.pending[key]; ok && !existing.Entry.At.Equal(intent.Entry.At) {
		return privacy.Activation{}, ports.FleetAuditIntent{}, shared.ErrConflict
	}
	s.pending[key] = intent
	return admitted, intent, nil
}

func (s *privacyPolicyStoreFake) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	tenantID, err := fakePrivacyTenant(ctx, "")
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ports.FleetAuditIntent, 0)
	for key, intent := range s.pending {
		if key.tenant == tenantID {
			out = append(out, intent)
		}
	}
	return out, nil
}

func (s *privacyPolicyStoreFake) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	tenantID, err := fakePrivacyTenant(ctx, "")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, fakePrivacyAuditKey{tenant: tenantID, id: id})
	return nil
}

func (s *privacyPolicyStoreFake) ActivePrivacyPolicy(ctx context.Context, tenantID shared.ID) (privacy.Assignment, error) {
	tenantID, err := fakePrivacyTenant(ctx, tenantID)
	if err != nil {
		return privacy.Assignment{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	version, ok := s.active[tenantID]
	if !ok {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	return s.policies[fakePrivacyPolicyKey(tenantID, version)], nil
}

func (s *privacyPolicyStoreFake) PrivacyPolicyByDigest(ctx context.Context, tenantID shared.ID, digest string) (privacy.Assignment, error) {
	tenantID, err := fakePrivacyTenant(ctx, tenantID)
	if err != nil {
		return privacy.Assignment{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	version, ok := s.digestVersion[fakePrivacyPolicyKey(tenantID, digest)]
	if !ok {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	return s.policies[fakePrivacyPolicyKey(tenantID, version)], nil
}

func (s *privacyPolicyStoreFake) PrivacyPolicyHistory(ctx context.Context, tenantID shared.ID) ([]privacy.Assignment, error) {
	tenantID, err := fakePrivacyTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]privacy.Assignment, 0)
	for _, assignment := range s.policies {
		if assignment.TenantID == tenantID {
			items = append(items, assignment)
		}
	}
	return items, nil
}

func (s *privacyPolicyStoreFake) PrivacyPolicyActivationHistory(ctx context.Context, tenantID shared.ID) ([]privacy.Activation, error) {
	tenantID, err := fakePrivacyTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]privacy.Activation(nil), s.activations[tenantID]...), nil
}

func fakePrivacyTenant(ctx context.Context, requested shared.ID) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() || (!requested.IsZero() && requested != tenantID) {
		return "", shared.ErrForbidden
	}
	return tenantID, nil
}

func fakePrivacyPolicyKey(tenantID shared.ID, value string) string {
	return tenantID.String() + ":" + value
}

// fakePrivacyAuditKey mirrors the real adapters: tenant and intention are separate
// fields, because intention ids contain colons and a concatenated key would let one
// tenant's sweep reach another's obligation.
type fakePrivacyAuditKey struct {
	tenant shared.ID
	id     string
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type recordingAudit struct {
	mu         sync.Mutex
	failAction string
	keys       map[string]int
	last       map[string]ports.AuditEntry
	failed     map[string]ports.AuditEntry
}

func (a *recordingAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failAction != "" && e.Action == a.failAction {
		return errors.New("audit store unavailable")
	}
	if a.last == nil {
		a.last = map[string]ports.AuditEntry{}
	}
	a.last[e.Action] = e
	return nil
}

// RecordOnce collapses exact retries on the deterministic key, mirroring the durable adapters.
func (a *recordingAudit) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	key := e.Metadata["idempotency_key"]
	if key == "" {
		return a.Record(ctx, e)
	}
	a.mu.Lock()
	if a.failAction != "" && e.Action == a.failAction {
		if a.failed == nil {
			a.failed = map[string]ports.AuditEntry{}
		}
		a.failed[key] = e
		a.mu.Unlock()
		return errors.New("audit store unavailable")
	}
	if a.keys == nil {
		a.keys = map[string]int{}
	}
	if a.keys[key] > 0 {
		a.mu.Unlock()
		return nil
	}
	a.keys[key]++
	a.mu.Unlock()
	return a.Record(ctx, e)
}

func (a *recordingAudit) count(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.keys[key]
}

func (a *recordingAudit) failedEntry(key string) ports.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.failed[key]
}

func newTestService(t *testing.T) (*Service, *recordingAudit, context.Context) {
	t.Helper()
	audit := &recordingAudit{}
	svc, err := NewService(newPrivacyPolicyStoreFake(), audit, fixedClock{now: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return svc, audit, shared.WithTenant(context.Background(), testTenant)
}

func TestNewServiceRejectsMissingDependencies(t *testing.T) {
	store := newPrivacyPolicyStoreFake()
	audit := &recordingAudit{}
	clock := fixedClock{now: time.Now().UTC()}
	for _, tc := range []struct {
		name  string
		store ports.PrivacyPolicyAuditStore
		audit ports.IdempotentAuditLogger
		clock ports.Clock
	}{
		{name: "store", audit: audit, clock: clock},
		{name: "audit", store: store, clock: clock},
		{name: "clock", store: store, audit: audit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewService(tc.store, tc.audit, tc.clock); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("NewService() error = %v, want validation", err)
			}
		})
	}
}

func TestAdmitAndActivateAreAuditedAndIdempotent(t *testing.T) {
	svc, audit, ctx := newTestService(t)
	assignment, created, err := svc.Admit(ctx, "operator", privacy.DefaultPolicy())
	if err != nil || !created {
		t.Fatalf("Admit() created=%t err=%v", created, err)
	}
	admitKey := "fleet.privacy_policy.admit:" + testTenant.String() + ":" + assignment.Digest
	if got := audit.count(admitKey); got != 1 {
		t.Fatalf("admit audit lines = %d, want 1", got)
	}

	// Re-admitting identical immutable content is not a new policy and must not duplicate the audit.
	if _, created, err := svc.Admit(ctx, "operator", privacy.DefaultPolicy()); err != nil || created {
		t.Fatalf("re-admit created=%t err=%v, want created=false", created, err)
	}
	if got := audit.count(admitKey); got != 1 {
		t.Fatalf("admit audit lines after retry = %d, want 1", got)
	}

	if _, err := svc.Activate(ctx, "operator", assignment.Digest, "activate-1"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	activateKey := "fleet.privacy_policy.activate:" + testTenant.String() + ":activate-1"
	if got := audit.count(activateKey); got != 1 {
		t.Fatalf("activate audit lines = %d, want 1", got)
	}
	if e := audit.last["fleet.privacy_policy.activate"]; e.Actor != "operator" ||
		e.Metadata["digest"] != assignment.Digest || e.Metadata["operation_id"] != "activate-1" ||
		e.Metadata["revision"] != "1" {
		t.Fatalf("activation audit must name the actor, operation, revision and digest, got %+v", e)
	}
}

// TestAuditFailureSurfacesAndRetryRepairs proves privacy-policy governance never silently loses its
// attribution: a failed audit is returned to the caller, and because admission and activation are
// both idempotent an exact retry repairs the missing line exactly once.
func TestAuditFailureSurfacesAndRetryRepairs(t *testing.T) {
	svc, audit, ctx := newTestService(t)
	audit.failAction = "fleet.privacy_policy.admit"
	if _, _, err := svc.Admit(ctx, "operator", privacy.DefaultPolicy()); err == nil {
		t.Fatal("a failed admission audit must surface, never be discarded")
	}

	audit.failAction = ""
	assignment, _, err := svc.Admit(ctx, "operator", privacy.DefaultPolicy())
	if err != nil {
		t.Fatalf("admit retry must repair the audit: %v", err)
	}
	admitKey := "fleet.privacy_policy.admit:" + testTenant.String() + ":" + assignment.Digest
	if got := audit.count(admitKey); got != 1 {
		t.Fatalf("repaired admit audit lines = %d, want 1", got)
	}

	audit.failAction = "fleet.privacy_policy.activate"
	if _, err := svc.Activate(ctx, "operator", assignment.Digest, "activate-1"); err == nil {
		t.Fatal("a failed activation audit must surface, never be discarded")
	}
	activateKey := "fleet.privacy_policy.activate:" + testTenant.String() + ":activate-1"
	failed := audit.failedEntry(activateKey)
	audit.failAction = ""
	if _, err := svc.Activate(ctx, "operator", assignment.Digest, "activate-1"); err != nil {
		t.Fatalf("activation retry must repair the audit: %v", err)
	}
	if got := audit.count(activateKey); got != 1 {
		t.Fatalf("repaired activate audit lines = %d, want 1", got)
	}
	if recorded := audit.last["fleet.privacy_policy.activate"]; recorded.At != failed.At ||
		recorded.Metadata["revision"] != failed.Metadata["revision"] ||
		recorded.Metadata["operation_id"] != failed.Metadata["operation_id"] ||
		recorded.Metadata["digest"] != failed.Metadata["digest"] {
		t.Fatalf("activation retry changed immutable audit metadata: failed=%+v recorded=%+v", failed, recorded)
	}
}

func TestActivationPreservesEveryIntentionalTransition(t *testing.T) {
	svc, audit, ctx := newTestService(t)
	v1, _, err := svc.Admit(ctx, "operator", privacy.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	policyV2 := privacy.DefaultPolicy()
	policyV2.Version = "tenant:v2"
	policyV2.MaxArgLen = 1024
	v2, _, err := svc.Admit(ctx, "operator", policyV2)
	if err != nil {
		t.Fatal(err)
	}

	for _, step := range []struct {
		digest, operationID, revision string
	}{
		{v1.Digest, "activate-v1", "1"},
		{v2.Digest, "activate-v2", "2"},
		{v1.Digest, "reactivate-v1", "3"},
	} {
		if _, err := svc.Activate(ctx, "operator", step.digest, shared.ID(step.operationID)); err != nil {
			t.Fatalf("activate %s: %v", step.operationID, err)
		}
		key := "fleet.privacy_policy.activate:" + testTenant.String() + ":" + step.operationID
		if got := audit.count(key); got != 1 {
			t.Fatalf("activation %s audit lines = %d, want 1", step.operationID, got)
		}
		if got := audit.last["fleet.privacy_policy.activate"].Metadata["revision"]; got != step.revision {
			t.Fatalf("activation %s revision = %s, want %s", step.operationID, got, step.revision)
		}
	}
	active, err := svc.Active(ctx)
	if err != nil || active.Digest != v1.Digest {
		t.Fatalf("active after A -> B -> A = %#v/%v, want v1", active, err)
	}
	if _, err := svc.Activate(ctx, "other-operator", v2.Digest, "activate-v1"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("contradictory operation reuse = %v, want conflict", err)
	}
}

func TestGovernanceRequiresTenantActorAndDigest(t *testing.T) {
	svc, _, ctx := newTestService(t)
	if _, _, err := svc.Admit(context.Background(), "operator", privacy.DefaultPolicy()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("admit without a tenant = %v, want forbidden", err)
	}
	if _, err := svc.Activate(ctx, "", "digest", "activate-invalid"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("activation without an actor = %v, want validation", err)
	}
	if _, err := svc.Activate(ctx, "operator", "  ", "activate-invalid"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("activation without a digest = %v, want validation", err)
	}
	if _, err := svc.Activate(ctx, "operator", "digest", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("activation without an operation id = %v, want validation", err)
	}
}
