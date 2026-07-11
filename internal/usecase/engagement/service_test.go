package engagement

import (
	"context"
	"errors"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// --- fakes ---

type memRepo struct {
	data map[shared.ID]*domain.Engagement
}

func newMemRepo() *memRepo { return &memRepo{data: map[shared.ID]*domain.Engagement{}} }

func (r *memRepo) Create(_ context.Context, e *domain.Engagement) error { r.data[e.ID] = e; return nil }
func (r *memRepo) Update(_ context.Context, e *domain.Engagement) error {
	if _, ok := r.data[e.ID]; !ok {
		return shared.ErrNotFound
	}
	r.data[e.ID] = e
	return nil
}
func (r *memRepo) Delete(_ context.Context, id shared.ID) error {
	delete(r.data, id)
	return nil
}
func (r *memRepo) GetByID(_ context.Context, id shared.ID) (*domain.Engagement, error) {
	e, ok := r.data[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return e, nil
}
func (r *memRepo) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*domain.Engagement, error) {
	e, ok := r.data[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if !tenantID.IsZero() && e.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return e, nil
}
func (r *memRepo) List(context.Context, shared.ID) ([]*domain.Engagement, error) { return nil, nil }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type fixedIDs struct{}

func (fixedIDs) NewID() shared.ID { return shared.ID("eng-1") }

type capAudit struct{ entries []ports.AuditEntry }

func (a *capAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}
func (a *capAudit) has(action string) bool {
	for _, e := range a.entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

// TestEngagementOwnership covers ownership: Create stamps the engagement owner
// (created_by) from the actor; a later mutation by a different actor updates updated_by but
// the owner (created_by) is immutable – the basis for per-engagement RBAC.
func TestEngagementOwnership(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	svc := NewService(newMemRepo(), fixedClock{now}, fixedIDs{}, &capAudit{})

	e, err := svc.Create(ctx, CreateInput{Name: "Acme", Client: "Acme", CreatedBy: "alice"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if e.Audit.CreatedBy != "alice" || e.Audit.UpdatedBy != "alice" {
		t.Fatalf("create must stamp the owner: created_by=%q updated_by=%q", e.Audit.CreatedBy, e.Audit.UpdatedBy)
	}
	got, err := svc.UpdateScope(ctx, "bob", "", e.ID, []domain.Target{{Kind: domain.TargetDomain, Value: "acme.io"}}, nil)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Audit.CreatedBy != "alice" {
		t.Errorf("owner (created_by) must be immutable across mutations, got %q", got.Audit.CreatedBy)
	}
	if got.Audit.UpdatedBy != "bob" {
		t.Errorf("updated_by must record the last modifier, got %q", got.Audit.UpdatedBy)
	}
}

func TestEngagementMutationsAndGatePickup(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	repo := newMemRepo()
	audit := &capAudit{}
	svc := NewService(repo, fixedClock{now}, fixedIDs{}, audit)

	e, err := svc.Create(ctx, CreateInput{Name: "Acme", Client: "Acme"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := e.ID

	// UpdateScope persists + audits.
	if _, err := svc.UpdateScope(ctx, "operator", "", id,
		[]domain.Target{{Kind: domain.TargetDomain, Value: "*.acme.io"}}, nil); err != nil {
		t.Fatalf("UpdateScope: %v", err)
	}
	if got, _ := repo.GetByID(ctx, id); len(got.Scope.InScope) != 1 {
		t.Errorf("scope not persisted")
	}
	if !audit.has("engagement.scope.update") {
		t.Error("scope update not audited")
	}

	// AC: a Guard over the SAME repo picks up the scope change live (no restart):
	// the just-added subdomain is allowed, an unrelated host denied.
	guard, err := execution.NewGuard(repo, fixedClock{now}, audit)
	if err != nil {
		t.Fatal(err)
	}
	req := func(host string) execution.Request {
		return execution.Request{Actor: "op", EngagementID: id, Action: "recon.test",
			Target: domain.Target{Kind: domain.TargetDomain, Value: host}}
	}
	if _, err := guard.Authorize(ctx, req("api.acme.io")); err != nil {
		t.Errorf("gate should allow newly in-scope target: %v", err)
	}
	if _, err := guard.Authorize(ctx, req("evil.com")); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("gate should deny out-of-scope target, got %v", err)
	}

	// SetWindow persists + audits.
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	if _, err := svc.SetWindow(ctx, "operator", "", id, &from, &to, "UTC"); err != nil {
		t.Fatalf("SetWindow: %v", err)
	}
	if !audit.has("engagement.window.update") {
		t.Error("window update not audited")
	}

	// RoE: restrict to the sca tool class; the gate then denies a recon-class
	// action even though scope + window + status all pass.
	if _, err := svc.SetRoE(ctx, "operator", "", id, domain.RoE{AllowedToolClasses: []domain.ToolClass{"sca"}}); err != nil {
		t.Fatalf("SetRoE: %v", err)
	}
	if !audit.has("engagement.roe.update") {
		t.Error("roe update not audited")
	}
	if _, err := guard.Authorize(ctx, execution.Request{Actor: "op", EngagementID: id, Action: "recon.subfinder",
		Target: domain.Target{Kind: domain.TargetDomain, Value: "api.acme.io"}}); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("RoE should deny a recon action when only sca is allowed, got %v", err)
	}

	// Lifecycle: draft -> active -> completed; completed blocks execution.
	if _, err := svc.Transition(ctx, "operator", "", id, domain.StatusActive); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := svc.Transition(ctx, "operator", "", id, domain.StatusCompleted); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got, _ := repo.GetByID(ctx, id); got.AllowsExecution() {
		t.Error("completed engagement must not allow execution")
	}
	if !audit.has("engagement.transition") {
		t.Error("transition not audited")
	}

	// Illegal transition + missing actor are rejected.
	if _, err := svc.Transition(ctx, "operator", "", id, domain.StatusActive); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("completed->active should be ErrValidation, got %v", err)
	}
	if _, err := svc.UpdateScope(ctx, "  ", "", id, nil, nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty actor should be ErrValidation, got %v", err)
	}
}

// TestSetLiveReconRequiresAttestation covers enabling live
// recon requires an AUP re-confirm + a recorded lab-authorization attestation, both
// captured in the audit record; disabling requires neither.
func TestSetLiveReconRequiresAttestation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	repo := newMemRepo()
	audit := &capAudit{}
	svc := NewService(repo, fixedClock{now}, fixedIDs{}, audit)
	e, err := svc.Create(ctx, CreateInput{Name: "Acme", Client: "Acme"})
	if err != nil {
		t.Fatal(err)
	}

	// Enabling without the AUP re-confirm / attestation is refused.
	if _, err := svc.SetLiveRecon(ctx, "op", "", e.ID, true, "", "I attest"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("enabling without an AUP version must be refused, got %v", err)
	}
	if _, err := svc.SetLiveRecon(ctx, "op", "", e.ID, true, "1.0", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("enabling without an attestation must be refused, got %v", err)
	}

	// With both, it succeeds and the attestation + AUP version are in the audit record.
	if _, err := svc.SetLiveRecon(ctx, "op", "", e.ID, true, "1.0", "I confirm legal authorization for live testing of this scope"); err != nil {
		t.Fatalf("enabling with attestation should succeed: %v", err)
	}
	var found *ports.AuditEntry
	for i := range audit.entries {
		if audit.entries[i].Action == "engagement.live_recon.update" {
			found = &audit.entries[i]
		}
	}
	if found == nil || found.Metadata["aup_version"] != "1.0" || found.Metadata["attestation"] == "" {
		t.Fatalf("the AUP re-confirm + attestation must be captured in the audit record: %+v", found)
	}

	// Disabling needs neither.
	if _, err := svc.SetLiveRecon(ctx, "op", "", e.ID, false, "", ""); err != nil {
		t.Errorf("disabling must not require an attestation: %v", err)
	}
}

// TestEngagementTenantIsolation covers tenant isolation: a caller scoped to tenant A
// cannot read OR mutate tenant B's engagement – every user-facing path returns ErrNotFound
// (existence is not revealed cross-tenant, so it must NOT be ErrForbidden), while a zero-tenant
// caller (single-tenant / default-tenant admin) sees any engagement. This guards against the
// dangerous false-separation mode where one read path is left unscoped.
func TestEngagementTenantIsolation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	repo := newMemRepo()
	svc := NewService(repo, fixedClock{now}, fixedIDs{}, &capAudit{})

	// Seed an engagement owned by tenant "A" directly (bypassing fixedIDs' constant ID).
	engA, err := domain.New(shared.ID("eng-A"), shared.ID("tenant-A"), "Acme", "Acme", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, engA); err != nil {
		t.Fatal(err)
	}

	// Tenant B cannot READ it – ErrNotFound, never ErrForbidden (don't reveal existence).
	if _, err := svc.Get(ctx, shared.ID("tenant-B"), engA.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant Get must be ErrNotFound, got %v", err)
	}
	// Tenant A sees its own; a zero-tenant (single-tenant / admin) caller sees any.
	if _, err := svc.Get(ctx, shared.ID("tenant-A"), engA.ID); err != nil {
		t.Errorf("same-tenant Get must succeed, got %v", err)
	}
	if _, err := svc.Get(ctx, "", engA.ID); err != nil {
		t.Errorf("zero-tenant Get must succeed, got %v", err)
	}
	// Every MUTATION is equally scoped: a wrong-tenant caller fails closed (ErrNotFound) – no
	// silent cross-tenant write. One assertion per mutation so a future unscoped load is caught.
	if _, err := svc.UpdateScope(ctx, "mallory", shared.ID("tenant-B"), engA.ID, nil, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant UpdateScope must be ErrNotFound, got %v", err)
	}
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	if _, err := svc.SetWindow(ctx, "mallory", shared.ID("tenant-B"), engA.ID, &from, &to, "UTC"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant SetWindow must be ErrNotFound, got %v", err)
	}
	if _, err := svc.SetRoE(ctx, "mallory", shared.ID("tenant-B"), engA.ID, domain.RoE{}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant SetRoE must be ErrNotFound, got %v", err)
	}
	if _, err := svc.Transition(ctx, "mallory", shared.ID("tenant-B"), engA.ID, domain.StatusActive); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant Transition must be ErrNotFound, got %v", err)
	}
	if _, err := svc.SetLiveRecon(ctx, "mallory", shared.ID("tenant-B"), engA.ID, true, "1.0", "I attest"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant SetLiveRecon must be ErrNotFound, got %v", err)
	}
}
