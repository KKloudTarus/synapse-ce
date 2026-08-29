package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPrivacyPolicyStoreImmutableHistoryAndRevisionedActivation(t *testing.T) {
	store := NewPrivacyPolicyStore()
	tenant := shared.ID("privacy-tenant-1")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Unix(1_750_000_000, 0).UTC()

	v1, err := privacy.NewAssignment(tenant, privacy.DefaultPolicy(), "operator", at)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.PutPrivacyPolicy(ctx, v1)
	if err != nil || !created {
		t.Fatalf("PutPrivacyPolicy(v1) = %v/%v, want created", created, err)
	}
	if _, err := store.ActivePrivacyPolicy(ctx, tenant); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("admission changed active pointer: %v", err)
	}

	retry := v1
	retry.CreatedAt = retry.CreatedAt.Add(time.Minute)
	created, err = store.PutPrivacyPolicy(ctx, retry)
	if err != nil || created {
		t.Fatalf("retry PutPrivacyPolicy(v1) = %v/%v, want idempotent", created, err)
	}
	storedV1, err := store.PrivacyPolicyByDigest(ctx, tenant, v1.Digest)
	if err != nil || !storedV1.CreatedAt.Equal(v1.CreatedAt) {
		t.Fatalf("retry replaced first admission metadata: %#v/%v", storedV1, err)
	}

	policyV2 := privacy.DefaultPolicy()
	policyV2.Version = "tenant:v2"
	policyV2.MaxArgLen = 1024
	v2, err := privacy.NewAssignment(tenant, policyV2, "operator", at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if created, err = store.PutPrivacyPolicy(ctx, v2); err != nil || !created {
		t.Fatalf("PutPrivacyPolicy(v2) = %v/%v, want created", created, err)
	}

	first, err := store.ActivatePrivacyPolicy(ctx, privacy.Activation{
		TenantID: tenant, OperationID: "activate-v1", PolicyDigest: v1.Digest,
		PolicyVersion: v1.Policy.Version, ActivatedBy: "operator", ActivatedAt: at.Add(2 * time.Minute),
	})
	if err != nil || first.Revision != 1 {
		t.Fatalf("activate v1 = %#v/%v, want revision 1", first, err)
	}
	exactRetry, err := store.ActivatePrivacyPolicy(ctx, privacy.Activation{
		TenantID: tenant, OperationID: "activate-v1", PolicyDigest: v1.Digest,
		PolicyVersion: v1.Policy.Version, ActivatedBy: "operator", ActivatedAt: at.Add(24 * time.Hour),
	})
	if err != nil || exactRetry != first {
		t.Fatalf("activation retry = %#v/%v, want original %#v", exactRetry, err, first)
	}
	second, err := store.ActivatePrivacyPolicy(ctx, privacy.Activation{
		TenantID: tenant, OperationID: "activate-v2", PolicyDigest: v2.Digest,
		PolicyVersion: v2.Policy.Version, ActivatedBy: "operator", ActivatedAt: at.Add(3 * time.Minute),
	})
	if err != nil || second.Revision != 2 {
		t.Fatalf("activate v2 = %#v/%v, want revision 2", second, err)
	}
	third, err := store.ActivatePrivacyPolicy(ctx, privacy.Activation{
		TenantID: tenant, OperationID: "reactivate-v1", PolicyDigest: v1.Digest,
		PolicyVersion: v1.Policy.Version, ActivatedBy: "operator", ActivatedAt: at.Add(4 * time.Minute),
	})
	if err != nil || third.Revision != 3 {
		t.Fatalf("reactivate v1 = %#v/%v, want revision 3", third, err)
	}

	active, err := store.ActivePrivacyPolicy(ctx, tenant)
	if err != nil || active.Digest != v1.Digest {
		t.Fatalf("ActivePrivacyPolicy() = %#v/%v, want v1", active, err)
	}
	history, err := store.PrivacyPolicyHistory(ctx, tenant)
	if err != nil || len(history) != 2 || history[0].Policy.Version != v2.Policy.Version {
		t.Fatalf("PrivacyPolicyHistory() = %#v/%v", history, err)
	}
	activations, err := store.PrivacyPolicyActivationHistory(ctx, tenant)
	if err != nil || len(activations) != 3 || activations[0] != first || activations[1] != second || activations[2] != third {
		t.Fatalf("PrivacyPolicyActivationHistory() = %#v/%v", activations, err)
	}

	active.Policy.Dispositions[privacy.CategoryProcessEnv] = privacy.DispositionAllow
	again, err := store.ActivePrivacyPolicy(ctx, tenant)
	if err != nil || again.Policy.Dispositions[privacy.CategoryProcessEnv] != privacy.DispositionDrop {
		t.Fatalf("stored active policy was mutated: %#v/%v", again, err)
	}
}

func TestPrivacyPolicyStoreRejectsContradictoryVersionOperationAndTenantAccess(t *testing.T) {
	store := NewPrivacyPolicyStore()
	tenant := shared.ID("privacy-tenant-1")
	other := shared.ID("privacy-tenant-2")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Unix(1_750_000_000, 0).UTC()
	assignment, err := privacy.NewAssignment(tenant, privacy.DefaultPolicy(), "operator", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutPrivacyPolicy(ctx, assignment); err != nil {
		t.Fatal(err)
	}

	changedPolicy := privacy.DefaultPolicy()
	changedPolicy.MaxArgLen = 1024
	contradictory, err := privacy.NewAssignment(tenant, changedPolicy, "operator", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutPrivacyPolicy(ctx, contradictory); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("contradictory PutPrivacyPolicy() error = %v, want conflict", err)
	}
	aliased := assignment
	aliased.Policy.Version = "tenant:v2"
	if _, err := store.PutPrivacyPolicy(ctx, aliased); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same digest under another version error = %v, want conflict", err)
	}

	activation := privacy.Activation{
		TenantID: tenant, OperationID: "activate-1", PolicyDigest: assignment.Digest,
		PolicyVersion: assignment.Policy.Version, ActivatedBy: "operator", ActivatedAt: at.Add(time.Minute),
	}
	if _, err := store.ActivatePrivacyPolicy(ctx, activation); err != nil {
		t.Fatal(err)
	}
	activation.ActivatedBy = "other-operator"
	if _, err := store.ActivatePrivacyPolicy(ctx, activation); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("contradictory activation operation error = %v, want conflict", err)
	}
	if _, err := store.ActivePrivacyPolicy(shared.WithTenant(context.Background(), other), tenant); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant ActivePrivacyPolicy() error = %v, want forbidden", err)
	}
	if _, err := store.PrivacyPolicyByDigest(shared.WithTenant(context.Background(), other), other, assignment.Digest); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant digest lookup error = %v, want not found", err)
	}
	if _, err := store.PrivacyPolicyActivationHistory(shared.WithTenant(context.Background(), other), tenant); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant activation history error = %v, want forbidden", err)
	}
}
