package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The whole point of the outbox is that state and its audit obligation share one
// fate. If the intention cannot be committed, the mutation it belongs to must not
// survive either — otherwise privacy governance state would exist with no durable
// record that it still owes an audit entry.
func TestActivatePrivacyPolicyWithAuditRollsBackOnRejectedIntention(t *testing.T) {
	fixture := newPrivacyPolicyPostgresFixture(t)
	ctx := shared.WithTenant(context.Background(), fixture.tenant)
	repo, err := NewPrivacyPolicyRepository(fixture.pool)
	if err != nil {
		t.Fatalf("new privacy policy repository: %v", err)
	}
	// This test deliberately leaves an undelivered obligation behind, and the privacy
	// fixture does not know about the outbox. Clean it up here: an orphan intention row
	// would make 0125's rollback guard refuse every later `goose down` in this package.
	t.Cleanup(func() { cleanupFleetAuditIntents(t, fixture.pool, fixture.tenant) })
	assignment := fixture.assignment(t, "tenant:v1", fixture.at)
	if _, err := repo.PutPrivacyPolicy(ctx, assignment); err != nil {
		t.Fatalf("put privacy policy: %v", err)
	}
	activation := privacy.Activation{
		TenantID: fixture.tenant, OperationID: shared.ID("atomic-activate"),
		PolicyDigest: assignment.Digest, PolicyVersion: assignment.Policy.Version,
		ActivatedBy: "integration-admin", ActivatedAt: fixture.at.Add(time.Hour),
	}
	// An intention whose id disagrees with its idempotency key is rejected inside the
	// same transaction as the activation insert.
	broken := ports.FleetAuditIntent{
		ID: "fleet.privacy_policy.activate:atomic",
		Entry: ports.AuditEntry{
			Actor: "integration-admin", Action: "fleet.privacy_policy.activate",
			Target: assignment.Policy.Version, At: fixture.at.Add(time.Hour),
			Metadata: map[string]string{"idempotency_key": "a-different-key"},
		},
	}
	if _, _, err := repo.ActivatePrivacyPolicyWithAudit(ctx, activation, broken); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error for a malformed intention, got %v", err)
	}
	history, err := repo.PrivacyPolicyActivationHistory(ctx, fixture.tenant)
	if err != nil {
		t.Fatalf("activation history: %v", err)
	}
	if len(history) != 0 {
		t.Fatalf("activation survived a rejected audit intention: %#v", history)
	}
	if _, err := repo.ActivePrivacyPolicy(ctx, fixture.tenant); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("active pointer advanced without a durable audit obligation: %v", err)
	}
	var pendingRows int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM fleet_audit_intents
		WHERE tenant_id=$1`, fixture.tenant.String()).Scan(&pendingRows); err != nil {
		t.Fatalf("count intentions: %v", err)
	}
	if pendingRows != 0 {
		t.Fatalf("rejected intention rows=%d, want 0", pendingRows)
	}

	// The same activation succeeds once its intention is well formed, and the audit
	// obligation is durable and pending before anyone acknowledges it.
	good := broken
	good.Entry.Metadata = map[string]string{"idempotency_key": good.ID}
	admitted, committedIntent, err := repo.ActivatePrivacyPolicyWithAudit(ctx, activation, good)
	if err != nil {
		t.Fatalf("activate with a valid intention: %v", err)
	}
	if admitted.Revision != 1 {
		t.Fatalf("admitted revision=%d, want 1", admitted.Revision)
	}
	pending, err := repo.ListPendingFleetAudits(ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != good.ID {
		t.Fatalf("pending intentions=%#v, want exactly %s", pending, good.ID)
	}
	// The audit payload must name the revision that actually became durable, so a
	// restart-time delivery describes the same transition the caller admitted.
	if pending[0].Entry.Metadata["revision"] != "1" {
		t.Fatalf("pending audit revision=%q, want 1", pending[0].Entry.Metadata["revision"])
	}
	if !pending[0].Entry.At.Equal(admitted.ActivatedAt) {
		t.Fatalf("pending audit at=%v, want the admitted activation instant %v", pending[0].Entry.At, admitted.ActivatedAt)
	}
	// The returned intention is what the caller must audit, so it has to be exactly what
	// a restart-time reconciler would read back. If these could differ, one obligation
	// would produce two different hash-chain entries.
	if !ports.SameFleetAuditIntent(committedIntent, pending[0]) {
		t.Fatalf("returned intention=%#v, want the durable %#v", committedIntent.Entry, pending[0].Entry)
	}
}
