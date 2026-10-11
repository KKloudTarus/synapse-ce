package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Applies the real migration in a dedicated database; no mocked SQL or
// app-superuser connection is used for the HTTP-side isolation assertions.
func TestMigration0199InboundWebhookPlane(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 199, 198)
	db := isolated.db
	if err := goose.UpTo(db, ".", 199); err != nil {
		t.Fatalf("apply inbound webhook migration: %v", err)
	}
	requireMigrationTable(t, db, "inbound_webhook_endpoints", true)
	requireMigrationRLS(t, db, "inbound_webhook_endpoints")
	requireMigrationPolicies(t, db, "inbound_webhook_endpoints", "inbound_webhook_owner_all", "inbound_webhook_tenant_select")
	requireMigrationIndexes(t, db, "inbound_webhook_owner")
	var tenantPolicyCommand string
	if err := db.QueryRow(`SELECT cmd FROM pg_policies
        WHERE schemaname='public' AND tablename='inbound_webhook_endpoints'
          AND policyname='inbound_webhook_tenant_select'`).Scan(&tenantPolicyCommand); err != nil {
		t.Fatal(err)
	}
	if tenantPolicyCommand != "SELECT" {
		t.Fatalf("tenant webhook policy permits %s, want SELECT-only", tenantPolicyCommand)
	}
	var exposedCount int
	var exposedName string
	if err := db.QueryRow(`
        SELECT count(*), min(arg.name)
          FROM pg_proc p CROSS JOIN LATERAL unnest(p.proargmodes,p.proargnames) arg(mode,name)
         WHERE p.oid='synapse_lookup_inbound_webhook(text)'::regprocedure
           AND arg.mode IN ('o','b','t')
    `).Scan(&exposedCount, &exposedName); err != nil {
		t.Fatal(err)
	}
	if exposedCount != 1 || exposedName != "tenant_id" {
		t.Errorf("privileged lookup must return ONLY tenant ID; got %d outputs, first %s", exposedCount, exposedName)
	}
	for _, fn := range []string{
		"synapse_lookup_inbound_webhook(text)",
		"synapse_admit_inbound_webhook(text,text,text,text,integer,boolean)",
	} {
		var granted bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL
            aclexplode(COALESCE(p.proacl, acldefault('f',p.proowner))) acl
            WHERE p.oid=$1::regprocedure AND acl.grantee=0
              AND acl.privilege_type='EXECUTE')`, fn).Scan(&granted); err != nil {
			t.Fatal(err)
		}
		if granted {
			t.Errorf("privileged function %s is executable by PUBLIC", fn)
		}
	}
	if err := goose.DownTo(db, ".", 198); err != nil {
		t.Fatalf("rollback migration: %v", err)
	}
	requireMigrationTable(t, db, "inbound_webhook_endpoints", false)
}

func TestInboundWebhookHostilePostgresRuntimeRole(t *testing.T) {
	fixture := newRLS817Fixture(t)
	ctx := context.Background()
	const idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const idB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const ownerA = "inbound-tenant-A"
	const ownerB = "inbound-tenant-B"
	// Cleanup precedes the fixture's tenant deletion to respect the owner FK.
	t.Cleanup(func() {
		_, _ = fixture.owner.Exec(context.Background(),
			"DELETE FROM inbound_webhook_endpoints WHERE public_id IN ($1,$2)", idA, idB)
		_, _ = fixture.owner.Exec(context.Background(),
			"DELETE FROM integrations WHERE id IN ($1,$2)", ownerA, ownerB)
	})
	for _, row := range []struct {
		tenant    shared.ID
		id, owner string
	}{
		{rls817TenantA, idA, ownerA}, {rls817TenantB, idB, ownerB},
	} {
		_, err := fixture.owner.Exec(ctx,
			"INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'jenkins',$1,$3,true,now(),now())",
			row.owner, row.tenant, "https://hooks.example.invalid/"+row.owner)
		if err != nil {
			t.Fatalf("seed owned integration: %v", err)
		}
		_, err = fixture.owner.Exec(ctx,
			"INSERT INTO inbound_webhook_endpoints(public_id,tenant_id,owner_kind,owner_id,enabled,current_version,current_sealed,rate_per_minute) VALUES($1,$2,'integration',$3,true,1,'encrypted-placeholder',1)",
			row.id, row.tenant, row.owner)
		if err != nil {
			t.Fatalf("seed global endpoint: %v", err)
		}
	}
	// The production-equivalent runtime role gets only the two SECURITY
	// DEFINER functions, never a direct cross-tenant query or mutation.
	var count int
	if err := fixture.runtime.QueryRow(ctx, "SELECT count(*) FROM inbound_webhook_endpoints").Scan(&count); err != nil || count != 0 {
		t.Fatalf("unscoped runtime lookup exposed %d endpoints or failed: %v", count, err)
	}
	if _, err := fixture.runtime.Exec(ctx,
		"UPDATE inbound_webhook_endpoints SET enabled=false WHERE public_id=$1", idA); err == nil {
		t.Fatal("runtime role retained direct webhook-registry mutation privilege")
	}
	store := NewInboundWebhookRepository(fixture.runtime)
	a, found, err := store.LookupInboundWebhook(ctx, idA)
	if err != nil || !found || a.TenantID != rls817TenantA || !a.Enabled {
		t.Fatalf("tenant-A lookup invalid: found=%v tenant=%s enabled=%v err=%v", found, a.TenantID, a.Enabled, err)
	}
	b, found, err := store.LookupInboundWebhook(ctx, idB)
	if err != nil || !found || b.TenantID != rls817TenantB || !b.Enabled {
		t.Fatalf("tenant-B lookup invalid: found=%v tenant=%s enabled=%v err=%v", found, b.TenantID, b.Enabled, err)
	}
	_, found, err = store.LookupInboundWebhook(ctx, "ccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil || found {
		t.Fatalf("nonexistent endpoint leaked: found=%v err=%v", found, err)
	}

	// An identity forged using A's tenant and B's public ID must NOT consume
	// B's quota or access B's integration under A's RLS context.
	attempted := ports.InboundWebhookIdentity{
		PublicID: idB, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: ownerB,
	}
	decision, err := store.AdmitInboundWebhook(ctx, attempted, 1, false)
	if err != nil || decision != -1 {
		t.Fatalf("cross-tenant admission=%d err=%v", decision, err)
	}
	// The SECURITY DEFINER function itself must bind its tenant argument to
	// app.current_tenant. This remains true even when migrations/tests created
	// the function under a role that would otherwise bypass FORCE RLS.
	err = requireTenant(ctx, fixture.runtime, rls817TenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"SELECT synapse_admit_inbound_webhook($1,$2,$3,$4,$5,$6)",
			idB, rls817TenantB.String(), "integration", ownerB, 1, false,
		).Scan(&decision)
	})
	if err != nil || decision != -1 {
		t.Fatalf("direct cross-tenant privileged admission=%d err=%v", decision, err)
	}
	valid := ports.InboundWebhookIdentity{
		PublicID: idB, TenantID: rls817TenantB, OwnerKind: "integration", OwnerID: ownerB,
	}
	decision, err = store.AdmitInboundWebhook(ctx, valid, 1, false)
	if err != nil || decision != 1 {
		t.Fatalf("valid admission=%d err=%v", decision, err)
	}
	decision, err = store.AdmitInboundWebhook(ctx, valid, 1, false)
	if err != nil || decision != 0 {
		t.Fatalf("shared endpoint rate limit=%d err=%v", decision, err)
	}
	// Eight independent repository instances contend on one endpoint through
	// real pgx connections; only one may consume the first minute's quota.
	if _, err := fixture.owner.Exec(ctx,
		"UPDATE inbound_webhook_endpoints SET window_started_at='-infinity'::timestamptz, window_count=0 WHERE public_id=$1", idB); err != nil {
		t.Fatal(err)
	}
	type admission struct {
		decision int
		err      error
	}
	results := make(chan admission, 8)
	var concurrentCalls sync.WaitGroup
	for i := 0; i < 8; i++ {
		concurrentCalls.Add(1)
		go func() {
			defer concurrentCalls.Done()
			n, err := NewInboundWebhookRepository(fixture.runtime).AdmitInboundWebhook(ctx, valid, 1, false)
			results <- admission{decision: n, err: err}
		}()
	}
	concurrentCalls.Wait()
	close(results)
	accepted, limited := 0, 0
	for item := range results {
		if item.err != nil {
			t.Fatalf("concurrent SQL admission failed: %v", item.err)
		}
		switch item.decision {
		case 1:
			accepted++
		case 0:
			limited++
		default:
			t.Fatalf("concurrent admission returned %d", item.decision)
		}
	}
	if accepted != 1 || limited != 7 {
		t.Fatalf("shared quota oversubscribed: accepted=%d limited=%d", accepted, limited)
	}
	// A tenant/secret remap without versioning is rejected by the actual
	// PostgreSQL guard even if a privileged migrator attempts it.
	if _, err := fixture.owner.Exec(ctx,
		"UPDATE inbound_webhook_endpoints SET current_sealed='replacement' WHERE public_id=$1", idA); err == nil {
		t.Fatal("same-version secret substitution was accepted")
	}
	if _, err := fixture.owner.Exec(ctx,
		"UPDATE inbound_webhook_endpoints SET tenant_id=$1 WHERE public_id=$2", rls817TenantB, idA); err == nil {
		t.Fatal("cross-tenant endpoint retargeting was accepted")
	}
	if _, err := fixture.owner.Exec(ctx, `
        UPDATE inbound_webhook_endpoints
           SET current_version=2,
               previous_sealed=current_sealed,
               previous_expires_at=now()+interval '1 hour'
         WHERE public_id=$1`, idA); err == nil {
		t.Fatal("key version advanced without a new active secret")
	}
	// The record size is independently bounded; a valid version bump cannot
	// smuggle an oversized sealed key into the privileged authentication path.
	if _, err := fixture.owner.Exec(ctx, `
        UPDATE inbound_webhook_endpoints
           SET current_version=2, current_sealed=repeat('x',8193),
               previous_sealed=current_sealed, previous_expires_at=now()+interval '1 hour'
         WHERE public_id=$1`, idA); err == nil {
		t.Fatal("oversized credential passed the migration's size constraint")
	}
	// The previous-key signature cannot be admitted if no overlap exists.
	decision, err = store.AdmitInboundWebhook(ctx, valid, 1, true)
	if err != nil || decision != -1 {
		t.Fatalf("absent previous key admitted=%d err=%v", decision, err)
	}
	if _, err := fixture.owner.Exec(ctx, `
        UPDATE inbound_webhook_endpoints
           SET current_version=2, current_sealed='next-sealed',
               previous_sealed=current_sealed, previous_expires_at=now()+interval '25 hours'
         WHERE public_id=$1`, idB); err == nil {
		t.Fatal("rotation overlap longer than 24 hours was accepted")
	}
	_, err = fixture.owner.Exec(ctx, `
        UPDATE inbound_webhook_endpoints
           SET current_version=2, current_sealed='next-sealed',
               previous_sealed=current_sealed, previous_expires_at=now()+interval '1 minute',
               window_count=0
         WHERE public_id=$1`, idB)
	if err != nil {
		t.Fatalf("valid 24-hour overlap rotation rejected: %v", err)
	}
	decision, err = store.AdmitInboundWebhook(ctx, valid, 2, true)
	if err != nil || decision != 1 {
		t.Fatalf("valid overlapping key admission=%d err=%v", decision, err)
	}
	_, err = fixture.owner.Exec(ctx,
		"UPDATE inbound_webhook_endpoints SET previous_expires_at=now()-interval '1 minute' WHERE public_id=$1", idB)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = store.AdmitInboundWebhook(ctx, valid, 2, true)
	if err != nil || decision != -1 {
		t.Fatalf("expired previous key admitted=%d err=%v", decision, err)
	}
	if _, err := fixture.owner.Exec(ctx,
		"UPDATE inbound_webhook_endpoints SET previous_expires_at=now()+interval '1 hour' WHERE public_id=$1", idB); err == nil {
		t.Fatal("expired previous-key overlap could be revived without rotation")
	}

	// Scoped SELECT may read only the tenant's own endpoint despite having
	// the table-level SELECT grant needed for sealed key verification.
	err = requireTenant(ctx, fixture.runtime, rls817TenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM inbound_webhook_endpoints").Scan(&count)
	})
	if err != nil || count != 1 {
		t.Fatalf("tenant A saw %d endpoint rows, err=%v", count, err)
	}
	// Rotation/version drift and disabled integration fail closed even with an
	// otherwise correct endpoint record and tenant-scoped RLS session.
	decision, err = store.AdmitInboundWebhook(ctx, valid, 1, false)
	if err != nil || decision != -1 {
		t.Fatalf("stale version admitted=%d err=%v", decision, err)
	}
	_, err = fixture.owner.Exec(ctx, "UPDATE integrations SET enabled=false WHERE id=$1", ownerB)
	if err != nil {
		t.Fatal(err)
	}
	// The SECURITY DEFINER admission function must independently enforce owner
	// state even if a future caller bypasses the repository's pre-lock/check.
	err = requireTenant(ctx, fixture.runtime, rls817TenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"SELECT synapse_admit_inbound_webhook($1,$2,$3,$4,$5,$6)",
			idB, rls817TenantB.String(), "integration", ownerB, 2, false,
		).Scan(&decision)
	})
	if err != nil || decision != -1 {
		t.Fatalf("direct privileged admission ignored disabled owner: decision=%d err=%v", decision, err)
	}
	_, found, err = store.LookupInboundWebhook(ctx, idB)
	if err != nil || !found {
		t.Fatalf("disabled integration lookup err=%v found=%v", err, found)
	}
	decision, err = store.AdmitInboundWebhook(ctx, valid, 2, false)
	if err != nil || decision != -1 {
		t.Fatalf("disabled integration admitted=%d err=%v", decision, err)
	}
	_, err = fixture.owner.Exec(ctx, "UPDATE integrations SET enabled=true, archived=true WHERE id=$1", ownerB)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = store.AdmitInboundWebhook(ctx, valid, 2, false)
	if err != nil || decision != -1 {
		t.Fatalf("archived integration admitted=%d err=%v", decision, err)
	}
	_, err = fixture.owner.Exec(ctx, "UPDATE integrations SET archived=false WHERE id=$1", ownerB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.owner.Exec(ctx, "UPDATE inbound_webhook_endpoints SET revoked_at=now() WHERE public_id=$1", idB)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = store.AdmitInboundWebhook(ctx, valid, 2, false)
	if err != nil || decision != -1 {
		t.Fatalf("revoked endpoint admitted=%d err=%v", decision, err)
	}
	if _, err := fixture.owner.Exec(ctx,
		"UPDATE inbound_webhook_endpoints SET revoked_at=NULL WHERE public_id=$1", idB); err == nil {
		t.Fatal("revoked endpoint could be resurrected")
	}
	// A runtime transaction scoped to A cannot read a B integration directly.
	err = requireTenant(ctx, fixture.runtime, rls817TenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT id FROM integrations WHERE id=$1", ownerB).Scan(new(string))
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant-A RLS read of tenant-B integration returned %v", err)
	}
}
