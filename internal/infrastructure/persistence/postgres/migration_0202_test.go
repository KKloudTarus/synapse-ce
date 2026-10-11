package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMigration0202InboundWebhookEventDedupe(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 202, 201)
	db := isolated.db
	if err := goose.UpTo(db, ".", 202); err != nil {
		t.Fatalf("apply inbound event dedupe migration: %v", err)
	}
	requireMigrationTable(t, db, "inbound_webhook_events", true)
	requireMigrationRLS(t, db, "inbound_webhook_events")
	requireMigrationPolicies(t, db, "inbound_webhook_events", "inbound_webhook_events_tenant_all")
	requireMigrationIndexes(t, db, "inbound_webhook_events_received")
	for _, fn := range []string{
		"synapse_provision_github_inbound_webhook(text,text,text,text,integer)",
		"synapse_rotate_github_inbound_webhook(text,text,text,integer,text,timestamp with time zone)",
	} {
		var publicExecute bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM pg_proc p
			CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f',p.proowner))) acl
			WHERE p.oid=$1::regprocedure AND acl.grantee=0 AND acl.privilege_type='EXECUTE'
		)`, fn).Scan(&publicExecute); err != nil {
			t.Fatal(err)
		}
		if publicExecute {
			t.Fatalf("webhook lifecycle function %s is executable by PUBLIC", fn)
		}
	}
	if err := goose.DownTo(db, ".", 201); err != nil {
		t.Fatalf("rollback inbound event dedupe migration: %v", err)
	}
	requireMigrationTable(t, db, "inbound_webhook_events", false)
}

func TestInboundWebhookEventDedupeHostileTenant(t *testing.T) {
	fixture := newRLS817Fixture(t)
	ctx := context.Background()
	const publicA = "dedupeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const publicB = "dedupebbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const ownerA = "github-dedupe-A"
	const ownerB = "github-dedupe-B"
	t.Cleanup(func() {
		_, _ = fixture.owner.Exec(context.Background(), "DELETE FROM inbound_webhook_endpoints WHERE public_id IN ($1,$2)", publicA, publicB)
		_, _ = fixture.owner.Exec(context.Background(), "DELETE FROM integrations WHERE id IN ($1,$2)", ownerA, ownerB)
	})
	for _, row := range []struct {
		tenant shared.ID
		public, owner, endpoint string
	}{
		{rls817TenantA, publicA, ownerA, "https://github.com/tenant-a"},
		{rls817TenantB, publicB, ownerB, "https://github.com/tenant-b"},
	} {
		if _, err := fixture.owner.Exec(ctx,
			"INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'github',$1,$3,true,now(),now())",
			row.owner, row.tenant, row.endpoint); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.owner.Exec(ctx,
			"INSERT INTO inbound_webhook_endpoints(public_id,tenant_id,owner_kind,owner_id,enabled,current_version,current_sealed,rate_per_minute) VALUES($1,$2,'integration',$3,true,1,'encrypted-placeholder',10)",
			row.public, row.tenant, row.owner); err != nil {
			t.Fatal(err)
		}
	}
	store := NewInboundWebhookRepository(fixture.runtime)
	idA := ports.InboundWebhookIdentity{PublicID: publicA, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: ownerA}
	claimed, err := store.ClaimInboundWebhookEvent(ctx, idA, "github", "delivery-1", time.Now())
	if err != nil || !claimed {
		t.Fatalf("first claim=%v err=%v", claimed, err)
	}
	claimed, err = store.ClaimInboundWebhookEvent(ctx, idA, "github", "delivery-1", time.Now())
	if err != nil || claimed {
		t.Fatalf("replay claim=%v err=%v", claimed, err)
	}
	// A forged tenant/public-ID combination cannot attach an event to B.
	forged := ports.InboundWebhookIdentity{PublicID: publicB, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: ownerB}
	claimed, err = store.ClaimInboundWebhookEvent(ctx, forged, "github", "delivery-x", time.Now())
	if err == nil && claimed {
		t.Fatal("cross-tenant event claim succeeded")
	}

	// Lifecycle functions are privileged but remain tenant-bound. A tenant-A
	// session cannot provision an endpoint for tenant B even when it knows the
	// integration id and can invoke the function.
	const ownerC = "github-provision-B"
	const publicC = "provisionbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := fixture.owner.Exec(ctx,
		"INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'github',$1,$3,true,now(),now())",
		ownerC, rls817TenantB, "https://github.com/provision-b"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = fixture.owner.Exec(context.Background(), "DELETE FROM inbound_webhook_endpoints WHERE public_id=$1", publicC)
		_, _ = fixture.owner.Exec(context.Background(), "DELETE FROM integrations WHERE id=$1", ownerC)
	})
	var provisioned bool
	err = requireTenant(ctx, fixture.runtime, rls817TenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"SELECT synapse_provision_github_inbound_webhook($1,$2,$3,$4,$5)",
			rls817TenantB.String(), publicC, ownerC, "sealed-new", 60,
		).Scan(&provisioned)
	})
	if err != nil || provisioned {
		t.Fatalf("cross-tenant provision=%v err=%v", provisioned, err)
	}
	endpoint := ports.InboundWebhookEndpoint{
		PublicID: publicC, TenantID: rls817TenantB, OwnerKind: "integration", OwnerID: ownerC,
		Provider: "github", CurrentVersion: 1, CurrentSealed: "sealed-new", Enabled: true, RatePerMinute: 60,
	}
	provisioned, err = store.ProvisionInboundWebhook(ctx, endpoint)
	if err != nil || !provisioned {
		t.Fatalf("tenant-B provision=%v err=%v", provisioned, err)
	}
	rotated, err := store.RotateInboundWebhook(ctx, ports.InboundWebhookIdentity{
		PublicID: publicC, TenantID: rls817TenantB, OwnerKind: "integration", OwnerID: ownerC,
	}, 1, "sealed-next", time.Now().Add(time.Hour))
	if err != nil || !rotated {
		t.Fatalf("tenant-B rotate=%v err=%v", rotated, err)
	}
	got, found, err := store.GetInboundWebhookForOwner(ctx, rls817TenantB, "integration", ownerC)
	if err != nil || !found || got.CurrentVersion != 2 || got.CurrentSealed != "sealed-next" {
		t.Fatalf("rotated endpoint=%+v found=%v err=%v", got, found, err)
	}
}
