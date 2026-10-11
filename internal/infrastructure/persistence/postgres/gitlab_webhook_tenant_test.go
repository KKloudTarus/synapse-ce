package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"testing"
)

func TestInboundWebhookEventDedupeTenantIsolation(t *testing.T) {
	fixture := newRLS817Fixture(t)
	ctx := context.Background()
	const publicA = "dedupeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const publicB = "dedupebbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const ownerA = "dedupe-owner-A"
	const ownerB = "dedupe-owner-B"

	t.Cleanup(func() {
		_, _ = fixture.owner.Exec(context.Background(),
			"DELETE FROM inbound_webhook_endpoints WHERE public_id IN ($1,$2)", publicA, publicB)
		_, _ = fixture.owner.Exec(context.Background(),
			"DELETE FROM integrations WHERE id IN ($1,$2)", ownerA, ownerB)
	})
	for _, row := range []struct {
		tenant   shared.ID
		publicID string
		ownerID  string
	}{
		{rls817TenantA, publicA, ownerA},
		{rls817TenantB, publicB, ownerB},
	} {
		if _, err := fixture.owner.Exec(ctx,
			"INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'gitlab',$1,$3,true,now(),now())",
			row.ownerID, row.tenant, "https://gitlab.example.invalid/"+row.ownerID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.owner.Exec(ctx,
			"INSERT INTO inbound_webhook_endpoints(public_id,tenant_id,owner_kind,owner_id,enabled,current_version,current_sealed) VALUES($1,$2,'integration',$3,true,1,'sealed')",
			row.publicID, row.tenant, row.ownerID); err != nil {
			t.Fatal(err)
		}
	}

	store := NewInboundWebhookRepository(fixture.runtime)
	idA := ports.InboundWebhookIdentity{PublicID: publicA, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: ownerA}
	digest := sha256.Sum256([]byte("signed-body"))
	event := ports.InboundWebhookEvent{Provider: "gitlab", EventID: "13792a34-cac6-4fda-95a8-c58e00a3954e", PayloadSHA256: hex.EncodeToString(digest[:])}
	receive := func(context.Context) error { return nil }
	claimed, err := store.ProcessInboundWebhookEvent(ctx, idA, event, receive)
	if err != nil || !claimed {
		t.Fatalf("first claim = %v, %v; want true,nil", claimed, err)
	}
	claimed, err = store.ProcessInboundWebhookEvent(ctx, idA, event, receive)
	if err != nil || claimed {
		t.Fatalf("replay claim = %v, %v; want false,nil", claimed, err)
	}

	// A forged identity cannot create a claim on B's endpoint while scoped to A:
	// the composite foreign key is present, and RLS hides B from the tenant-A write.
	forged := ports.InboundWebhookIdentity{PublicID: publicB, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: ownerB}
	claimed, err = store.ProcessInboundWebhookEvent(ctx, forged, event, receive)
	if err == nil && claimed {
		t.Fatal("cross-tenant event claim succeeded")
	}

}
