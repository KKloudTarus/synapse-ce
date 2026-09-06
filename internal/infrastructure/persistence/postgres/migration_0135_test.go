package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestMigration0135EngagementOffensiveRoE round-trips the offensive rules-of-engagement columns through
// the engagement repository and asserts the risk_ceiling CHECK constraint rejects an unknown class.
func TestMigration0135EngagementOffensiveRoE(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	suffix := randHex(t)
	tenant := shared.ID("t-0135-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM scope_targets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM engagements WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	repo := NewEngagementRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	eng, err := engagement.New(shared.ID("eng-0135-"+suffix), tenant, "RoE Eng", "Client", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.SetOffensiveRoE("Ops <ops@client.test>", "+1-555-0100", "high", true, now); err != nil {
		t.Fatal(err)
	}
	tctx := shared.WithTenant(ctx, tenant)
	if err := repo.Create(tctx, eng); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByIDInTenant(tctx, tenant, eng.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CustomerContact != "Ops <ops@client.test>" || got.EmergencyContact != "+1-555-0100" || got.RiskCeiling != "high" || !got.ExclusionsChecked {
		t.Fatalf("RoE did not round-trip: %+v", got)
	}
	// Update path persists a change too.
	if err := got.SetOffensiveRoE("Ops2", "+1-555-0200", "medium", true, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(tctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, _ := repo.GetByIDInTenant(tctx, tenant, eng.ID)
	if again.RiskCeiling != "medium" || again.CustomerContact != "Ops2" {
		t.Fatalf("RoE update did not persist: %+v", again)
	}

	// The CHECK constraint rejects an unknown risk class on a direct write.
	_, cerr := pool.Exec(ctx, `UPDATE engagements SET risk_ceiling='bogus' WHERE id=$1`, eng.ID.String())
	if cerr == nil || !strings.Contains(strings.ToLower(cerr.Error()), "risk_ceiling") {
		t.Fatalf("risk_ceiling CHECK did not reject an unknown class: %v", cerr)
	}
}
