package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/notificationconformance"
)

// TestNotificationPostgresConformance runs the contract the memory adapters also satisfy, as the
// application role, so row level security applies. Every case works in tenants of its own, so the
// cases share one migrated database.
func TestNotificationPostgresConformance(t *testing.T) {
	pool := notificationTestPool(t)
	repo := NewNotificationRepository(pool)
	source := NewNotificationSource(pool, repo, time.Minute)
	notificationconformance.Run(t, func(*testing.T) notificationconformance.Backend {
		return notificationconformance.Backend{
			Repository: repo,
			Outbox:     NewNotificationOutbox(pool),
			Source:     source,
			Runner:     NewTenantTransactionRunner(pool),
			AddTenant: func(t *testing.T, tenant shared.ID) {
				if _, err := pool.Exec(context.Background(), `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
					t.Fatalf("add tenant %s: %v", tenant, err)
				}
			},
			AddEngagement: func(t *testing.T, tenant, id shared.ID) {
				ctx := context.Background()
				if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'engagement')`, id, tenant)
					return err
				}); err != nil {
					t.Fatalf("add engagement %s: %v", id, err)
				}
			},
		}
	})
}
