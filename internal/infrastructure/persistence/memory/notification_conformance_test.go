package memory

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/notificationconformance"
)

// TestNotificationMemoryConformance runs the contract the Postgres adapters also satisfy.
func TestNotificationMemoryConformance(t *testing.T) {
	notificationconformance.Run(t, func(*testing.T) notificationconformance.Backend {
		jobs := NewJobQueue(idgen.RandomID{}, nil)
		repo := NewNotificationRepository(jobs, nil)
		outbox := NewNotificationOutbox()
		source := NewNotificationSource(repo, outbox)
		return notificationconformance.Backend{
			Repository:    repo,
			Outbox:        outbox,
			Source:        source,
			Runner:        NewTenantTransactionRunner(),
			AddTenant:     func(_ *testing.T, tenant shared.ID) { source.AddTenant(tenant) },
			AddEngagement: func(_ *testing.T, tenant, id shared.ID) { repo.AddEngagement(tenant, id) },
		}
	})
}
