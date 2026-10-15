package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestJiraCredentialsRejectRelocatedCiphertextAndInvalidateOrigin(t *testing.T) {
	for _, provider := range []integration.Provider{"jira-cloud", "jira-dc"} {
		t.Run(string(provider), func(t *testing.T) {
			clock, ids := idgen.SystemClock{}, idgen.RandomID{}
			cipher, err := vault.NewCipher(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			store := NewIntegrationStore(NewJobQueue(ids, clock.Now), cipher, clock, &integrationFailingAudit{})
			tenant := shared.ID("jira-tenant")
			ctx := shared.WithTenant(context.Background(), tenant)
			now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
			item := integration.Integration{ID: "jira", TenantID: tenant, Provider: provider, Name: "Jira", Endpoint: "https://test.atlassian.net", Config: []byte(`{}`), PollInterval: time.Minute, Version: 1, ConnectionRevision: 1, CreatedAt: now, UpdatedAt: now}
			audit := ports.AuditEntry{Actor: "admin", Action: "integration.created", Target: item.ID.String(), At: now}
			if err := store.CreateIntegration(ctx, item, audit); err != nil {
				t.Fatal(err)
			}
			if err := store.PutIntegrationCredential(ctx, item.ID, "default", []byte(`{"test":"fixture"}`), 1, 1, audit); err != nil {
				t.Fatal(err)
			}
			item, err = store.GetIntegration(ctx, item.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.ResolveIntegrationCredential(ctx, item.ID, "default", item.CredentialRevision); err != nil {
				t.Fatal(err)
			}
			store.mu.Lock()
			moved := item
			moved.Endpoint = "https://other.atlassian.net"
			store.integrations[tenantKey(tenant, item.ID)] = moved
			store.mu.Unlock()
			if _, err = store.ResolveIntegrationCredential(ctx, item.ID, "default", item.CredentialRevision); err == nil {
				t.Fatal("relocated ciphertext decrypted")
			}
			store.mu.Lock()
			store.integrations[tenantKey(tenant, item.ID)] = item
			store.mu.Unlock()
			updated, err := store.UpdateIntegration(ctx, moved, item.Version, audit)
			if err != nil {
				t.Fatal(err)
			}
			if updated.Enabled || updated.ConnectionRevision <= item.ConnectionRevision {
				t.Fatal("origin did not disable and revise connection")
			}
			if _, err = store.ResolveIntegrationCredential(ctx, item.ID, "default", updated.CredentialRevision); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("credential remained after origin change: %v", err)
			}
			if _, err = store.ResolveIntegrationCredential(shared.WithTenant(ctx, "foreign"), item.ID, "default", updated.CredentialRevision); !errors.Is(err, shared.ErrNotFound) {
				t.Fatal("foreign tenant could resolve")
			}
		})
	}
}
