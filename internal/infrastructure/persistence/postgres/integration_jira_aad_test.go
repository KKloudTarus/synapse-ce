package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
)

func TestPostgresJiraCredentialAADRejectsOriginTamperingAndTenantReplay(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	dsn = isolatedIntegrationDatabase(t, ctx, dsn)
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := NewIntegrationStore(pool, cipher)
	suffix := randHex(t)
	now := time.Date(2026, time.October, 14, 0, 0, 0, 0, time.UTC)

	for _, provider := range []integration.Provider{"jira-cloud", "jira-dc"} {
		t.Run(string(provider), func(t *testing.T) {
			tenantID := shared.ID("jira-aad-" + string(provider) + "-" + suffix)
			foreignTenant := shared.ID("jira-aad-foreign-" + string(provider) + "-" + suffix)
			if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenantID.String(), foreignTenant.String()); err != nil {
				t.Fatal(err)
			}
			endpoint := "https://tenant.atlassian.net"
			changedEndpoint := "https://other.atlassian.net"
			if provider == "jira-dc" {
				endpoint = "https://jira.example.test/jira"
				changedEndpoint = "https://jira-other.example.test/jira"
			}
			item := integration.Integration{
				ID: shared.ID("jira-" + string(provider) + "-" + suffix), TenantID: tenantID, Provider: provider,
				Name: "Jira", Endpoint: endpoint, Config: []byte(`{}`), PollInterval: time.Minute,
				Enabled: true, Version: 1, ConnectionRevision: 1, CredentialRevision: 1, CreatedAt: now, UpdatedAt: now,
			}
			tenantCtx := shared.WithTenant(ctx, tenantID)
			audit := integrationMutationAudit("integration.created", item.ID, now)
			if err := store.CreateIntegration(tenantCtx, item, audit); err != nil {
				t.Fatal(err)
			}
			secret := []byte(`{"credential":"jira-fixture-secret"}`)
			if err := store.PutIntegrationCredential(tenantCtx, item.ID, "default", secret, item.Version, item.ConnectionRevision, integrationMutationAudit("integration.credential_replaced", item.ID, now)); err != nil {
				t.Fatal(err)
			}
			current, err := store.GetIntegration(tenantCtx, item.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := store.ResolveIntegrationCredential(tenantCtx, item.ID, "default", current.CredentialRevision); err != nil || string(got) != string(secret) {
				t.Fatalf("normal credential open=%q err=%v", got, err)
			}
			if _, err := store.ResolveIntegrationCredential(shared.WithTenant(ctx, foreignTenant), item.ID, "default", current.CredentialRevision); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("foreign tenant credential resolve error=%v, want not found", err)
			}

			if _, err := pool.Exec(ctx, `UPDATE integrations SET endpoint=$1 WHERE tenant_id=$2 AND id=$3`, changedEndpoint, tenantID.String(), item.ID.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ResolveIntegrationCredential(tenantCtx, item.ID, "default", current.CredentialRevision); err == nil {
				t.Fatal("endpoint-tampered credential decrypted")
			}
			if _, err := pool.Exec(ctx, `UPDATE integrations SET endpoint=$1 WHERE tenant_id=$2 AND id=$3`, endpoint, tenantID.String(), item.ID.String()); err != nil {
				t.Fatal(err)
			}
			if got, err := store.ResolveIntegrationCredential(tenantCtx, item.ID, "default", current.CredentialRevision); err != nil || string(got) != string(secret) {
				t.Fatalf("restored endpoint credential open=%q err=%v", got, err)
			}

			changed := current
			changed.Endpoint = changedEndpoint
			updated, err := store.UpdateIntegration(tenantCtx, changed, current.Version, integrationMutationAudit("integration.updated", item.ID, now))
			if err != nil {
				t.Fatal(err)
			}
			if updated.Enabled || updated.ConnectionRevision <= current.ConnectionRevision || updated.CredentialRevision <= current.CredentialRevision {
				t.Fatalf("origin update did not disable and revise: before=%+v after=%+v", current, updated)
			}
			if _, err := store.ResolveIntegrationCredential(tenantCtx, item.ID, "default", updated.CredentialRevision); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("origin update retained credential: %v", err)
			}
		})
	}
}
