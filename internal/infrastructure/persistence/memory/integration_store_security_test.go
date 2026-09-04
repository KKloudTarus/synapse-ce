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

type integrationFailingAudit struct {
	err     error
	entries []ports.AuditEntry
}

func (audit *integrationFailingAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	if audit.err != nil {
		return audit.err
	}
	audit.entries = append(audit.entries, entry)
	return nil
}

func TestIntegrationMutationsRejectAuditFailureAndArchivedCredentialWrites(t *testing.T) {
	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}
	queue := NewJobQueue(ids, clock.Now)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	auditFailure := errors.New("audit unavailable")
	audit := &integrationFailingAudit{err: auditFailure}
	store := NewIntegrationStore(queue, cipher, clock, audit)
	tenantID := shared.ID("tenant-1")
	ctx := shared.WithTenant(context.Background(), tenantID)
	now := time.Now().UTC()
	item := integration.Integration{
		ID: "integration-1", TenantID: tenantID, Provider: "jenkins", Name: "Jenkins", Endpoint: "https://jenkins.example.com",
		Config: []byte(`{}`), PollInterval: time.Minute, Version: 1, ConnectionRevision: 1, CreatedAt: now, UpdatedAt: now,
	}
	entry := ports.AuditEntry{Actor: "admin", Action: "integration.created", Target: item.ID.String(), At: now}
	if err := store.CreateIntegration(ctx, item, entry); !errors.Is(err, auditFailure) {
		t.Fatalf("create audit failure=%v", err)
	}
	if _, err := store.GetIntegration(ctx, item.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("create committed without audit: %v", err)
	}

	audit.err = nil
	if err := store.CreateIntegration(ctx, item, entry); err != nil {
		t.Fatal(err)
	}
	audit.err = auditFailure
	credentialAudit := ports.AuditEntry{Actor: "admin", Action: "integration.credential_replaced", Target: item.ID.String(), At: now}
	if err := store.PutIntegrationCredential(ctx, item.ID, "default", []byte(`{"api_token":"secret"}`), item.Version, item.ConnectionRevision, credentialAudit); !errors.Is(err, auditFailure) {
		t.Fatalf("credential audit failure=%v", err)
	}
	if configured, err := store.IntegrationCredentialConfigured(ctx, item.ID, "default"); err != nil || configured {
		t.Fatalf("credential committed without audit: configured=%v err=%v", configured, err)
	}

	audit.err = nil
	if err := store.PutIntegrationCredential(ctx, item.ID, "default", []byte(`{"api_token":"secret"}`), item.Version, item.ConnectionRevision, credentialAudit); err != nil {
		t.Fatal(err)
	}
	current, err := store.GetIntegration(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	audit.err = auditFailure
	archiveAudit := ports.AuditEntry{Actor: "admin", Action: "integration.archived", Target: item.ID.String(), At: now}
	if err := store.ArchiveIntegration(ctx, item.ID, current.Version, archiveAudit); !errors.Is(err, auditFailure) {
		t.Fatalf("archive audit failure=%v", err)
	}
	current, err = store.GetIntegration(ctx, item.ID)
	if err != nil || current.Archived {
		t.Fatalf("archive committed without audit: item=%+v err=%v", current, err)
	}

	audit.err = nil
	if err := store.ArchiveIntegration(ctx, item.ID, current.Version, archiveAudit); err != nil {
		t.Fatal(err)
	}
	archived, err := store.GetIntegration(ctx, item.ID)
	if err != nil || !archived.Archived {
		t.Fatalf("archive state=%+v err=%v", archived, err)
	}
	if configured, err := store.IntegrationCredentialConfigured(ctx, item.ID, "default"); err != nil || configured {
		t.Fatalf("archived credential retained: configured=%v err=%v", configured, err)
	}
	if err := store.PutIntegrationCredential(ctx, item.ID, "default", []byte(`{"api_token":"replacement"}`), archived.Version, archived.ConnectionRevision, credentialAudit); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("archived credential write error=%v, want conflict", err)
	}
}

func TestStartIntegrationOperationRejectsStalePollAdmission(t *testing.T) {
	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}
	queue := NewJobQueue(ids, clock.Now)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	audit := &integrationFailingAudit{}
	store := NewIntegrationStore(queue, cipher, clock, audit)
	tenantID := shared.ID("tenant-1")
	ctx := shared.WithTenant(context.Background(), tenantID)
	now := time.Now().UTC()
	item := integration.Integration{
		ID: "integration-1", TenantID: tenantID, Provider: "jenkins", Name: "Jenkins", Endpoint: "https://jenkins.example.com",
		Config: []byte(`{}`), PollInterval: time.Minute, Enabled: true, Version: 1, ConnectionRevision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateIntegration(ctx, item, ports.AuditEntry{Actor: "admin", Action: "integration.created", Target: item.ID.String(), At: now}); err != nil {
		t.Fatal(err)
	}
	updatedInput := item
	updatedInput.Config = []byte(`{"scope":"changed"}`)
	if _, err := store.UpdateIntegration(ctx, updatedInput, item.Version, ports.AuditEntry{Actor: "admin", Action: "integration.updated", Target: item.ID.String(), At: now}); err != nil {
		t.Fatal(err)
	}
	operation := integration.Operation{
		ID: "operation-1", TenantID: tenantID, IntegrationID: item.ID, Type: integration.OperationPoll, State: integration.OperationQueued,
		JobID: "job-1", Actor: "admin", ConnectionRevision: item.ConnectionRevision, CredentialRevision: item.CredentialRevision, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := store.StartIntegrationOperation(ctx, operation, "integration.operation", []byte(`{}`), ports.AuditEntry{Actor: "admin", Action: "integration.operation_started", Target: operation.ID.String(), At: now}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale poll admission error=%v, want conflict", err)
	}
	if _, err := store.GetIntegrationOperation(ctx, operation.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("stale poll operation persisted: %v", err)
	}
	if job, err := queue.Claim(ctx, time.Minute, "integration.operation"); err != nil || job != nil {
		t.Fatalf("stale poll job queued: job=%+v err=%v", job, err)
	}
}
