package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type IntegrationStore interface {
	CreateIntegration(ctx context.Context, item integration.Integration, audit AuditEntry) error
	ListIntegrations(ctx context.Context, includeArchived bool) ([]integration.Integration, error)
	GetIntegration(ctx context.Context, id shared.ID) (integration.Integration, error)
	UpdateIntegration(ctx context.Context, item integration.Integration, expectedVersion int, audit AuditEntry) (integration.Integration, error)
	SetIntegrationEnabled(ctx context.Context, id shared.ID, enabled bool, expectedVersion int, audit AuditEntry) (integration.Integration, error)
	ArchiveIntegration(ctx context.Context, id shared.ID, expectedVersion int, audit AuditEntry) error

	PutIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string, plaintext []byte, expectedVersion, expectedConnectionRevision int, audit AuditEntry) error
	DeleteIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string, expectedVersion, expectedConnectionRevision int, audit AuditEntry) error
	ResolveIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string, expectedRevision int) ([]byte, error)
	IntegrationCredentialConfigured(ctx context.Context, integrationID shared.ID, credentialID string) (bool, error)

	CreateIntegrationBinding(ctx context.Context, binding integration.Binding, audit AuditEntry) error
	ListIntegrationBindings(ctx context.Context, integrationID shared.ID) ([]integration.Binding, error)
	DeleteIntegrationBinding(ctx context.Context, integrationID, bindingID shared.ID, audit AuditEntry) error

	StartIntegrationOperation(ctx context.Context, operation integration.Operation, jobKind string, payload []byte, audit AuditEntry) (integration.Operation, error)
	GetIntegrationOperation(ctx context.Context, id shared.ID) (integration.Operation, error)
	ListIntegrationOperations(ctx context.Context, integrationID shared.ID, limit int) ([]integration.Operation, error)
	BeginIntegrationOperation(ctx context.Context, id shared.ID, startedAt time.Time) (integration.Operation, bool, error)
	FinishIntegrationOperation(ctx context.Context, id shared.ID, state integration.OperationState, checkpoint string, counts integration.OperationCounts, errors []string, pipelines []integration.Pipeline, finishedAt time.Time) (integration.Operation, error)
	FinishIntegrationPoll(ctx context.Context, id shared.ID, state integration.OperationState, checkpoint string, counts integration.OperationCounts, errors []string, runs []integration.ExternalRun, finishedAt time.Time) (integration.Operation, error)
	CancelIntegrationOperation(ctx context.Context, id shared.ID, finishedAt time.Time, audit AuditEntry) (integration.Operation, error)
	ListDueIntegrations(ctx context.Context, now time.Time, limit int) ([]integration.Integration, error)

	ListIntegrationExternalRuns(ctx context.Context, integrationID shared.ID, limit int) ([]integration.ExternalRun, error)
}

type IntegrationAnalysisMatcher interface {
	MatchIntegrationAnalysis(ctx context.Context, projectID shared.ID, revision string) (analysisID shared.ID, state integration.CorrelationState, err error)
}

type IntegrationObserver interface {
	ObserveIntegrationOperation(provider, operation, outcome string)
}
