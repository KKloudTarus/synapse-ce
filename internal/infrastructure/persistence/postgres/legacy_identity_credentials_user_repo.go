package postgres

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// UserRepository also exposes the D5 projection capability so the existing composition root can
// discover it after attaching TenantTransactionRunner. The implementation remains in the dedicated
// LegacyCredentialRepository; both adapters share the same pool and therefore the same bound pgx
// transaction carried in context.
var _ ports.LegacyCredentialProjectionStore = (*UserRepository)(nil)

func (r *UserRepository) legacyCredentialRepository() *LegacyCredentialRepository {
	return &LegacyCredentialRepository{pool: r.pool}
}

func (r *UserRepository) ClassifyAndProjectLegacyCredential(ctx context.Context, tenantID, userID shared.ID, at time.Time) (ports.LegacyCredentialProjection, error) {
	return r.legacyCredentialRepository().ClassifyAndProjectLegacyCredential(ctx, tenantID, userID, at)
}

func (r *UserRepository) SyncIssuedLegacyCredential(ctx context.Context, request ports.LegacyCredentialSyncRequest) (ports.LegacyCredentialProjection, bool, error) {
	return r.legacyCredentialRepository().SyncIssuedLegacyCredential(ctx, request)
}

func (r *UserRepository) SyncLegacyCredentialDisabled(ctx context.Context, request ports.LegacyCredentialSyncRequest) (ports.LegacyCredentialProjection, bool, error) {
	return r.legacyCredentialRepository().SyncLegacyCredentialDisabled(ctx, request)
}

func (r *UserRepository) ResolveLegacyCredentialClassification(ctx context.Context, request ports.LegacyCredentialResolutionRequest) (ports.LegacyCredentialProjection, error) {
	return r.legacyCredentialRepository().ResolveLegacyCredentialClassification(ctx, request)
}

func (r *UserRepository) GetLegacyCredentialProjection(ctx context.Context, tenantID, userID shared.ID) (ports.LegacyCredentialProjection, error) {
	return r.legacyCredentialRepository().GetLegacyCredentialProjection(ctx, tenantID, userID)
}

func (r *UserRepository) ReconcileLegacyCredentials(ctx context.Context, tenantID shared.ID) (ports.LegacyCredentialReconciliation, error) {
	return r.legacyCredentialRepository().ReconcileLegacyCredentials(ctx, tenantID)
}
