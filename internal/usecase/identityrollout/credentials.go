package identityrollout

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CredentialProjectionRunner performs the D5 offline classification/projection pass while legacy
// users remains authoritative. It is intentionally restart-from-beginning and idempotent: the D5
// projection store owns per-user optimistic versions and always re-reads the current legacy source.
// A persisted lease is unnecessary here because concurrent runners converge on the same classified
// row or conflict visibly; D4's membership backfill, which creates identity authority, remains the
// leased/fenced phase.
type CredentialProjectionRunner struct {
	source ports.IdentityBackfillSource
	store  ports.LegacyCredentialProjectionStore
	clock  ports.Clock
}

func NewCredentialProjectionRunner(source ports.IdentityBackfillSource, store ports.LegacyCredentialProjectionStore, clock ports.Clock) (*CredentialProjectionRunner, error) {
	if source == nil || store == nil || clock == nil {
		return nil, fmt.Errorf("%w: legacy credential projection dependencies are required", shared.ErrValidation)
	}
	return &CredentialProjectionRunner{source: source, store: store, clock: clock}, nil
}

type CredentialProjectionRequest struct {
	TenantID  shared.ID
	BatchSize int
}

func (runner *CredentialProjectionRunner) Run(ctx context.Context, request CredentialProjectionRequest) (ports.LegacyCredentialReconciliation, error) {
	tenantID := shared.TenantOrDefault(request.TenantID)
	if tenantID.IsZero() {
		return ports.LegacyCredentialReconciliation{}, fmt.Errorf("%w: legacy credential projection tenant is required", shared.ErrValidation)
	}
	batchSize := request.BatchSize
	if batchSize == 0 {
		batchSize = DefaultIdentityBackfillBatch
	}
	if batchSize < 1 || batchSize > MaxIdentityBackfillBatch {
		return ports.LegacyCredentialReconciliation{}, fmt.Errorf("%w: legacy credential projection batch size must be between 1 and %d", shared.ErrValidation, MaxIdentityBackfillBatch)
	}

	// Freeze row admission. Individual rows are deliberately re-read by the store at projection
	// time, so a concurrent legacy rotation/disable cannot be overwritten by a stale page value.
	snapshotAt := runner.clock.Now().UTC()
	var after shared.ID
	for {
		if err := ctx.Err(); err != nil {
			return ports.LegacyCredentialReconciliation{}, err
		}
		batch, err := runner.source.ListLegacyHumans(ctx, tenantID, after, snapshotAt, batchSize)
		if err != nil {
			return ports.LegacyCredentialReconciliation{}, fmt.Errorf("list legacy credentials for projection: %w", err)
		}
		if len(batch) > batchSize {
			return ports.LegacyCredentialReconciliation{}, fmt.Errorf("%w: legacy credential source returned %d rows for limit %d", shared.ErrConflict, len(batch), batchSize)
		}
		if len(batch) == 0 {
			reconciliation, err := runner.store.ReconcileLegacyCredentials(ctx, tenantID)
			if err != nil {
				return ports.LegacyCredentialReconciliation{}, err
			}
			return reconciliation, nil
		}

		for _, source := range batch {
			if err := ctx.Err(); err != nil {
				return ports.LegacyCredentialReconciliation{}, err
			}
			if shared.TenantOrDefault(source.TenantID) != tenantID || source.UserID.IsZero() {
				return ports.LegacyCredentialReconciliation{}, fmt.Errorf("%w: legacy credential source returned invalid tenant/user identity", shared.ErrValidation)
			}
			if source.UserID.String() == legacyBootstrapUserID {
				// Defense in depth for alternate adapters; PostgreSQL D4 source already excludes it.
				after = source.UserID
				continue
			}
			if _, err := runner.store.ClassifyAndProjectLegacyCredential(ctx, tenantID, source.UserID, runner.clock.Now().UTC()); err != nil {
				return ports.LegacyCredentialReconciliation{}, fmt.Errorf("project legacy credential %s: %w", source.UserID, err)
			}
			after = source.UserID
		}
	}
}
