package identityrollout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	IdentityBackfillSchemaVersion = 1
	DefaultIdentityBackfillBatch  = 500
	MaxIdentityBackfillBatch      = 2000
	defaultIdentityBackfillLease  = 10 * time.Minute
	legacyBootstrapUserID         = "operator"
)

const (
	BackfillOutcomeProjected = "projected"
	BackfillOutcomeUnchanged = "unchanged"
	BackfillOutcomeDrift     = "drift"
)

// BackfillRunner projects legacy users into persons/memberships while users remains authoritative.
// It is deliberately tenant-at-a-time so every derived membership write stays under the normal
// tenant RLS boundary. The global person row is reached only as part of the store's atomic projection.
type BackfillRunner struct {
	source ports.IdentityBackfillSource
	store  ports.IdentityBackfillStore
	ids    ports.IDGenerator
	clock  ports.Clock
}

func NewBackfillRunner(source ports.IdentityBackfillSource, store ports.IdentityBackfillStore, ids ports.IDGenerator, clock ports.Clock) (*BackfillRunner, error) {
	if source == nil || store == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: identity backfill dependencies are required", shared.ErrValidation)
	}
	return &BackfillRunner{source: source, store: store, ids: ids, clock: clock}, nil
}

type BackfillRequest struct {
	TenantID      shared.ID
	Actor         string
	LeaseOwner    string
	BatchSize     int
	ResumeAfter   shared.ID
	LeaseDuration time.Duration
}

func (runner *BackfillRunner) Run(ctx context.Context, request BackfillRequest) (ports.IdentityBackfillRun, error) {
	tenantID := shared.TenantOrDefault(request.TenantID)
	actor := strings.TrimSpace(request.Actor)
	leaseOwner := strings.TrimSpace(request.LeaseOwner)
	if tenantID.IsZero() || actor == "" || len(actor) > 256 || leaseOwner == "" || len(leaseOwner) > 256 {
		return ports.IdentityBackfillRun{}, fmt.Errorf("%w: tenant, actor, and lease owner are required", shared.ErrValidation)
	}
	batchSize := request.BatchSize
	if batchSize == 0 {
		batchSize = DefaultIdentityBackfillBatch
	}
	if batchSize < 1 || batchSize > MaxIdentityBackfillBatch {
		return ports.IdentityBackfillRun{}, fmt.Errorf("%w: batch size must be between 1 and %d", shared.ErrValidation, MaxIdentityBackfillBatch)
	}
	leaseDuration := request.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultIdentityBackfillLease
	}
	now := runner.clock.Now().UTC()
	acquisitionID := runner.ids.NewID()
	run, _, err := runner.store.AcquireIdentityBackfillRun(ctx, ports.IdentityBackfillAcquireRequest{
		Run: ports.IdentityBackfillRun{
			TenantID: tenantID, ID: acquisitionID, SchemaVersion: IdentityBackfillSchemaVersion,
			BatchSize: batchSize, SnapshotAt: now, State: ports.IdentityBackfillRunning,
			LeaseOwner: leaseOwner, LeaseToken: acquisitionID, LeaseExpiresAt: now.Add(leaseDuration),
			CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		},
		ResumeAfter: request.ResumeAfter, LeaseDuration: leaseDuration,
	})
	if err != nil {
		return ports.IdentityBackfillRun{}, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillCancelled, ports.IdentityBackfillReconciliation{}, err)
		}
		sources, err := runner.source.ListLegacyHumans(ctx, tenantID, run.CheckpointUser, run.SnapshotAt, run.BatchSize)
		if err != nil {
			return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, err)
		}
		if len(sources) > run.BatchSize {
			return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, fmt.Errorf("identity backfill source returned %d rows for limit %d", len(sources), run.BatchSize))
		}
		if len(sources) == 0 {
			reconciliation, reconcileErr := runner.store.ReconcileIdentityBackfill(ctx, tenantID, run.SnapshotAt)
			if reconcileErr != nil {
				return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, reconcileErr)
			}
			if reconciliation.CorruptCredentialCount != 0 || reconciliation.DuplicateCredentialCount != 0 || reconciliation.BootstrapMembershipCount != 0 {
				cause := fmt.Errorf("%w: identity backfill safety reconciliation failed: corrupt_credentials=%d duplicate_credentials=%d bootstrap_memberships=%d", shared.ErrConflict, reconciliation.CorruptCredentialCount, reconciliation.DuplicateCredentialCount, reconciliation.BootstrapMembershipCount)
				return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, reconciliation, cause)
			}
			return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillCompleted, reconciliation, nil)
		}

		seenHashes := make(map[string]shared.ID, len(sources))
		checkpoint := run.CheckpointUser
		for _, source := range sources {
			if err := ctx.Err(); err != nil {
				return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillCancelled, ports.IdentityBackfillReconciliation{}, err)
			}
			checkpoint = source.UserID
			if source.UserID.String() == legacyBootstrapUserID {
				// Defense in depth: the PostgreSQL source excludes bootstrap, but a different adapter
				// must not accidentally turn deployment recovery authority into an ordinary membership.
				continue
			}
			if err := validateLegacyHuman(tenantID, source); err != nil {
				return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, err)
			}
			if prior, exists := seenHashes[source.APIKeyHash]; exists && prior != source.UserID {
				return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, fmt.Errorf("%w: duplicate legacy credential digest in backfill batch", shared.ErrConflict))
			}
			seenHashes[source.APIKeyHash] = source.UserID
			sourceHash := legacyHumanHash(source)

			if existing, itemErr := runner.store.GetIdentityBackfillItem(ctx, tenantID, run.ID, source.UserID); itemErr == nil {
				if existing.SourceHash != sourceHash {
					return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, fmt.Errorf("%w: legacy user %s changed after it was projected; start a new snapshot", shared.ErrConflict, source.UserID))
				}
				continue
			} else if !errors.Is(itemErr, shared.ErrNotFound) {
				return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, itemErr)
			}

			if _, _, err := runner.store.ProjectLegacyHuman(ctx, run, source, sourceHash, runner.clock.Now().UTC()); err != nil {
				return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, err)
			}
		}

		run, err = runner.store.AdvanceIdentityBackfillRun(ctx, tenantID, run.ID, leaseOwner, run.LeaseToken, checkpoint, runner.clock.Now().UTC(), leaseDuration)
		if err != nil {
			return runner.finish(ctx, run, leaseOwner, ports.IdentityBackfillFailed, ports.IdentityBackfillReconciliation{}, err)
		}
	}
}

func (runner *BackfillRunner) finish(ctx context.Context, run ports.IdentityBackfillRun, leaseOwner string, state ports.IdentityBackfillState, reconciliation ports.IdentityBackfillReconciliation, cause error) (ports.IdentityBackfillRun, error) {
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	finished, err := runner.store.FinishIdentityBackfillRun(finishCtx, run.TenantID, run.ID, leaseOwner, run.LeaseToken, state, reconciliation, runner.clock.Now().UTC())
	if err != nil {
		if cause != nil {
			return run, errors.Join(cause, err)
		}
		return run, err
	}
	if cause != nil {
		return finished, cause
	}
	return finished, nil
}

func validateLegacyHuman(tenantID shared.ID, source ports.LegacyHumanSnapshot) error {
	if shared.TenantOrDefault(source.TenantID) != tenantID || source.UserID.IsZero() {
		return fmt.Errorf("%w: legacy user tenant/id is invalid", shared.ErrValidation)
	}
	if strings.TrimSpace(source.Name) == "" || len(strings.TrimSpace(source.Name)) > 200 || !source.Role.Valid() {
		return fmt.Errorf("%w: legacy user %s profile is invalid", shared.ErrValidation, source.UserID)
	}
	if !isLowerHexDigest(source.APIKeyHash) {
		return fmt.Errorf("%w: legacy user %s has a corrupt credential digest", shared.ErrValidation, source.UserID)
	}
	if source.CreatedAt.IsZero() || source.UpdatedAt.Before(source.CreatedAt) {
		return fmt.Errorf("%w: legacy user %s timestamps are invalid", shared.ErrValidation, source.UserID)
	}
	return nil
}

func isLowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	return strings.ToLower(value) == value
}

func legacyHumanHash(source ports.LegacyHumanSnapshot) string {
	// Length-prefix each free-form value so the hash is unambiguous without inventing a JSON schema.
	parts := []string{
		source.TenantID.String(), source.UserID.String(), source.Name, string(source.Role), source.APIKeyHash,
		strconv.FormatBool(source.Disabled), source.CreatedAt.UTC().Format(time.RFC3339Nano), source.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(strconv.Itoa(len(part))))
		_, _ = h.Write([]byte{':'})
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}
