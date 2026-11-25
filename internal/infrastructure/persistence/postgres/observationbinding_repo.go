package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// observationBindingCols is the column order every scan in this file relies on.
const observationBindingCols = `id, tenant_id, engagement_id, scope, external_identity, finding_id,
	observation_id, version, decided_by, reason, decided_at, superseded_at`

// ObservationBindingRepository persists human-approved observation-to-finding bindings.
//
// Every statement runs through WithTenant, so a caller inside TenantTransactionRunner.Run writes on THAT
// transaction and a caller outside it gets its own. The partial unique index
// observation_finding_bindings_current is what decides a race between two adopters: the loser gets a
// 23505 and is told a binding is already in force, rather than both callers believing they own the
// remediation workflow.
type ObservationBindingRepository struct{ pool *pgxpool.Pool }

// NewObservationBindingRepository returns the PostgreSQL binding store.
func NewObservationBindingRepository(pool *pgxpool.Pool) *ObservationBindingRepository {
	return &ObservationBindingRepository{pool: pool}
}

var _ ports.ObservationBindingStore = (*ObservationBindingRepository)(nil)

// Adopt records the first binding for a scoped identity, and is idempotent for the same finding.
func (r *ObservationBindingRepository) Adopt(ctx context.Context, tenantID shared.ID, binding observationbinding.Binding) (observationbinding.Binding, error) {
	if err := validateBindingWrite(tenantID, binding); err != nil {
		return observationbinding.Binding{}, err
	}
	if binding.Version != 1 {
		return observationbinding.Binding{}, fmt.Errorf("%w: an adopted binding starts at version 1", shared.ErrValidation)
	}
	if !binding.SupersededAt.IsZero() {
		return observationbinding.Binding{}, fmt.Errorf("%w: an adopted binding cannot already be superseded", shared.ErrValidation)
	}

	var persisted observationbinding.Binding
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		// Take the current row first, under a lock, so a concurrent adopter of the same identity waits
		// here instead of racing to the unique index and failing with a constraint name.
		current, err := lockCurrentBinding(ctx, tx, binding)
		switch {
		case err == nil && current.FindingID == binding.FindingID:
			// A retry of the same decision. Returning the binding already in force keeps a repeated
			// request from minting a second version of an unchanged decision.
			persisted = current
			return nil
		case err == nil:
			return fmt.Errorf("%w: observation %s/%s is already bound to finding %s", shared.ErrConflict,
				binding.Scope, binding.ExternalIdentity, current.FindingID)
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("read current observation binding: %w", err)
		}

		persisted, err = insertBinding(ctx, tx, tenantID, binding)
		return err
	})
	if err != nil {
		return observationbinding.Binding{}, err
	}
	return persisted, nil
}

// Supersede retires the binding in force and inserts its replacement in one transaction.
func (r *ObservationBindingRepository) Supersede(ctx context.Context, tenantID shared.ID, expectedVersion int, binding observationbinding.Binding) (observationbinding.Binding, error) {
	if err := validateBindingWrite(tenantID, binding); err != nil {
		return observationbinding.Binding{}, err
	}
	if expectedVersion < 1 {
		return observationbinding.Binding{}, fmt.Errorf("%w: superseding needs the version being replaced", shared.ErrValidation)
	}
	if binding.Version != expectedVersion+1 {
		return observationbinding.Binding{}, fmt.Errorf("%w: a superseding binding is one version after the one it replaces", shared.ErrValidation)
	}

	var persisted observationbinding.Binding
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		current, err := lockCurrentBinding(ctx, tx, binding)
		if errors.Is(err, pgx.ErrNoRows) {
			// Either nothing was ever adopted, or another supersede committed while this one waited on
			// its lock. Those are different answers: the second caller decided against a view that has
			// moved, which is a conflict to refetch, not a missing binding to report as 404.
			latest, latestErr := latestBindingVersion(ctx, tx, binding)
			if latestErr != nil {
				return latestErr
			}
			if latest > 0 {
				return fmt.Errorf("%w: observation binding is at version %d, not %d", shared.ErrConflict, latest, expectedVersion)
			}
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read current observation binding: %w", err)
		}
		if current.Version != expectedVersion {
			// The caller decided against a view that has moved. Applying it anyway would silently
			// discard whatever decision was made in between.
			return fmt.Errorf("%w: observation binding is at version %d, not %d", shared.ErrConflict, current.Version, expectedVersion)
		}
		// Two API replicas with skewed clocks can hand this a decision time earlier than the one being
		// retired. The table refuses that row, so the retirement is clamped instead: a decision never
		// retires before it was made, and a skewed clock costs an ordering nuance rather than a 500.
		retiredAt := binding.DecidedAt.UTC()
		if retiredAt.Before(current.DecidedAt) {
			retiredAt = current.DecidedAt
		}
		if _, err := tx.Exec(ctx, `UPDATE observation_finding_bindings SET superseded_at=$2
			WHERE tenant_id=current_setting('app.current_tenant') AND id=$1`, current.ID.String(), retiredAt); err != nil {
			return fmt.Errorf("retire current observation binding: %w", err)
		}
		persisted, err = insertBinding(ctx, tx, tenantID, binding)
		return err
	})
	if err != nil {
		return observationbinding.Binding{}, err
	}
	return persisted, nil
}

// Current returns the binding in force for a scoped identity.
func (r *ObservationBindingRepository) Current(ctx context.Context, tenantID, engagementID shared.ID, identity observationbinding.Identity) (observationbinding.Binding, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return observationbinding.Binding{}, fmt.Errorf("%w: an observation binding read needs a tenant and an engagement", shared.ErrValidation)
	}
	if err := identity.Validate(); err != nil {
		return observationbinding.Binding{}, err
	}
	var binding observationbinding.Binding
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var scanErr error
		binding, scanErr = scanObservationBinding(tx.QueryRow(ctx, `SELECT `+observationBindingCols+`
			FROM observation_finding_bindings
			WHERE tenant_id=current_setting('app.current_tenant') AND engagement_id=$1
			  AND scope=$2 AND external_identity=$3 AND superseded_at IS NULL`,
			engagementID.String(), identity.Scope, identity.ExternalIdentity))
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return scanErr
	})
	if err != nil {
		return observationbinding.Binding{}, err
	}
	return binding, nil
}

// CurrentByEngagement returns only the bindings in force, unordered.
//
// It exists because the page-load path folds the result straight into a map: ordering every version by
// decision time is work with no consumer, and at scale it is the difference between an index scan and an
// on-disk sort of rows the caller then throws away.
func (r *ObservationBindingRepository) CurrentByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]observationbinding.Binding, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return nil, fmt.Errorf("%w: an observation binding listing needs a tenant and an engagement", shared.ErrValidation)
	}
	var out []observationbinding.Binding
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+observationBindingCols+` FROM observation_finding_bindings
			WHERE tenant_id=current_setting('app.current_tenant') AND engagement_id=$1
			  AND superseded_at IS NULL`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list current observation bindings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			binding, scanErr := scanObservationBinding(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, binding)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListByEngagement returns every version in the engagement, newest decision first.
func (r *ObservationBindingRepository) ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]observationbinding.Binding, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return nil, fmt.Errorf("%w: an observation binding listing needs a tenant and an engagement", shared.ErrValidation)
	}
	var out []observationbinding.Binding
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+observationBindingCols+` FROM observation_finding_bindings
			WHERE tenant_id=current_setting('app.current_tenant') AND engagement_id=$1
			ORDER BY decided_at DESC, version DESC, id DESC`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list observation bindings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			binding, scanErr := scanObservationBinding(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, binding)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// lockCurrentBinding reads the version in force FOR UPDATE, so a concurrent writer for the same identity
// serializes behind it rather than discovering the clash as a constraint violation.
// The tenant is not a parameter: it travels in app.current_tenant, which WithTenant set for this
// transaction, and reading it from there is what keeps the query and the RLS policy agreeing.
func lockCurrentBinding(ctx context.Context, tx pgx.Tx, binding observationbinding.Binding) (observationbinding.Binding, error) {
	return scanObservationBinding(tx.QueryRow(ctx, `SELECT `+observationBindingCols+`
		FROM observation_finding_bindings
		WHERE tenant_id=current_setting('app.current_tenant') AND engagement_id=$1
		  AND scope=$2 AND external_identity=$3 AND superseded_at IS NULL
		FOR UPDATE`, binding.EngagementID.String(), binding.Scope, binding.ExternalIdentity))
}

// latestBindingVersion returns the highest version recorded for an identity, or 0 when it has none. It
// is what tells a lost supersede race apart from a binding that was never adopted.
func latestBindingVersion(ctx context.Context, tx pgx.Tx, binding observationbinding.Binding) (int, error) {
	var latest *int
	if err := tx.QueryRow(ctx, `SELECT max(version) FROM observation_finding_bindings
		WHERE tenant_id=current_setting('app.current_tenant') AND engagement_id=$1
		  AND scope=$2 AND external_identity=$3`,
		binding.EngagementID.String(), binding.Scope, binding.ExternalIdentity).Scan(&latest); err != nil {
		return 0, fmt.Errorf("read latest observation binding version: %w", err)
	}
	if latest == nil {
		return 0, nil
	}
	return *latest, nil
}

func insertBinding(ctx context.Context, tx pgx.Tx, tenantID shared.ID, binding observationbinding.Binding) (observationbinding.Binding, error) {
	_, err := tx.Exec(ctx, `INSERT INTO observation_finding_bindings
		(id, tenant_id, engagement_id, scope, external_identity, finding_id, observation_id, version,
		 decided_by, reason, decided_at)
		VALUES ($1, current_setting('app.current_tenant'), $2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		binding.ID.String(), binding.EngagementID.String(), binding.Scope, binding.ExternalIdentity,
		binding.FindingID.String(), binding.ObservationID.String(), binding.Version,
		binding.DecidedBy.String(), binding.Reason, binding.DecidedAt.UTC())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch {
			case pgErr.Code == "23505":
				// Two adopters got past the lock on different connections, which the partial unique index
				// is the final arbiter of.
				return observationbinding.Binding{}, fmt.Errorf("%w: a binding for this observation is already in force", shared.ErrConflict)
			case pgErr.Code == "23503":
				// The composite foreign keys carry the tenant and the engagement, so this is also what a
				// cross-tenant or cross-engagement reference looks like.
				return observationbinding.Binding{}, fmt.Errorf("%w: the finding or the observation does not exist in this tenant engagement", shared.ErrValidation)
			}
		}
		return observationbinding.Binding{}, fmt.Errorf("insert observation binding: %w", err)
	}
	return binding, nil
}

func validateBindingWrite(tenantID shared.ID, binding observationbinding.Binding) error {
	if tenantID.IsZero() {
		return fmt.Errorf("%w: an observation binding write needs a tenant", shared.ErrValidation)
	}
	if binding.TenantID != tenantID {
		return fmt.Errorf("%w: observation binding %s is stamped with tenant %q but was written into %q",
			shared.ErrValidation, binding.ID, binding.TenantID, tenantID)
	}
	return binding.Validate()
}

type bindingScanner interface {
	Scan(dest ...any) error
}

func scanObservationBinding(row bindingScanner) (observationbinding.Binding, error) {
	var (
		binding      observationbinding.Binding
		id, tenant   string
		engagement   string
		findingID    string
		observation  string
		decidedBy    string
		supersededAt *time.Time
	)
	if err := row.Scan(&id, &tenant, &engagement, &binding.Scope, &binding.ExternalIdentity, &findingID,
		&observation, &binding.Version, &decidedBy, &binding.Reason, &binding.DecidedAt, &supersededAt); err != nil {
		return observationbinding.Binding{}, err
	}
	binding.ID, binding.TenantID, binding.EngagementID = shared.ID(id), shared.ID(tenant), shared.ID(engagement)
	binding.FindingID, binding.ObservationID, binding.DecidedBy = shared.ID(findingID), shared.ID(observation), shared.ID(decidedBy)
	binding.DecidedAt = binding.DecidedAt.UTC()
	if supersededAt != nil {
		binding.SupersededAt = supersededAt.UTC()
	}
	return binding, nil
}
