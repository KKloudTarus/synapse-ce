package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PrivacyPolicyRepository persists immutable source-policy versions and the
// separately mutable active pointer under tenant RLS.
type PrivacyPolicyRepository struct {
	pool *pgxpool.Pool
	*FleetAuditRepository
}

func NewPrivacyPolicyRepository(pool *pgxpool.Pool) (*PrivacyPolicyRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: privacy-policy repository requires a database pool", shared.ErrValidation)
	}
	audits, err := NewFleetAuditRepository(pool)
	if err != nil {
		return nil, err
	}
	return &PrivacyPolicyRepository{pool: pool, FleetAuditRepository: audits}, nil
}

var _ ports.PrivacyPolicyStore = (*PrivacyPolicyRepository)(nil)
var _ ports.PrivacyPolicyAuditStore = (*PrivacyPolicyRepository)(nil)

func (r *PrivacyPolicyRepository) PutPrivacyPolicy(
	ctx context.Context,
	assignment privacy.Assignment,
) (bool, error) {
	tenantID, err := privacyPolicyPostgresTenant(ctx, assignment.TenantID)
	if err != nil {
		return false, err
	}
	assignment.TenantID = tenantID
	if err := assignment.Validate(); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(assignment.Policy)
	if err != nil {
		return false, fmt.Errorf("marshal privacy policy: %w", err)
	}
	created := false
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO privacy_policies
			(tenant_id,policy_version,policy,digest,created_by,created_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT DO NOTHING`,
			tenantID.String(), assignment.Policy.Version, encoded, assignment.Digest,
			assignment.CreatedBy, assignment.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert privacy policy: %w", err)
		}
		created = tag.RowsAffected() == 1
		if !created {
			var stored privacy.Assignment
			err := scanPrivacyAssignment(tx.QueryRow(ctx, `SELECT tenant_id,policy,digest,created_by,created_at
				FROM privacy_policies WHERE tenant_id=$1 AND policy_version=$2`,
				tenantID.String(), assignment.Policy.Version), &stored)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: privacy policy digest already belongs to another version", shared.ErrConflict)
			}
			if err != nil {
				return fmt.Errorf("load existing privacy policy: %w", err)
			}
			if !privacy.SameAssignment(stored, assignment) {
				return fmt.Errorf("%w: privacy policy version already has different immutable content", shared.ErrConflict)
			}
		}
		return nil
	})
	return created, err
}

func (r *PrivacyPolicyRepository) ActivatePrivacyPolicy(
	ctx context.Context,
	activation privacy.Activation,
) (privacy.Activation, error) {
	tenantID, err := privacyPolicyPostgresTenant(ctx, activation.TenantID)
	if err != nil {
		return privacy.Activation{}, err
	}
	activation.TenantID = tenantID
	// timestamptz keeps microseconds. Normalize before admission so the returned
	// activation is byte-identical to the durable row, and so an activation audit
	// derived from it cannot disagree with what a restart would read back.
	activation.ActivatedAt = activation.ActivatedAt.UTC().Truncate(time.Microsecond)
	validation := activation
	if validation.Revision == 0 {
		validation.Revision = 1
	}
	if err := validation.Validate(); err != nil {
		return privacy.Activation{}, err
	}

	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var version string
		if err := tx.QueryRow(ctx, `SELECT policy_version FROM privacy_policies
			WHERE tenant_id=$1 AND digest=$2`, tenantID.String(), activation.PolicyDigest).Scan(&version); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return fmt.Errorf("resolve privacy policy for activation: %w", err)
		}
		if version != activation.PolicyVersion {
			return fmt.Errorf("%w: privacy activation policy identity is inconsistent", shared.ErrConflict)
		}

		var existing privacy.Activation
		err := tx.QueryRow(ctx, `SELECT tenant_id,operation_id,revision,policy_digest,
			policy_version,activated_by,activated_at FROM privacy_policy_activations
			WHERE tenant_id=$1 AND operation_id=$2`, tenantID.String(), activation.OperationID.String()).Scan(
			&existing.TenantID, &existing.OperationID, &existing.Revision, &existing.PolicyDigest,
			&existing.PolicyVersion, &existing.ActivatedBy, &existing.ActivatedAt,
		)
		if err == nil {
			if existing.PolicyDigest != activation.PolicyDigest ||
				existing.PolicyVersion != activation.PolicyVersion ||
				existing.ActivatedBy != activation.ActivatedBy {
				return fmt.Errorf("%w: privacy activation operation already has different immutable content", shared.ErrConflict)
			}
			// pgx scans timestamptz in the session's local zone. An exact retry must return a
			// value indistinguishable from the first admission, and the audit intention derived
			// from it must hash identically, so normalize to the UTC identity we stored.
			existing.ActivatedAt = existing.ActivatedAt.UTC()
			activation = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("load privacy activation operation: %w", err)
		}

		var lockResult int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM pg_advisory_xact_lock(hashtextextended($1,0))`, tenantID.String()).Scan(&lockResult); err != nil {
			return fmt.Errorf("lock privacy activation sequence: %w", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(revision),0)+1
			FROM privacy_policy_activations WHERE tenant_id=$1`, tenantID.String()).Scan(&activation.Revision); err != nil {
			return fmt.Errorf("allocate privacy activation revision: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO privacy_policy_activations
			(tenant_id,operation_id,revision,policy_digest,policy_version,activated_by,activated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, tenantID.String(), activation.OperationID.String(),
			activation.Revision, activation.PolicyDigest, activation.PolicyVersion,
			activation.ActivatedBy, activation.ActivatedAt); err != nil {
			return fmt.Errorf("insert privacy activation: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO privacy_active_policies
			(tenant_id,policy_version,activated_at) VALUES ($1,$2,$3)
			ON CONFLICT (tenant_id) DO UPDATE SET
			policy_version=EXCLUDED.policy_version,
			activated_at=EXCLUDED.activated_at`, tenantID.String(), activation.PolicyVersion,
			activation.ActivatedAt); err != nil {
			return fmt.Errorf("activate privacy policy: %w", err)
		}
		return nil
	})
	return activation, err
}

func (r *PrivacyPolicyRepository) ActivatePrivacyPolicyWithAudit(
	ctx context.Context,
	activation privacy.Activation,
	intent ports.FleetAuditIntent,
) (privacy.Activation, ports.FleetAuditIntent, error) {
	tenantID, err := privacyPolicyPostgresTenant(ctx, activation.TenantID)
	if err != nil {
		return privacy.Activation{}, ports.FleetAuditIntent{}, err
	}
	var admitted privacy.Activation
	var committed ports.FleetAuditIntent
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		transactionCtx := context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{
			tenantID: tenantID.String(),
			tx:       tx,
		})
		var err error
		admitted, err = r.ActivatePrivacyPolicy(transactionCtx, activation)
		if err != nil {
			return err
		}
		// Bind the audit payload to the revision and instant that actually became
		// durable: an exact operation retry re-reads the original activation, so its
		// audit entry stays identical instead of drifting to the retry's clock.
		// Clone the metadata first — the map belongs to the caller, and mutating it in
		// place would make the caller's own copy silently track ours.
		candidate := intent
		candidate.Entry.Metadata = maps.Clone(candidate.Entry.Metadata)
		candidate.Entry.At = admitted.ActivatedAt
		candidate.Entry.Metadata["revision"] = fmt.Sprintf("%d", admitted.Revision)
		committed, err = r.InsertFleetAudit(transactionCtx, candidate)
		return err
	})
	return admitted, committed, err
}

func (r *PrivacyPolicyRepository) PrivacyPolicyActivationHistory(
	ctx context.Context,
	tenantID shared.ID,
) ([]privacy.Activation, error) {
	tenantID, err := privacyPolicyPostgresTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items := make([]privacy.Activation, 0)
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,operation_id,revision,policy_digest,
			policy_version,activated_by,activated_at FROM privacy_policy_activations
			WHERE tenant_id=$1 ORDER BY revision`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list privacy activation history: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item privacy.Activation
			if err := rows.Scan(&item.TenantID, &item.OperationID, &item.Revision,
				&item.PolicyDigest, &item.PolicyVersion, &item.ActivatedBy, &item.ActivatedAt); err != nil {
				return fmt.Errorf("scan privacy activation: %w", err)
			}
			// pgx scans timestamptz in the session's local zone. Governance history must read
			// back as the same instant identity that was admitted, whatever TZ the process runs in.
			item.ActivatedAt = item.ActivatedAt.UTC()
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

func (r *PrivacyPolicyRepository) ActivePrivacyPolicy(
	ctx context.Context,
	tenantID shared.ID,
) (privacy.Assignment, error) {
	tenantID, err := privacyPolicyPostgresTenant(ctx, tenantID)
	if err != nil {
		return privacy.Assignment{}, err
	}
	var assignment privacy.Assignment
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		return scanPrivacyAssignment(tx.QueryRow(ctx, `SELECT p.tenant_id,p.policy,p.digest,p.created_by,p.created_at
			FROM privacy_active_policies active JOIN privacy_policies p
			ON p.tenant_id=active.tenant_id AND p.policy_version=active.policy_version
			WHERE active.tenant_id=$1`, tenantID.String()), &assignment)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	if err != nil {
		return privacy.Assignment{}, fmt.Errorf("load active privacy policy: %w", err)
	}
	return assignment, nil
}

func (r *PrivacyPolicyRepository) PrivacyPolicyByDigest(
	ctx context.Context,
	tenantID shared.ID,
	digest string,
) (privacy.Assignment, error) {
	tenantID, err := privacyPolicyPostgresTenant(ctx, tenantID)
	if err != nil {
		return privacy.Assignment{}, err
	}
	if digest == "" {
		return privacy.Assignment{}, fmt.Errorf("%w: privacy policy digest is required", shared.ErrValidation)
	}
	var assignment privacy.Assignment
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		return scanPrivacyAssignment(tx.QueryRow(ctx, `SELECT tenant_id,policy,digest,created_by,created_at
			FROM privacy_policies WHERE tenant_id=$1 AND digest=$2`,
			tenantID.String(), digest), &assignment)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	if err != nil {
		return privacy.Assignment{}, fmt.Errorf("load privacy policy by digest: %w", err)
	}
	return assignment, nil
}

func (r *PrivacyPolicyRepository) PrivacyPolicyHistory(
	ctx context.Context,
	tenantID shared.ID,
) ([]privacy.Assignment, error) {
	tenantID, err := privacyPolicyPostgresTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items := make([]privacy.Assignment, 0)
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,policy,digest,created_by,created_at
			FROM privacy_policies WHERE tenant_id=$1
			ORDER BY created_at DESC,policy_version DESC`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list privacy policies: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var assignment privacy.Assignment
			if err := scanPrivacyAssignment(rows, &assignment); err != nil {
				return err
			}
			items = append(items, assignment)
		}
		return rows.Err()
	})
	return items, err
}

func scanPrivacyAssignment(row rowScanner, assignment *privacy.Assignment) error {
	var encoded []byte
	if err := row.Scan(
		&assignment.TenantID,
		&encoded,
		&assignment.Digest,
		&assignment.CreatedBy,
		&assignment.CreatedAt,
	); err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, &assignment.Policy); err != nil {
		return fmt.Errorf("decode privacy policy: %w", err)
	}
	if err := assignment.Validate(); err != nil {
		return fmt.Errorf("validate stored privacy policy: %w", err)
	}
	return nil
}

func privacyPolicyPostgresTenant(ctx context.Context, requested shared.ID) (shared.ID, error) {
	bound, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	bound, requested = shared.TenantOrDefault(bound), shared.TenantOrDefault(requested)
	if bound != requested {
		return "", fmt.Errorf("%w: privacy policy tenant does not match context", shared.ErrForbidden)
	}
	return bound, nil
}
