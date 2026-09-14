package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const identityBackfillRunCols = `tenant_id,id,schema_version,batch_size,snapshot_at,checkpoint_user_id,state,lease_owner,lease_token,lease_expires_at,processed_count,projected_count,unchanged_count,drift_count,source_count,person_count,membership_count,created_by,created_at,updated_at,completed_at`

type IdentityRolloutRepository struct{ pool *pgxpool.Pool }

func NewIdentityRolloutRepository(pool *pgxpool.Pool) (*IdentityRolloutRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: identity rollout repository requires pool", shared.ErrValidation)
	}
	return &IdentityRolloutRepository{pool: pool}, nil
}

var _ ports.IdentityBackfillSource = (*IdentityRolloutRepository)(nil)
var _ ports.IdentityBackfillStore = (*IdentityRolloutRepository)(nil)
var _ ports.IdentityRolloutLedger = (*IdentityRolloutRepository)(nil)

func (repository *IdentityRolloutRepository) ListLegacyHumans(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) (out []ports.LegacyHumanSnapshot, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || snapshotAt.IsZero() || limit < 1 || limit > 2000 {
		return nil, fmt.Errorf("%w: identity legacy source query is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,name,role,api_key_hash,disabled,created_at,updated_at
			FROM users
			WHERE ownership_tenant_id=$1 AND id<>'operator' AND id COLLATE "C">$2 AND created_at<=$3
			ORDER BY id COLLATE "C" LIMIT $4`, tenantID.String(), after.String(), snapshotAt.UTC(), limit)
		if err != nil {
			return fmt.Errorf("list legacy identity users: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item ports.LegacyHumanSnapshot
			var role string
			item.TenantID = tenantID
			if err := rows.Scan(&item.UserID, &item.Name, &role, &item.APIKeyHash, &item.Disabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
				return fmt.Errorf("scan legacy identity user: %w", err)
			}
			item.Role = user.Role(role)
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

func (repository *IdentityRolloutRepository) AcquireIdentityBackfillRun(ctx context.Context, request ports.IdentityBackfillAcquireRequest) (run ports.IdentityBackfillRun, resumed bool, err error) {
	if err := validateIdentityBackfillAcquire(request); err != nil {
		return run, false, err
	}
	err = WithTenant(ctx, repository.pool, request.Run.TenantID.String(), func(tx pgx.Tx) error {
		existing, scanErr := scanIdentityBackfillRun(tx.QueryRow(ctx, `SELECT `+identityBackfillRunCols+` FROM identity_backfill_runs WHERE tenant_id=$1 AND state='running' FOR UPDATE`, request.Run.TenantID.String()))
		if scanErr == nil {
			if existing.SchemaVersion != request.Run.SchemaVersion || existing.BatchSize != request.Run.BatchSize {
				return fmt.Errorf("%w: identity backfill config differs from active run", shared.ErrConflict)
			}
			updated, updateErr := scanIdentityBackfillRun(tx.QueryRow(ctx, `UPDATE identity_backfill_runs
				SET lease_owner=$3,lease_token=$4,lease_expires_at=now()+($5 * interval '1 microsecond'),updated_at=$6
				WHERE tenant_id=$1 AND id=$2 AND state='running' AND (lease_owner=$3 OR lease_expires_at<=now())
				RETURNING `+identityBackfillRunCols,
				request.Run.TenantID.String(), existing.ID.String(), request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.LeaseDuration.Microseconds(), request.Run.CreatedAt.UTC()))
			if errors.Is(updateErr, pgx.ErrNoRows) {
				return fmt.Errorf("%w: identity backfill already has a live lease", shared.ErrConflict)
			}
			if updateErr != nil {
				return fmt.Errorf("resume identity backfill: %w", updateErr)
			}
			run, resumed = updated, true
			return nil
		}
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return fmt.Errorf("find active identity backfill: %w", scanErr)
		}
		created, createErr := scanIdentityBackfillRun(tx.QueryRow(ctx, `INSERT INTO identity_backfill_runs
			(tenant_id,id,schema_version,batch_size,snapshot_at,checkpoint_user_id,state,lease_owner,lease_token,lease_expires_at,
			 processed_count,projected_count,unchanged_count,drift_count,source_count,person_count,membership_count,created_by,created_at,updated_at,completed_at)
			VALUES($1,$2,$3,$4,$5,$6,'running',$7,$8,now()+($9 * interval '1 microsecond'),0,0,0,0,0,0,0,$10,$11,$11,NULL)
			RETURNING `+identityBackfillRunCols,
			request.Run.TenantID.String(), request.Run.ID.String(), request.Run.SchemaVersion, request.Run.BatchSize, request.Run.SnapshotAt.UTC(), request.ResumeAfter.String(),
			request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.LeaseDuration.Microseconds(), request.Run.CreatedBy, request.Run.CreatedAt.UTC()))
		if createErr != nil {
			return fmt.Errorf("create identity backfill run: %w", createErr)
		}
		run = created
		return nil
	})
	return run, resumed, err
}

func (repository *IdentityRolloutRepository) GetIdentityBackfillItem(ctx context.Context, tenantID, runID, userID shared.ID) (item ports.IdentityBackfillItem, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		return scanIdentityBackfillItem(tx.QueryRow(ctx, `SELECT tenant_id,run_id,user_id,person_id,membership_id,source_hash,outcome,reason_code,processed_at
			FROM identity_backfill_items WHERE tenant_id=$1 AND run_id=$2 AND user_id=$3`, tenantID.String(), runID.String(), userID.String()), &item)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return item, shared.ErrNotFound
	}
	if err != nil {
		return item, fmt.Errorf("get identity backfill item: %w", err)
	}
	return item, nil
}

func (repository *IdentityRolloutRepository) ProjectLegacyHuman(ctx context.Context, run ports.IdentityBackfillRun, source ports.LegacyHumanSnapshot, sourceHash string, now time.Time) (item ports.IdentityBackfillItem, created bool, err error) {
	tenantID := shared.TenantOrDefault(run.TenantID)
	if tenantID.IsZero() || run.ID.IsZero() || run.LeaseToken.IsZero() || source.UserID.IsZero() || shared.TenantOrDefault(source.TenantID) != tenantID || len(sourceHash) != 64 || now.IsZero() {
		return item, false, fmt.Errorf("%w: identity projection request is invalid", shared.ErrValidation)
	}
	now = now.UTC()
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var active bool
		if lockErr := tx.QueryRow(ctx, `SELECT state='running' AND lease_token=$3 AND lease_expires_at>now()
			FROM identity_backfill_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), run.ID.String(), run.LeaseToken.String()).Scan(&active); errors.Is(lockErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if lockErr != nil {
			return fmt.Errorf("lock identity backfill lease: %w", lockErr)
		}
		if !active {
			return fmt.Errorf("%w: identity backfill lease is stale", shared.ErrConflict)
		}

		var existing ports.IdentityBackfillItem
		itemErr := scanIdentityBackfillItem(tx.QueryRow(ctx, `SELECT tenant_id,run_id,user_id,person_id,membership_id,source_hash,outcome,reason_code,processed_at
			FROM identity_backfill_items WHERE tenant_id=$1 AND run_id=$2 AND user_id=$3`, tenantID.String(), run.ID.String(), source.UserID.String()), &existing)
		if itemErr == nil {
			if existing.SourceHash != sourceHash {
				return fmt.Errorf("%w: legacy source changed after projection", shared.ErrConflict)
			}
			item = existing
			return nil
		}
		if !errors.Is(itemErr, pgx.ErrNoRows) {
			return fmt.Errorf("read identity backfill item: %w", itemErr)
		}

		// Re-read and lock the authoritative legacy row inside the same transaction. A concurrent
		// legacy mutation between page read and projection is rejected instead of projected stale.
		var current ports.LegacyHumanSnapshot
		var currentRole string
		current.TenantID = tenantID
		if sourceErr := tx.QueryRow(ctx, `SELECT id,name,role,api_key_hash,disabled,created_at,updated_at FROM users
			WHERE ownership_tenant_id=$1 AND id=$2 AND id<>'operator' FOR SHARE`, tenantID.String(), source.UserID.String()).Scan(
			&current.UserID, &current.Name, &currentRole, &current.APIKeyHash, &current.Disabled, &current.CreatedAt, &current.UpdatedAt); errors.Is(sourceErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if sourceErr != nil {
			return fmt.Errorf("lock authoritative legacy user: %w", sourceErr)
		}
		current.Role = user.Role(currentRole)
		if !sameLegacyHuman(source, current) {
			return fmt.Errorf("%w: authoritative legacy user changed during projection", shared.ErrConflict)
		}

		expectedName := strings.TrimSpace(source.Name)
		expectedMembershipStatus := "active"
		if source.Disabled {
			expectedMembershipStatus = "suspended"
		}
		personExists, personMatches, err := inspectBackfillPerson(ctx, tx, source.UserID, expectedName)
		if err != nil {
			return err
		}
		membershipExists, membershipMatches, err := inspectBackfillMembership(ctx, tx, tenantID, source.UserID, source.Role, expectedMembershipStatus)
		if err != nil {
			return err
		}
		indexExists, err := inspectBackfillPersonIndex(ctx, tx, tenantID, source.UserID)
		if err != nil {
			return err
		}

		outcome, reason := "unchanged", "already_projected"
		if (personExists && !personMatches) || (membershipExists && !membershipMatches) {
			outcome, reason = "drift", "projection_mismatch"
		} else if !personExists || !membershipExists || !indexExists {
			if !personExists {
				if _, err := tx.Exec(ctx, `INSERT INTO persons(id,display_name,status,credential_epoch,version,created_at,updated_at)
					VALUES($1,$2,'active',1,1,$3,$4)`, source.UserID.String(), expectedName, source.CreatedAt.UTC(), source.UpdatedAt.UTC()); err != nil {
					return fmt.Errorf("project legacy person: %w", err)
				}
			}
			if !membershipExists {
				if _, err := tx.Exec(ctx, `INSERT INTO memberships(tenant_id,id,person_id,role,status,epoch,version,created_at,updated_at)
					VALUES($1,$2,$2,$3,$4,1,1,$5,$6)`, tenantID.String(), source.UserID.String(), string(source.Role), expectedMembershipStatus, source.CreatedAt.UTC(), source.UpdatedAt.UTC()); err != nil {
					return fmt.Errorf("project legacy membership: %w", err)
				}
			}
			if !indexExists {
				if _, err := tx.Exec(ctx, `INSERT INTO person_organization_index(person_id,tenant_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, source.UserID.String(), tenantID.String()); err != nil {
					return fmt.Errorf("project person organization index: %w", err)
				}
			}
			outcome, reason = "projected", "derived_rows_created"
		}

		item = ports.IdentityBackfillItem{TenantID: tenantID, RunID: run.ID, UserID: source.UserID, PersonID: source.UserID, MembershipID: source.UserID, SourceHash: sourceHash, Outcome: outcome, ReasonCode: reason, ProcessedAt: now}
		var inserted int
		insertErr := tx.QueryRow(ctx, `INSERT INTO identity_backfill_items(tenant_id,run_id,user_id,person_id,membership_id,source_hash,outcome,reason_code,processed_at)
			VALUES($1,$2,$3,$3,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,run_id,user_id) DO NOTHING RETURNING 1`,
			tenantID.String(), run.ID.String(), source.UserID.String(), sourceHash, outcome, reason, now).Scan(&inserted)
		if errors.Is(insertErr, pgx.ErrNoRows) {
			return nil
		}
		if insertErr != nil {
			return fmt.Errorf("save identity backfill item: %w", insertErr)
		}
		created = inserted == 1
		return nil
	})
	return item, created, err
}

func (repository *IdentityRolloutRepository) AdvanceIdentityBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (run ports.IdentityBackfillRun, err error) {
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || leaseToken.IsZero() || checkpoint.IsZero() || now.IsZero() || leaseDuration <= 0 {
		return run, fmt.Errorf("%w: identity backfill checkpoint is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		updated, updateErr := scanIdentityBackfillRun(tx.QueryRow(ctx, `UPDATE identity_backfill_runs AS run
			SET checkpoint_user_id=$5,updated_at=$6,lease_expires_at=now()+($7 * interval '1 microsecond'),
			processed_count=(SELECT count(*) FROM identity_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			projected_count=(SELECT count(*) FROM identity_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='projected'),
			unchanged_count=(SELECT count(*) FROM identity_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='unchanged'),
			drift_count=(SELECT count(*) FROM identity_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='drift')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>now()
			  AND run.checkpoint_user_id COLLATE "C" <= $5
			RETURNING `+identityBackfillRunCols,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), checkpoint.String(), now, leaseDuration.Microseconds()))
		if errors.Is(updateErr, pgx.ErrNoRows) {
			return fmt.Errorf("%w: identity backfill checkpoint rejected", shared.ErrConflict)
		}
		if updateErr != nil {
			return fmt.Errorf("advance identity backfill: %w", updateErr)
		}
		run = updated
		return nil
	})
	return run, err
}

func (repository *IdentityRolloutRepository) ReconcileIdentityBackfill(ctx context.Context, tenantID shared.ID, snapshotAt time.Time) (reconciliation ports.IdentityBackfillReconciliation, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || snapshotAt.IsZero() {
		return reconciliation, fmt.Errorf("%w: identity backfill reconciliation input is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `WITH source AS (
			SELECT u.* FROM users u WHERE u.ownership_tenant_id=$1 AND u.id<>'operator' AND u.created_at<=$2
		), duplicate_hashes AS (
			SELECT api_key_hash FROM source GROUP BY api_key_hash HAVING count(*)>1
		)
		SELECT
			count(*)::int,
			count(p.id)::int,
			count(m.id)::int,
			count(*) FILTER (WHERE p.id IS NULL OR p.display_name<>btrim(s.name) OR p.status<>'active' OR p.credential_epoch<>1 OR p.version<>1
				OR m.id IS NULL OR m.person_id<>s.id OR m.role<>s.role OR m.status<>CASE WHEN s.disabled THEN 'suspended' ELSE 'active' END OR m.epoch<>1 OR m.version<>1
				OR poi.person_id IS NULL)::int,
			count(*) FILTER (WHERE s.api_key_hash !~ '^[a-f0-9]{64}$')::int,
			(SELECT count(*)::int FROM duplicate_hashes),
			(SELECT count(*)::int FROM memberships bm WHERE bm.tenant_id=$1 AND (bm.id='operator' OR bm.person_id='operator'))
		FROM source s
		LEFT JOIN persons p ON p.id=s.id
		LEFT JOIN memberships m ON m.tenant_id=$1 AND m.id=s.id
		LEFT JOIN person_organization_index poi ON poi.person_id=s.id AND poi.tenant_id=$1`, tenantID.String(), snapshotAt.UTC()).Scan(
			&reconciliation.SourceCount, &reconciliation.PersonCount, &reconciliation.MembershipCount, &reconciliation.DriftCount,
			&reconciliation.CorruptCredentialCount, &reconciliation.DuplicateCredentialCount, &reconciliation.BootstrapMembershipCount)
	})
	if err != nil {
		return reconciliation, fmt.Errorf("reconcile identity backfill: %w", err)
	}
	return reconciliation, nil
}

func (repository *IdentityRolloutRepository) FinishIdentityBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state ports.IdentityBackfillState, reconciliation ports.IdentityBackfillReconciliation, now time.Time) (run ports.IdentityBackfillRun, err error) {
	if state != ports.IdentityBackfillCompleted && state != ports.IdentityBackfillCancelled && state != ports.IdentityBackfillFailed {
		return run, fmt.Errorf("%w: invalid identity backfill terminal state", shared.ErrValidation)
	}
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || leaseToken.IsZero() || now.IsZero() {
		return run, fmt.Errorf("%w: identity backfill completion identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		finished, finishErr := scanIdentityBackfillRun(tx.QueryRow(ctx, `UPDATE identity_backfill_runs AS run
			SET state=$5,lease_owner='',lease_token='',lease_expires_at=NULL,updated_at=$6,completed_at=$6,
			processed_count=(SELECT count(*) FROM identity_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			projected_count=(SELECT count(*) FROM identity_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='projected'),
			unchanged_count=(SELECT count(*) FROM identity_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='unchanged'),
			drift_count=GREATEST($7,(SELECT count(*) FROM identity_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='drift')),
			source_count=$8,person_count=$9,membership_count=$10
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>now()
			RETURNING `+identityBackfillRunCols,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), string(state), now,
			reconciliation.DriftCount, reconciliation.SourceCount, reconciliation.PersonCount, reconciliation.MembershipCount))
		if errors.Is(finishErr, pgx.ErrNoRows) {
			return fmt.Errorf("%w: identity backfill completion rejected", shared.ErrConflict)
		}
		if finishErr != nil {
			return fmt.Errorf("finish identity backfill: %w", finishErr)
		}
		run = finished
		return nil
	})
	return run, err
}

func (repository *IdentityRolloutRepository) AppendIdentityRolloutPhaseRecord(ctx context.Context, record ports.IdentityRolloutPhaseRecord) error {
	record.TenantID = shared.TenantOrDefault(record.TenantID)
	if record.TenantID.IsZero() || record.ID.IsZero() || strings.TrimSpace(record.Owner) == "" || strings.TrimSpace(record.RollbackAction) == "" || strings.TrimSpace(record.CreatedBy) == "" || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: identity rollout phase record is invalid", shared.ErrValidation)
	}
	return WithTenant(ctx, repository.pool, record.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity_rollout_phase_records
			(tenant_id,id,phase,owner,source_of_truth,allowed_writers,source_count,projected_count,drift_count,corrupt_credential_count,duplicate_credential_count,
			 denial_count,error_count,session_count,observation_minutes,abort_threshold_bps,last_known_good_phase,rollback_action,metrics_recorded,approval_recorded,created_by,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
			record.TenantID.String(), record.ID.String(), record.Phase, strings.TrimSpace(record.Owner), record.SourceOfTruth, record.AllowedWriters,
			record.SourceCount, record.ProjectedCount, record.DriftCount, record.CorruptCredentialCount, record.DuplicateCredentialCount,
			record.DenialCount, record.ErrorCount, record.SessionCount, record.ObservationMinutes, record.AbortThresholdBPS,
			record.LastKnownGoodPhase, strings.TrimSpace(record.RollbackAction), record.MetricsRecorded, record.ApprovalRecorded, strings.TrimSpace(record.CreatedBy), record.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("append identity rollout phase record: %w", err)
		}
		return nil
	})
}

func inspectBackfillPerson(ctx context.Context, tx pgx.Tx, id shared.ID, expectedName string) (exists, matches bool, err error) {
	var name, status string
	var epoch, version int64
	err = tx.QueryRow(ctx, `SELECT display_name,status,credential_epoch,version FROM persons WHERE id=$1 FOR UPDATE`, id.String()).Scan(&name, &status, &epoch, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("inspect identity backfill person: %w", err)
	}
	return true, name == expectedName && status == "active" && epoch == 1 && version == 1, nil
}

func inspectBackfillMembership(ctx context.Context, tx pgx.Tx, tenantID, id shared.ID, role user.Role, status string) (exists, matches bool, err error) {
	var personID, gotRole, gotStatus string
	var epoch, version int64
	err = tx.QueryRow(ctx, `SELECT person_id,role,status,epoch,version FROM memberships WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), id.String()).Scan(&personID, &gotRole, &gotStatus, &epoch, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("inspect identity backfill membership: %w", err)
	}
	return true, personID == id.String() && gotRole == string(role) && gotStatus == status && epoch == 1 && version == 1, nil
}

func inspectBackfillPersonIndex(ctx context.Context, tx pgx.Tx, tenantID, personID shared.ID) (bool, error) {
	var one int
	err := tx.QueryRow(ctx, `SELECT 1 FROM person_organization_index WHERE person_id=$1 AND tenant_id=$2`, personID.String(), tenantID.String()).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect identity person organization index: %w", err)
	}
	return true, nil
}

func sameLegacyHuman(left, right ports.LegacyHumanSnapshot) bool {
	return shared.TenantOrDefault(left.TenantID) == shared.TenantOrDefault(right.TenantID) && left.UserID == right.UserID && left.Name == right.Name && left.Role == right.Role && left.APIKeyHash == right.APIKeyHash && left.Disabled == right.Disabled && left.CreatedAt.Equal(right.CreatedAt) && left.UpdatedAt.Equal(right.UpdatedAt)
}

func validateIdentityBackfillAcquire(request ports.IdentityBackfillAcquireRequest) error {
	run := request.Run
	run.TenantID = shared.TenantOrDefault(run.TenantID)
	if run.TenantID.IsZero() || run.ID.IsZero() || run.SchemaVersion <= 0 || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.LeaseOwner != strings.TrimSpace(run.LeaseOwner) || run.LeaseOwner == "" || len(run.LeaseOwner) > 256 || run.LeaseToken.IsZero() || request.LeaseDuration <= 0 || strings.TrimSpace(run.CreatedBy) == "" || len(strings.TrimSpace(run.CreatedBy)) > 256 || run.CreatedAt.IsZero() {
		return fmt.Errorf("%w: identity backfill acquisition is invalid", shared.ErrValidation)
	}
	return nil
}

func scanIdentityBackfillRun(row rowScanner) (ports.IdentityBackfillRun, error) {
	var run ports.IdentityBackfillRun
	var state string
	var leaseExpires, completedAt pgtype.Timestamptz
	if err := row.Scan(&run.TenantID, &run.ID, &run.SchemaVersion, &run.BatchSize, &run.SnapshotAt, &run.CheckpointUser, &state, &run.LeaseOwner, &run.LeaseToken, &leaseExpires,
		&run.ProcessedCount, &run.ProjectedCount, &run.UnchangedCount, &run.DriftCount, &run.SourceCount, &run.PersonCount, &run.MembershipCount,
		&run.CreatedBy, &run.CreatedAt, &run.UpdatedAt, &completedAt); err != nil {
		return run, err
	}
	run.State = ports.IdentityBackfillState(state)
	if leaseExpires.Valid {
		run.LeaseExpiresAt = leaseExpires.Time
	}
	if completedAt.Valid {
		completed := completedAt.Time
		run.CompletedAt = &completed
	}
	return run, nil
}

func scanIdentityBackfillItem(row rowScanner, item *ports.IdentityBackfillItem) error {
	return row.Scan(&item.TenantID, &item.RunID, &item.UserID, &item.PersonID, &item.MembershipID, &item.SourceHash, &item.Outcome, &item.ReasonCode, &item.ProcessedAt)
}
