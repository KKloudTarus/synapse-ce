package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func cutoverState(ctx context.Context, tx pgx.Tx, tenant shared.ID) (ports.IdentityCutoverState, error) {
	var phase string
	var version int
	var declared, contracted bool
	err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT cutover_phase FROM identity_policies WHERE tenant_id=$1),'legacy'), COALESCE((SELECT version FROM identity_policies WHERE tenant_id=$1),0), EXISTS(SELECT 1 FROM identity_cutover_ledger WHERE tenant_id=$1 AND action='declared'), EXISTS(SELECT 1 FROM identity_cutover_ledger WHERE tenant_id=$1 AND action='contracted')`, tenant.String()).Scan(&phase, &version, &declared, &contracted)
	if err != nil {
		return ports.IdentityCutoverState{}, err
	}
	if contracted {
		phase = string(ports.IdentityCutoverContracted)
	}
	return ports.IdentityCutoverState{TenantID: tenant, Phase: ports.IdentityCutoverPhase(phase), PolicyVersion: version, Declared: declared, Contracted: contracted}, nil
}
func (s *IdentityFoundationStore) CutoverState(ctx context.Context, tenant shared.ID) (out ports.IdentityCutoverState, err error) {
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error { out, err = cutoverState(ctx, tx, tenant); return err })
	return out, err
}
func (s *IdentityFoundationStore) RecordCutoverWriterHeartbeat(ctx context.Context, tenant shared.ID, generation, instanceID string, at time.Time) error {
	if generation == "" || instanceID == "" || at.IsZero() {
		return fmt.Errorf("%w: writer generation, instance and time are required", shared.ErrValidation)
	}
	return s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity_cutover_writer_heartbeats(tenant_id,generation,instance_id,seen_at)
			VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,instance_id) DO UPDATE SET generation=EXCLUDED.generation,seen_at=EXCLUDED.seen_at`, tenant.String(), generation, instanceID, at)
		return err
	})
}
func cutoverAudit(ctx context.Context, tx pgx.Tx, tenant shared.ID, action, actor string, now time.Time, evidence ports.IdentityCutoverEvidence) error {
	if evidence.MigrationVersion == 0 {
		var err error
		evidence.MigrationVersion, err = EmbeddedMigrationCeiling()
		if err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO identity_cutover_ledger(tenant_id,action,actor,policy_version,shadow_report_id,old_writer_generation,old_writer_count,migration_version,created_at) VALUES($1,$2,$3,(SELECT version FROM identity_policies WHERE tenant_id=$1),NULLIF($4,''),NULLIF($5,''),$6,$7,$8)`, tenant.String(), action, actor, evidence.ShadowReportID.String(), evidence.OldWriterGeneration, evidence.OldWriterCount, evidence.MigrationVersion, now)
	return err
}
func lockCutoverPolicy(ctx context.Context, tx pgx.Tx, tenant shared.ID) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM identity_policies WHERE tenant_id=$1 FOR UPDATE`, tenant.String()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return shared.ErrNotFound
	}
	return err
}
func (s *IdentityFoundationStore) PrepareCutover(ctx context.Context, tenant shared.ID, version int, actor string, now time.Time) (out ports.IdentityCutoverState, err error) {
	if actor == "" || version < 0 {
		return out, fmt.Errorf("%w: actor and expected version required", shared.ErrValidation)
	}
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		st, e := cutoverState(ctx, tx, tenant)
		if e != nil {
			return e
		}
		if st.Declared || st.Phase != ports.IdentityCutoverLegacy || st.PolicyVersion != version {
			return fmt.Errorf("%w: prepare requires current legacy policy", ports.ErrIdentityCutover)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO identity_policies(tenant_id,id,cutover_phase,updated_at) VALUES($1,'identity','shadow',$2) ON CONFLICT(tenant_id) DO UPDATE SET cutover_phase='shadow',updated_at=EXCLUDED.updated_at WHERE identity_policies.version=$3`, tenant.String(), now, version); e != nil {
			return e
		}
		if e = cutoverAudit(ctx, tx, tenant, "prepared", actor, now, ports.IdentityCutoverEvidence{}); e != nil {
			return e
		}
		out, e = cutoverState(ctx, tx, tenant)
		return e
	})
	return out, err
}
func (s *IdentityFoundationStore) CanaryCutover(ctx context.Context, tenant shared.ID) (out ports.IdentityShadowReport, err error) {
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		st, e := cutoverState(ctx, tx, tenant)
		if e != nil {
			return e
		}
		if st.Phase != ports.IdentityCutoverShadow {
			return fmt.Errorf("%w: canary requires shadow", ports.ErrIdentityCutover)
		}
		e = tx.QueryRow(ctx, `SELECT id,legacy_users,bootstrap_skipped,memberships,missing_memberships,credentials_expected,credentials_matched,authenticators_expected,authenticators_matched,authenticator_mismatches,digest_mismatches,routing_mismatches,role_drift,state_drift,placeholders,ambiguous,drift_total,aborted,ready,rollback_prepared FROM identity_shadow_reports WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, tenant.String()).Scan(&out.ID, &out.LegacyUsers, &out.BootstrapSkipped, &out.Memberships, &out.MissingMemberships, &out.CredentialsExpected, &out.CredentialsMatched, &out.AuthenticatorsExpected, &out.AuthenticatorsMatched, &out.AuthenticatorMismatches, &out.DigestMismatches, &out.RoutingMismatches, &out.RoleDrift, &out.StateDrift, &out.Placeholders, &out.Ambiguous, &out.DriftTotal, &out.Aborted, &out.Ready, &out.RollbackPrepared)
		out.TenantID = tenant
		if errors.Is(e, pgx.ErrNoRows) {
			return fmt.Errorf("%w: no shadow report", ports.ErrIdentityCutover)
		}
		return e
	})
	return out, err
}
func (s *IdentityFoundationStore) DeclareCutover(ctx context.Context, tenant shared.ID, version int, ev ports.IdentityCutoverEvidence, actor string, now time.Time) (out ports.IdentityCutoverState, err error) {
	versions, versionErr := embeddedMigrationVersions()
	if versionErr != nil {
		return out, versionErr
	}
	latest := versions[len(versions)-1]
	if actor == "" || version < 1 || ev.ShadowReportID.IsZero() || ev.OldWriterGeneration == "" || ev.OldWriterCount != 0 || int64(ev.MigrationVersion) < latest {
		return out, fmt.Errorf("%w: complete clean evidence is required", shared.ErrValidation)
	}
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if e := lockCutoverPolicy(ctx, tx, tenant); e != nil {
			return e
		}
		if e := checkMigrationsReady(ctx, tx); e != nil {
			return fmt.Errorf("verify cutover migration readiness: %w", e)
		}
		st, e := cutoverState(ctx, tx, tenant)
		if e != nil {
			return e
		}
		if st.Declared || st.Phase != ports.IdentityCutoverShadow || st.PolicyVersion != version {
			return fmt.Errorf("%w: declaration policy drift", ports.ErrIdentityCutover)
		}
		var ready, rollback bool
		var created time.Time
		e = tx.QueryRow(ctx, `SELECT ready,rollback_prepared,created_at FROM identity_shadow_reports WHERE tenant_id=$1 AND id=$2`, tenant.String(), ev.ShadowReportID.String()).Scan(&ready, &rollback, &created)
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return fmt.Errorf("%w: shadow evidence is missing", ports.ErrIdentityCutover)
			}
			return e
		}
		if !ready || !rollback || created.After(now) || now.Sub(created) >= 24*time.Hour {
			return fmt.Errorf("%w: shadow evidence is stale or unclean", ports.ErrIdentityCutover)
		}
		var current, old int
		e = tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE generation=$2), count(*) FILTER (WHERE generation<>$2)
			FROM identity_cutover_writer_heartbeats WHERE tenant_id=$1 AND seen_at>$3`, tenant.String(), ev.OldWriterGeneration, now.Add(-5*time.Minute)).Scan(&current, &old)
		if e != nil {
			return e
		}
		if current == 0 || old != 0 {
			return fmt.Errorf("%w: writer heartbeats are missing or an old writer remains", ports.ErrIdentityCutover)
		}
		if e = cutoverAudit(ctx, tx, tenant, "declared", actor, now, ev); e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE identity_policies SET cutover_phase='declared',updated_at=$2 WHERE tenant_id=$1 AND version=$3`, tenant.String(), now, version)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: declaration version changed", ports.ErrIdentityCutover)
		}
		out, e = cutoverState(ctx, tx, tenant)
		return e
	})
	return out, err
}
func (s *IdentityFoundationStore) ContractCutover(ctx context.Context, tenant shared.ID, version int, actor string, now time.Time) (out ports.IdentityCutoverState, err error) {
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if e := lockCutoverPolicy(ctx, tx, tenant); e != nil {
			return e
		}
		st, e := cutoverState(ctx, tx, tenant)
		if e != nil {
			return e
		}
		if !st.Declared || st.Contracted || st.PolicyVersion != version {
			return fmt.Errorf("%w: contract requires declared current policy", ports.ErrIdentityCutover)
		}
		if e = cutoverAudit(ctx, tx, tenant, "contracted", actor, now, ports.IdentityCutoverEvidence{}); e != nil {
			return e
		}
		out, e = cutoverState(ctx, tx, tenant)
		return e
	})
	return out, err
}
func (s *IdentityFoundationStore) AbortCutover(ctx context.Context, tenant shared.ID, version int, actor string, now time.Time) (out ports.IdentityCutoverState, err error) {
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if e := lockCutoverPolicy(ctx, tx, tenant); e != nil {
			return e
		}
		st, e := cutoverState(ctx, tx, tenant)
		if e != nil {
			return e
		}
		if st.Declared || st.Phase != ports.IdentityCutoverShadow || st.PolicyVersion != version {
			return fmt.Errorf("%w: abort is refused after declaration or version drift", ports.ErrIdentityCutover)
		}
		tag, e := tx.Exec(ctx, `UPDATE identity_policies SET cutover_phase='legacy',updated_at=$2 WHERE tenant_id=$1 AND version=$3`, tenant.String(), now, version)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: abort version changed", ports.ErrIdentityCutover)
		}
		if e = cutoverAudit(ctx, tx, tenant, "aborted", actor, now, ports.IdentityCutoverEvidence{}); e != nil {
			return e
		}
		out, e = cutoverState(ctx, tx, tenant)
		return e
	})
	return out, err
}
