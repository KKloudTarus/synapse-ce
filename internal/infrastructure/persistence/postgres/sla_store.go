package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SLAStore is the PostgreSQL adapter for versioned SLA policy, immutable assessments, and the
// human remediation lifecycle. Every operation is routed through WithTenant so RLS remains the
// final isolation boundary even when an application-level predicate regresses.
type SLAStore struct{ pool *pgxpool.Pool }

func NewSLAStore(pool *pgxpool.Pool) *SLAStore { return &SLAStore{pool: pool} }

var _ ports.SLAStore = (*SLAStore)(nil)

func (s *SLAStore) PutPolicy(ctx context.Context, policy sla.Policy, activate bool) (bool, error) {
	tenantID, err := slaPostgresTenant(ctx, policy.TenantID)
	if err != nil {
		return false, err
	}
	policy.TenantID = tenantID
	if err := policy.Validate(); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(policy.Config)
	if err != nil {
		return false, fmt.Errorf("marshal sla policy: %w", err)
	}
	created := false
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO sla_policies
			(tenant_id,config_version,config,sha256,created_by,created_at)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,config_version) DO NOTHING`,
			tenantID.String(), policy.Config.Version, encoded, policy.SHA256, policy.CreatedBy, policy.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert sla policy: %w", err)
		}
		created = tag.RowsAffected() == 1
		if !created {
			var storedHash string
			if err := tx.QueryRow(ctx, `SELECT sha256 FROM sla_policies WHERE tenant_id=$1 AND config_version=$2`,
				tenantID.String(), policy.Config.Version).Scan(&storedHash); err != nil {
				return fmt.Errorf("load existing sla policy: %w", err)
			}
			if storedHash != policy.SHA256 {
				return fmt.Errorf("%w: sla policy version already has different content", shared.ErrConflict)
			}
		}
		if activate {
			if _, err := tx.Exec(ctx, `INSERT INTO sla_active_policies (tenant_id,config_version,activated_at)
				VALUES ($1,$2,$3) ON CONFLICT (tenant_id) DO UPDATE
				SET config_version=EXCLUDED.config_version,activated_at=EXCLUDED.activated_at`,
				tenantID.String(), policy.Config.Version, policy.CreatedAt); err != nil {
				return fmt.Errorf("activate sla policy: %w", err)
			}
		}
		return nil
	})
	return created, err
}

func (s *SLAStore) ActivePolicy(ctx context.Context, tenantID shared.ID) (sla.Policy, error) {
	tenantID, err := slaPostgresTenant(ctx, tenantID)
	if err != nil {
		return sla.Policy{}, err
	}
	var policy sla.Policy
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		return scanSLAPolicy(tx.QueryRow(ctx, `SELECT p.tenant_id,p.config,p.sha256,p.created_by,p.created_at
			FROM sla_active_policies active JOIN sla_policies p
			ON p.tenant_id=active.tenant_id AND p.config_version=active.config_version
			WHERE active.tenant_id=$1`, tenantID.String()), &policy)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return sla.Policy{}, shared.ErrNotFound
	}
	if err != nil {
		return sla.Policy{}, fmt.Errorf("load active sla policy: %w", err)
	}
	return policy, nil
}

func (s *SLAStore) PolicyHistory(ctx context.Context, tenantID shared.ID) ([]sla.Policy, error) {
	tenantID, err := slaPostgresTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items := make([]sla.Policy, 0)
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,config,sha256,created_by,created_at FROM sla_policies
			WHERE tenant_id=$1 ORDER BY created_at DESC,config_version DESC`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list sla policies: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var policy sla.Policy
			if err := scanSLAPolicy(rows, &policy); err != nil {
				return err
			}
			items = append(items, policy)
		}
		return rows.Err()
	})
	return items, err
}

func (s *SLAStore) UpsertAssessment(ctx context.Context, assessment sla.Assessment) (sla.AssessmentUpsertResult, error) {
	tenantID, err := slaPostgresTenant(ctx, assessment.TenantID)
	if err != nil {
		return sla.AssessmentUpsertResult{}, err
	}
	assessment.TenantID = tenantID
	if err := assessment.Validate(); err != nil {
		return sla.AssessmentUpsertResult{}, err
	}
	result := sla.AssessmentUpsertResult{Assessment: assessment}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		// Serialize every candidate for one finding, including its first assessment. A row lock
		// cannot protect the absent-pointer case, so use a transaction advisory lock on the stable
		// tenant/engagement/finding identity.
		lockKey := slaFindingAdvisoryLockKey(tenantID, assessment.EngagementID, assessment.FindingID)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
			return fmt.Errorf("lock sla finding: %w", err)
		}
		var existing sla.Assessment
		found, err := loadSLAAssessment(ctx, tx, tenantID, assessment.ID, &existing)
		if err != nil {
			return err
		}
		if found {
			result.Assessment = existing
			return nil
		}
		var previousID string
		err = tx.QueryRow(ctx, `SELECT assessment_id FROM sla_current_assessments
			WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3`, tenantID.String(),
			assessment.EngagementID.String(), assessment.FindingID.String()).Scan(&previousID)
		if errors.Is(err, pgx.ErrNoRows) {
			assessment.PreviousAssessmentID = ""
		} else if err != nil {
			return fmt.Errorf("load current sla assessment pointer: %w", err)
		} else {
			var previous sla.Assessment
			found, err := loadSLAAssessment(ctx, tx, tenantID, shared.ID(previousID), &previous)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("load current sla assessment: %w", shared.ErrNotFound)
			}
			assessment, err = sla.ContinueAssessment(assessment, previous)
			if err != nil {
				return err
			}
		}
		if err := insertSLAAssessment(ctx, tx, assessment); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sla_current_assessments
			(tenant_id,engagement_id,finding_id,assessment_id,updated_at) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id,engagement_id,finding_id) DO UPDATE
			SET assessment_id=EXCLUDED.assessment_id,updated_at=EXCLUDED.updated_at`, tenantID.String(),
			assessment.EngagementID.String(), assessment.FindingID.String(), assessment.ID.String(), assessment.AssessedAt); err != nil {
			return fmt.Errorf("update current sla assessment pointer: %w", err)
		}
		// ON CONFLICT changes only machine-owned provenance. It cannot clobber status, acceptance,
		// attribution, timestamps, reason, or optimistic version.
		if _, err := tx.Exec(ctx, `INSERT INTO sla_lifecycles
			(tenant_id,engagement_id,finding_id,assessment_id,status,version,updated_by,updated_at)
			VALUES ($1,$2,$3,$4,'open',1,'system:sla',$5)
			ON CONFLICT (tenant_id,engagement_id,finding_id) DO UPDATE SET assessment_id=EXCLUDED.assessment_id`,
			tenantID.String(), assessment.EngagementID.String(), assessment.FindingID.String(),
			assessment.ID.String(), assessment.AssessedAt); err != nil {
			return fmt.Errorf("initialize sla lifecycle: %w", err)
		}
		result.Assessment, result.Created = assessment, true
		return nil
	})
	if err != nil {
		return sla.AssessmentUpsertResult{}, err
	}
	return result, nil
}

func (s *SLAStore) Current(ctx context.Context, tenantID, engagementID, findingID shared.ID) (sla.Current, error) {
	tenantID, err := slaPostgresTenant(ctx, tenantID)
	if err != nil {
		return sla.Current{}, err
	}
	var current sla.Current
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, currentSLAQuery+` WHERE pointer.tenant_id=$1 AND pointer.engagement_id=$2 AND pointer.finding_id=$3`,
			tenantID.String(), engagementID.String(), findingID.String())
		return scanSLACurrent(row, &current)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return sla.Current{}, shared.ErrNotFound
	}
	if err != nil {
		return sla.Current{}, fmt.Errorf("load current sla: %w", err)
	}
	return current, nil
}

func (s *SLAStore) ListCurrent(ctx context.Context, tenantID, engagementID shared.ID) ([]sla.Current, error) {
	tenantID, err := slaPostgresTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items := make([]sla.Current, 0)
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, currentSLAQuery+` WHERE pointer.tenant_id=$1 AND pointer.engagement_id=$2
			ORDER BY assessment.remediate_by,assessment.finding_id`, tenantID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list current sla: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item sla.Current
			if err := scanSLACurrent(rows, &item); err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

func (s *SLAStore) AssessmentHistory(ctx context.Context, tenantID, engagementID, findingID shared.ID) ([]sla.Assessment, error) {
	tenantID, err := slaPostgresTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items := make([]sla.Assessment, 0)
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+slaAssessmentColumns+` FROM sla_assessments
			WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3 ORDER BY assessed_at DESC,id DESC`,
			tenantID.String(), engagementID.String(), findingID.String())
		if err != nil {
			return fmt.Errorf("list sla assessment history: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item sla.Assessment
			if err := scanSLAAssessment(rows, &item); err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

func (s *SLAStore) SaveTransition(ctx context.Context, next sla.Lifecycle, event sla.LifecycleEvent) error {
	tenantID, err := slaPostgresTenant(ctx, next.TenantID)
	if err != nil {
		return err
	}
	next.TenantID, event.TenantID = tenantID, tenantID
	if err := next.Validate(); err != nil {
		return err
	}
	if err := validatePostgresSLAEvent(next, event); err != nil {
		return err
	}
	return WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE sla_lifecycles SET
			status=$1,version=$2,reason=$3,compensating_control=$4,accepted_by=$5,accepted_at=$6,
			acceptance_expires_at=$7,updated_by=$8,updated_at=$9
			WHERE tenant_id=$10 AND engagement_id=$11 AND finding_id=$12 AND assessment_id=$13 AND version=$14`,
			string(next.Status), next.Version, next.Reason, next.CompensatingControl, next.AcceptedBy,
			next.AcceptedAt, next.AcceptanceExpiresAt, next.UpdatedBy, next.UpdatedAt, tenantID.String(),
			next.EngagementID.String(), next.FindingID.String(), next.AssessmentID.String(), event.BeforeVersion)
		if err != nil {
			return fmt.Errorf("update sla lifecycle: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("sla lifecycle changed: %w", shared.ErrConflict)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sla_lifecycle_events
			(tenant_id,id,engagement_id,finding_id,assessment_id,from_status,to_status,reason,
			compensating_control,acceptance_expires_at,actor,before_version,after_version,occurred_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, tenantID.String(), event.ID.String(),
			event.EngagementID.String(), event.FindingID.String(), event.AssessmentID.String(), string(event.From),
			string(event.To), event.Reason, event.CompensatingControl, event.AcceptanceExpiresAt, event.Actor,
			event.BeforeVersion, event.AfterVersion, event.At); err != nil {
			return wrapPostgresSLAWriteError("insert sla lifecycle event", err)
		}
		return nil
	})
}

func (s *SLAStore) LifecycleEvents(ctx context.Context, tenantID, engagementID, findingID shared.ID) ([]sla.LifecycleEvent, error) {
	tenantID, err := slaPostgresTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items := make([]sla.LifecycleEvent, 0)
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,id,engagement_id,finding_id,assessment_id,from_status,to_status,
			reason,compensating_control,acceptance_expires_at,actor,before_version,after_version,occurred_at
			FROM sla_lifecycle_events WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3
			ORDER BY occurred_at,id`, tenantID.String(), engagementID.String(), findingID.String())
		if err != nil {
			return fmt.Errorf("list sla lifecycle events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item sla.LifecycleEvent
			if err := rows.Scan(&item.TenantID, &item.ID, &item.EngagementID, &item.FindingID, &item.AssessmentID,
				&item.From, &item.To, &item.Reason, &item.CompensatingControl, &item.AcceptanceExpiresAt,
				&item.Actor, &item.BeforeVersion, &item.AfterVersion, &item.At); err != nil {
				return fmt.Errorf("scan sla lifecycle event: %w", err)
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

const slaAssessmentColumns = `tenant_id,id,engagement_id,finding_id,source_risk_assessment_id,inputs,result,
	input_hash,config_hash,previous_assessment_id,deadline_anchor_at,assessed_at,created_at`

const slaLifecycleColumns = `lifecycle.tenant_id,lifecycle.engagement_id,lifecycle.finding_id,lifecycle.assessment_id,
	lifecycle.status,lifecycle.version,lifecycle.reason,lifecycle.compensating_control,lifecycle.accepted_by,
	lifecycle.accepted_at,lifecycle.acceptance_expires_at,lifecycle.updated_by,lifecycle.updated_at`

const currentSLAQuery = `SELECT ` + slaAssessmentPrefixedColumns + `,` + slaLifecycleColumns + `
	FROM sla_current_assessments pointer
	JOIN sla_assessments assessment ON assessment.tenant_id=pointer.tenant_id AND assessment.id=pointer.assessment_id
	JOIN sla_lifecycles lifecycle ON lifecycle.tenant_id=pointer.tenant_id
		AND lifecycle.engagement_id=pointer.engagement_id AND lifecycle.finding_id=pointer.finding_id
		AND lifecycle.assessment_id=pointer.assessment_id`

const slaAssessmentPrefixedColumns = `assessment.tenant_id,assessment.id,assessment.engagement_id,
	assessment.finding_id,assessment.source_risk_assessment_id,assessment.inputs,assessment.result,
	assessment.input_hash,assessment.config_hash,assessment.previous_assessment_id,assessment.deadline_anchor_at,
	assessment.assessed_at,assessment.created_at`

func slaPostgresTenant(ctx context.Context, requested shared.ID) (shared.ID, error) {
	bound, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	bound, requested = shared.TenantOrDefault(bound), shared.TenantOrDefault(requested)
	if bound != requested {
		return "", fmt.Errorf("%w: sla tenant does not match context", shared.ErrValidation)
	}
	return bound, nil
}

func scanSLAPolicy(row interface{ Scan(...any) error }, policy *sla.Policy) error {
	var encoded []byte
	if err := row.Scan(&policy.TenantID, &encoded, &policy.SHA256, &policy.CreatedBy, &policy.CreatedAt); err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, &policy.Config); err != nil {
		return fmt.Errorf("decode sla policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("validate stored sla policy: %w", err)
	}
	return nil
}

func loadSLAAssessment(ctx context.Context, tx pgx.Tx, tenantID, id shared.ID, item *sla.Assessment) (bool, error) {
	err := scanSLAAssessment(tx.QueryRow(ctx, `SELECT `+slaAssessmentColumns+` FROM sla_assessments WHERE tenant_id=$1 AND id=$2`,
		tenantID.String(), id.String()), item)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func scanSLAAssessment(row interface{ Scan(...any) error }, item *sla.Assessment) error {
	var inputJSON, resultJSON []byte
	var sourceID, previousID pgtype.Text
	if err := row.Scan(&item.TenantID, &item.ID, &item.EngagementID, &item.FindingID,
		&sourceID, &inputJSON, &resultJSON, &item.InputHash, &item.ConfigHash,
		&previousID, &item.DeadlineAnchorAt, &item.AssessedAt, &item.CreatedAt); err != nil {
		return err
	}
	item.SourceRiskAssessmentID, item.PreviousAssessmentID = "", ""
	if sourceID.Valid {
		item.SourceRiskAssessmentID = shared.ID(sourceID.String)
	}
	if previousID.Valid {
		item.PreviousAssessmentID = shared.ID(previousID.String)
	}
	if err := json.Unmarshal(inputJSON, &item.Inputs); err != nil {
		return fmt.Errorf("decode sla assessment inputs: %w", err)
	}
	if err := json.Unmarshal(resultJSON, &item.Result); err != nil {
		return fmt.Errorf("decode sla assessment result: %w", err)
	}
	if err := item.Validate(); err != nil {
		return fmt.Errorf("validate stored sla assessment: %w", err)
	}
	return nil
}

func scanSLALifecycle(row interface{ Scan(...any) error }, item *sla.Lifecycle) error {
	if err := row.Scan(&item.TenantID, &item.EngagementID, &item.FindingID, &item.AssessmentID,
		&item.Status, &item.Version, &item.Reason, &item.CompensatingControl, &item.AcceptedBy,
		&item.AcceptedAt, &item.AcceptanceExpiresAt, &item.UpdatedBy, &item.UpdatedAt); err != nil {
		return err
	}
	if err := item.Validate(); err != nil {
		return fmt.Errorf("validate stored sla lifecycle: %w", err)
	}
	return nil
}

func scanSLACurrent(row interface{ Scan(...any) error }, item *sla.Current) error {
	var inputJSON, resultJSON []byte
	var sourceID, previousID pgtype.Text
	if err := row.Scan(&item.Assessment.TenantID, &item.Assessment.ID, &item.Assessment.EngagementID,
		&item.Assessment.FindingID, &sourceID, &inputJSON, &resultJSON,
		&item.Assessment.InputHash, &item.Assessment.ConfigHash, &previousID,
		&item.Assessment.DeadlineAnchorAt, &item.Assessment.AssessedAt, &item.Assessment.CreatedAt,
		&item.Lifecycle.TenantID,
		&item.Lifecycle.EngagementID, &item.Lifecycle.FindingID, &item.Lifecycle.AssessmentID,
		&item.Lifecycle.Status, &item.Lifecycle.Version, &item.Lifecycle.Reason,
		&item.Lifecycle.CompensatingControl, &item.Lifecycle.AcceptedBy, &item.Lifecycle.AcceptedAt,
		&item.Lifecycle.AcceptanceExpiresAt, &item.Lifecycle.UpdatedBy, &item.Lifecycle.UpdatedAt); err != nil {
		return err
	}
	item.Assessment.SourceRiskAssessmentID, item.Assessment.PreviousAssessmentID = "", ""
	if sourceID.Valid {
		item.Assessment.SourceRiskAssessmentID = shared.ID(sourceID.String)
	}
	if previousID.Valid {
		item.Assessment.PreviousAssessmentID = shared.ID(previousID.String)
	}
	if err := json.Unmarshal(inputJSON, &item.Assessment.Inputs); err != nil {
		return fmt.Errorf("decode sla current inputs: %w", err)
	}
	if err := json.Unmarshal(resultJSON, &item.Assessment.Result); err != nil {
		return fmt.Errorf("decode sla current result: %w", err)
	}
	if _, err := item.View(item.Assessment.AssessedAt); err != nil {
		return fmt.Errorf("validate stored sla current: %w", err)
	}
	return nil
}

func insertSLAAssessment(ctx context.Context, tx pgx.Tx, item sla.Assessment) error {
	inputs, err := json.Marshal(item.Inputs)
	if err != nil {
		return fmt.Errorf("marshal sla assessment inputs: %w", err)
	}
	result, err := json.Marshal(item.Result)
	if err != nil {
		return fmt.Errorf("marshal sla assessment result: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO sla_assessments
		(tenant_id,id,engagement_id,finding_id,source_risk_assessment_id,inputs,result,input_hash,
		config_hash,config_version,tier,score,mitigate_by,remediate_by,previous_assessment_id,
		deadline_anchor_at,assessed_at,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, item.TenantID.String(),
		item.ID.String(), item.EngagementID.String(), item.FindingID.String(), nullableSLAID(item.SourceRiskAssessmentID),
		inputs, result, item.InputHash, item.ConfigHash, item.Result.ConfigVersion, string(item.Result.Tier), item.Result.Score,
		item.Result.MitigateBy, item.Result.RemediateBy, nullableSLAID(item.PreviousAssessmentID), item.DeadlineAnchorAt,
		item.AssessedAt, item.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert sla assessment: %w", err)
	}
	return nil
}

func validatePostgresSLAEvent(next sla.Lifecycle, event sla.LifecycleEvent) error {
	if event.ID.IsZero() || event.TenantID != next.TenantID || event.EngagementID != next.EngagementID ||
		event.FindingID != next.FindingID || event.AssessmentID != next.AssessmentID || event.To != next.Status ||
		event.AfterVersion != next.Version || event.BeforeVersion+1 != event.AfterVersion || event.At.IsZero() {
		return fmt.Errorf("%w: sla lifecycle event does not match next state", shared.ErrValidation)
	}
	return nil
}

func nullableSLAID(value shared.ID) any {
	if value.IsZero() {
		return nil
	}
	return value.String()
}

func slaFindingAdvisoryLockKey(tenantID, engagementID, findingID shared.ID) int64 {
	digest := sha256.Sum256([]byte(tenantID.String() + "\x00" + engagementID.String() + "\x00" + findingID.String()))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func postgresUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func wrapPostgresSLAWriteError(operation string, err error) error {
	if postgresUniqueViolation(err) {
		return fmt.Errorf("%s: %w: %w", operation, err, shared.ErrConflict)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
