package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.DocumentScheduleStore = (*DocumentStore)(nil)

const documentScheduleCols = `id,tenant_id,source_kind,source_ref,COALESCE(engagement_id,''),COALESCE(project_id,''),destination,COALESCE(integration_id,''),COALESCE(email_channel_id,''),owner_user_id,COALESCE(owner_membership_id,''),COALESCE(owner_person_id,''),timezone,frequency,weekday,day_of_month,hour,minute,enabled,version,next_due_at,checked_at,check_version,created_at,updated_at`

func scanDocumentSchedule(row rowScanner) (docpublish.Schedule, error) {
	var s docpublish.Schedule
	var e, p string
	err := row.Scan(&s.ID, &s.TenantID, &s.Source.SourceKind, &s.Source.SourceRef, &e, &p, &s.Destination, &s.IntegrationID, &s.EmailChannelID, &s.OwnerUserID, &s.OwnerMembershipID, &s.OwnerPersonID, &s.Timezone, &s.Frequency, &s.Weekday, &s.Day, &s.Hour, &s.Minute, &s.Enabled, &s.Version, &s.NextDueAt, &s.CheckedAt, &s.CheckVersion, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return s, err
	}
	s.Source.Scope, s.Source.ScopeID = documentScopeOf(e, p)
	s.NextDueAt = s.NextDueAt.UTC()
	s.CreatedAt = s.CreatedAt.UTC()
	s.UpdatedAt = s.UpdatedAt.UTC()
	if s.CheckedAt != nil {
		v := s.CheckedAt.UTC()
		s.CheckedAt = &v
	}
	return s, nil
}
func scheduleArgs(s docpublish.Schedule) (eng, proj any) {
	return documentScopeArgs(docpublish.Target{Scope: s.Source.Scope, ScopeID: s.Source.ScopeID})
}

func (s *DocumentStore) SaveDocumentSchedule(ctx context.Context, tenant shared.ID, in docpublish.Schedule, expected int) (docpublish.Schedule, error) {
	if tenant.IsZero() || in.TenantID != tenant || expected < 0 || in.Validate() != nil {
		return docpublish.Schedule{}, shared.ErrValidation
	}
	var out docpublish.Schedule
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		eng, proj := scheduleArgs(in)
		if expected == 0 {
			var e error
			out, e = scanDocumentSchedule(tx.QueryRow(ctx, `INSERT INTO document_schedules(tenant_id,id,source_kind,source_ref,engagement_id,project_id,destination,integration_id,email_channel_id,owner_user_id,owner_membership_id,owner_person_id,timezone,frequency,weekday,day_of_month,hour,minute,enabled,version,next_due_at,checked_at,check_version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),NULLIF($9,''),$10,NULLIF($11,''),NULLIF($12,''),$13,$14,$15,$16,$17,$18,$19,1,$20,NULL,0,$21,$21) RETURNING `+documentScheduleCols, tenant.String(), in.ID.String(), string(in.Source.SourceKind), in.Source.SourceRef, eng, proj, string(in.Destination), in.IntegrationID.String(), in.EmailChannelID.String(), in.OwnerUserID.String(), in.OwnerMembershipID.String(), in.OwnerPersonID.String(), in.Timezone, string(in.Frequency), in.Weekday, in.Day, in.Hour, in.Minute, in.Enabled, in.NextDueAt.UTC(), in.UpdatedAt.UTC()))
			return e
		}
		var e error
		out, e = scanDocumentSchedule(tx.QueryRow(ctx, `UPDATE document_schedules SET timezone=$4,frequency=$5,weekday=$6,day_of_month=$7,hour=$8,minute=$9,enabled=$10,next_due_at=$11,owner_user_id=$12,owner_membership_id=NULLIF($13,''),owner_person_id=NULLIF($14,''),updated_at=$15,version=version+1 WHERE tenant_id=$1 AND id=$2 AND version=$3 RETURNING `+documentScheduleCols, tenant.String(), in.ID.String(), expected, in.Timezone, string(in.Frequency), in.Weekday, in.Day, in.Hour, in.Minute, in.Enabled, in.NextDueAt.UTC(), in.OwnerUserID.String(), in.OwnerMembershipID.String(), in.OwnerPersonID.String(), in.UpdatedAt.UTC()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return docpublish.Schedule{}, shared.ErrConflict
	}
	if err != nil {
		return docpublish.Schedule{}, documentWriteError(err)
	}
	return out, nil
}
func (s *DocumentStore) GetDocumentSchedule(ctx context.Context, tenant, id shared.ID) (docpublish.Schedule, error) {
	var out docpublish.Schedule
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		out, e = scanDocumentSchedule(tx.QueryRow(ctx, `SELECT `+documentScheduleCols+` FROM document_schedules WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, shared.ErrNotFound
	}
	return out, err
}
func (s *DocumentStore) ListDocumentSchedules(ctx context.Context, tenant shared.ID, scope docpublish.Scope, scopeID shared.ID, limit int) ([]docpublish.Schedule, error) {
	if tenant.IsZero() || scopeID.IsZero() || limit < 1 || limit > docpublish.MaxListLimit {
		return nil, shared.ErrValidation
	}
	out := []docpublish.Schedule{}
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		column := "project_id"
		if scope == docpublish.Engagement {
			column = "engagement_id"
		}
		rows, e := tx.Query(ctx, `SELECT `+documentScheduleCols+` FROM document_schedules WHERE tenant_id=$1 AND `+column+`=$2 ORDER BY id LIMIT $3`, tenant.String(), scopeID.String(), limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			v, e := scanDocumentSchedule(rows)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}
func (s *DocumentStore) DeleteDocumentSchedule(ctx context.Context, tenant, id shared.ID, expected int, at time.Time) error {
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE document_schedules SET enabled=false,version=version+1,updated_at=$4 WHERE tenant_id=$1 AND id=$2 AND version=$3`, tenant.String(), id.String(), expected, at.UTC())
		if e == nil && tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return shared.ErrConflict
	}
	return err
}

func pgScheduleOccurrenceID(id shared.ID, due time.Time) shared.ID {
	h := sha256.Sum256([]byte(id.String() + "\x00" + due.UTC().Format(time.RFC3339Nano)))
	return shared.ID("schedule:" + hex.EncodeToString(h[:16]))
}
func scanScheduleOccurrence(row rowScanner) (ports.DocumentScheduleOccurrence, error) {
	var out ports.DocumentScheduleOccurrence
	var raw []byte
	var artifactStored bool
	err := row.Scan(&out.Occurrence.ID, &out.Occurrence.TenantID, &out.Occurrence.ScheduleID, &out.Occurrence.DueAt, &out.Occurrence.ScheduleVersion, &out.Occurrence.State, &out.Occurrence.Version, &out.Occurrence.LeaseUntil, &raw, &out.Occurrence.ArtifactDigest, &out.Occurrence.DocumentIntentID, &out.Occurrence.RemotePageID, &out.Occurrence.RemoteVersion, &out.Occurrence.CreatedAt, &out.Occurrence.UpdatedAt)
	if err != nil {
		return out, err
	}
	artifactStored = string(raw) != "null"
	out.ArtifactStored = artifactStored
	if artifactStored {
		if e := json.Unmarshal(raw, &out.Artifact); e != nil {
			return out, e
		}
	}
	return out, nil
}
func (s *DocumentStore) ClaimDueDocumentScheduleOccurrences(ctx context.Context, tenant shared.ID, limit int, at time.Time) ([]ports.DocumentScheduleWork, error) {
	if tenant.IsZero() || limit < 1 || limit > 20 {
		return nil, shared.ErrValidation
	}
	out := []ports.DocumentScheduleWork{}
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		// Keep both durable recovery and newly due work in the same bounded queue.
		// A failed occurrence receives a new updated_at when it is checkpointed, so it
		// naturally yields to an older fresh due time on the following tick. Uncertain
		// occurrences are intentionally absent: a lost SMTP acknowledgement is never
		// retransmitted automatically.
		rows, e := tx.Query(ctx, `WITH recovery_candidates AS (
			SELECT o.id AS candidate_id,o.updated_at AS ready_at,1 AS candidate_kind
			FROM document_schedule_occurrences o
			JOIN document_schedules s ON s.tenant_id=o.tenant_id AND s.id=o.schedule_id
			WHERE o.tenant_id=$1 AND s.enabled AND s.version=o.schedule_version
				AND o.state IN ('pending','failed','in_flight')
				AND (o.state IN ('pending','failed') OR (o.state='in_flight' AND o.lease_until<=$2))
			ORDER BY o.updated_at,o.id FOR UPDATE OF o SKIP LOCKED LIMIT $3
		), fresh_candidates AS (
			SELECT s.id AS candidate_id,s.next_due_at AS ready_at,0 AS candidate_kind
			FROM document_schedules s
			WHERE s.tenant_id=$1 AND s.enabled AND s.next_due_at<=$2
			ORDER BY s.next_due_at,s.id FOR UPDATE OF s SKIP LOCKED LIMIT $3
		), candidates AS (
			SELECT candidate_id,ready_at,candidate_kind FROM recovery_candidates
			UNION ALL
			SELECT candidate_id,ready_at,candidate_kind FROM fresh_candidates
		)
		SELECT candidate_id,candidate_kind
		FROM candidates
		ORDER BY ready_at,candidate_kind,candidate_id
		LIMIT $3`, tenant.String(), at.UTC(), limit)
		if e != nil {
			return e
		}
		type candidate struct {
			id   shared.ID
			kind int
		}
		var candidates []candidate
		for rows.Next() {
			var candidate candidate
			var id string
			if e := rows.Scan(&id, &candidate.kind); e != nil {
				rows.Close()
				return e
			}
			candidate.id = shared.ID(id)
			candidates = append(candidates, candidate)
		}
		if e := rows.Err(); e != nil {
			rows.Close()
			return e
		}
		rows.Close()

		for _, candidate := range candidates {
			if candidate.kind == 1 {
				occurrence, e := scanScheduleOccurrence(tx.QueryRow(ctx, `UPDATE document_schedule_occurrences SET state='in_flight',lease_until=$3,version=version+1,updated_at=$2 WHERE tenant_id=$1 AND id=$4 RETURNING id,tenant_id,schedule_id,due_at,schedule_version,state,version,lease_until,artifact,artifact_digest,document_intent_id,remote_page_id,remote_version,created_at,updated_at`, tenant.String(), at.UTC(), at.UTC().Add(5*time.Minute), candidate.id.String()))
				if e != nil {
					return e
				}
				schedule, e := scanDocumentSchedule(tx.QueryRow(ctx, `SELECT `+documentScheduleCols+` FROM document_schedules WHERE tenant_id=$1 AND id=$2`, tenant.String(), occurrence.Occurrence.ScheduleID.String()))
				if e != nil {
					return e
				}
				out = append(out, ports.DocumentScheduleWork{Schedule: schedule, Occurrence: occurrence})
				continue
			}
			schedule, e := scanDocumentSchedule(tx.QueryRow(ctx, `SELECT `+documentScheduleCols+` FROM document_schedules WHERE tenant_id=$1 AND id=$2`, tenant.String(), candidate.id.String()))
			if e != nil {
				return e
			}
			due := schedule.NextDueAt.UTC()
			oid := pgScheduleOccurrenceID(schedule.ID, due)
			next, e := schedule.NextDueAfter(at)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `UPDATE document_schedules SET next_due_at=$3,checked_at=$4,check_version=check_version+1 WHERE tenant_id=$1 AND id=$2 AND version=$5`, tenant.String(), schedule.ID.String(), next, at.UTC(), schedule.Version)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO document_schedule_occurrences(tenant_id,id,schedule_id,due_at,schedule_version,state,version,artifact,artifact_digest,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'pending',1,'null'::jsonb,'',$6,$6) ON CONFLICT(tenant_id,schedule_id,due_at) DO NOTHING`, tenant.String(), oid.String(), schedule.ID.String(), due, schedule.Version, at.UTC())
			if e != nil {
				return e
			}
			var occurrence ports.DocumentScheduleOccurrence
			occurrence, e = scanScheduleOccurrence(tx.QueryRow(ctx, `SELECT id,tenant_id,schedule_id,due_at,schedule_version,state,version,lease_until,artifact,artifact_digest,document_intent_id,remote_page_id,remote_version,created_at,updated_at FROM document_schedule_occurrences WHERE tenant_id=$1 AND schedule_id=$2 AND due_at=$3`, tenant.String(), schedule.ID.String(), due))
			if e != nil {
				return e
			}
			lease := at.UTC().Add(5 * time.Minute)
			occurrence, e = scanScheduleOccurrence(tx.QueryRow(ctx, `UPDATE document_schedule_occurrences SET state='in_flight',lease_until=$3,version=version+1,updated_at=$2 WHERE tenant_id=$1 AND id=$4 AND version=$5 RETURNING id,tenant_id,schedule_id,due_at,schedule_version,state,version,lease_until,artifact,artifact_digest,document_intent_id,remote_page_id,remote_version,created_at,updated_at`, tenant.String(), at.UTC(), lease, oid.String(), occurrence.Occurrence.Version))
			if e != nil {
				return e
			}
			schedule.NextDueAt = next
			check := at.UTC()
			schedule.CheckedAt = &check
			schedule.CheckVersion++
			out = append(out, ports.DocumentScheduleWork{Schedule: schedule, Occurrence: occurrence})
		}
		return nil
	})
	return out, err
}
func (s *DocumentStore) GetDocumentScheduleOccurrence(ctx context.Context, tenant, id shared.ID) (ports.DocumentScheduleOccurrence, error) {
	var out ports.DocumentScheduleOccurrence
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		out, e = scanScheduleOccurrence(tx.QueryRow(ctx, `SELECT id,tenant_id,schedule_id,due_at,schedule_version,state,version,lease_until,artifact,artifact_digest,document_intent_id,remote_page_id,remote_version,created_at,updated_at FROM document_schedule_occurrences WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, shared.ErrNotFound
	}
	return out, err
}
func (s *DocumentStore) SaveDocumentScheduleOccurrence(ctx context.Context, tenant shared.ID, in ports.DocumentScheduleOccurrence, expected int, at time.Time) (ports.DocumentScheduleOccurrence, error) {
	raw := []byte("null")
	if in.ArtifactStored {
		var e error
		raw, e = json.Marshal(in.Artifact)
		if e != nil || len(raw) > 32<<20 {
			return ports.DocumentScheduleOccurrence{}, shared.ErrValidation
		}
	}
	if len(raw) > 32<<20 {
		return ports.DocumentScheduleOccurrence{}, shared.ErrValidation
	}
	var out ports.DocumentScheduleOccurrence
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		out, e = scanScheduleOccurrence(tx.QueryRow(ctx, `UPDATE document_schedule_occurrences SET state=$4,lease_until=$5,artifact=CASE WHEN $6 THEN $7::jsonb ELSE artifact END,artifact_digest=CASE WHEN $6 THEN $8 ELSE artifact_digest END,document_intent_id=$9,remote_page_id=$10,remote_version=$11,version=version+1,updated_at=$12 WHERE tenant_id=$1 AND id=$2 AND version=$3 AND (artifact='null'::jsonb OR NOT $6 OR (artifact=$7::jsonb AND artifact_digest=$8)) RETURNING id,tenant_id,schedule_id,due_at,schedule_version,state,version,lease_until,artifact,artifact_digest,document_intent_id,remote_page_id,remote_version,created_at,updated_at`, tenant.String(), in.Occurrence.ID.String(), expected, string(in.Occurrence.State), in.Occurrence.LeaseUntil, in.ArtifactStored, raw, in.Occurrence.ArtifactDigest, in.Occurrence.DocumentIntentID.String(), in.Occurrence.RemotePageID, in.Occurrence.RemoteVersion, at.UTC()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, shared.ErrConflict
	}
	return out, err
}
func (s *DocumentStore) GetDocumentScheduleDelivery(ctx context.Context, tenant, occurrenceID shared.ID, recipientHash string) (ports.DocumentScheduleDelivery, error) {
	var out ports.DocumentScheduleDelivery
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		out, e = scanScheduleDelivery(tx.QueryRow(ctx, `SELECT id,tenant_id,occurrence_id,recipient,recipient_hash,message_id,state,version,lease_until,error_code,created_at,updated_at FROM document_schedule_deliveries WHERE tenant_id=$1 AND occurrence_id=$2 AND recipient_hash=$3`, tenant.String(), occurrenceID.String(), recipientHash))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, shared.ErrNotFound
	}
	return out, err
}
func scanScheduleDelivery(row rowScanner) (ports.DocumentScheduleDelivery, error) {
	var out ports.DocumentScheduleDelivery
	err := row.Scan(&out.ID, &out.TenantID, &out.OccurrenceID, &out.Recipient, &out.RecipientHash, &out.MessageID, &out.State, &out.Version, &out.LeaseUntil, &out.ErrorCode, &out.CreatedAt, &out.UpdatedAt)
	if err == nil {
		out.CreatedAt = out.CreatedAt.UTC()
		out.UpdatedAt = out.UpdatedAt.UTC()
		if out.LeaseUntil != nil {
			v := out.LeaseUntil.UTC()
			out.LeaseUntil = &v
		}
	}
	return out, err
}
func (s *DocumentStore) SaveDocumentScheduleDelivery(ctx context.Context, tenant shared.ID, in ports.DocumentScheduleDelivery, expected int, at time.Time) (ports.DocumentScheduleDelivery, error) {
	if tenant.IsZero() || in.TenantID != tenant || in.ID.IsZero() || in.OccurrenceID.IsZero() || in.RecipientHash == "" || in.MessageID.IsZero() || expected < 0 {
		return ports.DocumentScheduleDelivery{}, shared.ErrValidation
	}
	var out ports.DocumentScheduleDelivery
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		if expected == 0 {
			var e error
			out, e = scanScheduleDelivery(tx.QueryRow(ctx, `INSERT INTO document_schedule_deliveries(tenant_id,id,occurrence_id,recipient,recipient_hash,message_id,state,version,lease_until,error_code,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$10) RETURNING id,tenant_id,occurrence_id,recipient,recipient_hash,message_id,state,version,lease_until,error_code,created_at,updated_at`, tenant.String(), in.ID.String(), in.OccurrenceID.String(), in.Recipient, in.RecipientHash, in.MessageID.String(), string(in.State), in.LeaseUntil, in.ErrorCode, at.UTC()))
			return e
		}
		var e error
		out, e = scanScheduleDelivery(tx.QueryRow(ctx, `UPDATE document_schedule_deliveries SET state=$4,lease_until=$5,error_code=$6,version=version+1,updated_at=$7 WHERE tenant_id=$1 AND id=$2 AND version=$3 RETURNING id,tenant_id,occurrence_id,recipient,recipient_hash,message_id,state,version,lease_until,error_code,created_at,updated_at`, tenant.String(), in.ID.String(), expected, string(in.State), in.LeaseUntil, in.ErrorCode, at.UTC()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, shared.ErrConflict
	}
	if err != nil {
		return out, documentWriteError(err)
	}
	return out, nil
}
