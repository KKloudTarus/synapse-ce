package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TicketStore is the durable ticketing adapter; it does not use integration_operations,
// integration_bindings, the CI scheduler or a notification delivery.
type TicketStore struct{ pool *pgxpool.Pool }

func NewTicketStore(pool *pgxpool.Pool) (*TicketStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: ticket store requires a PostgreSQL pool", shared.ErrValidation)
	}
	return &TicketStore{pool: pool}, nil
}

var _ ports.TicketStore = (*TicketStore)(nil)
var _ ports.TicketAuditStore = (*TicketStore)(nil)
var _ ports.TicketIntentAuditStore = (*TicketStore)(nil)
var _ ports.TicketDispatchStore = (*TicketStore)(nil)
var _ ports.TicketAutoPushStore = (*TicketStore)(nil)
var _ ports.TicketGroupStore = (*TicketStore)(nil)
var _ ports.TicketStatusStore = (*TicketStore)(nil)
var _ ports.TicketStatusProgressStore = (*TicketStore)(nil)

const ticketStatusProgressCols = `tenant_id,mapping_id,engagement_id,finding_id,desired_state,applied_state,source_revision,COALESCE(transition_intent_id,''),COALESCE(update_intent_id,''),integration_author,version,episode,checked_at`

func scanTicketStatusProgress(row rowScanner) (out ports.TicketStatusProgress, err error) {
	err = row.Scan(&out.TenantID, &out.MappingID, &out.EngagementID, &out.FindingID, &out.DesiredState, &out.AppliedState,
		&out.SourceRevision, &out.TransitionIntentID, &out.UpdateIntentID, &out.IntegrationAuthor, &out.Version, &out.Episode, &out.CheckedAt)
	return out, err
}

func (s *TicketStore) GetTicketStatusProgress(ctx context.Context, tenant, mappingID, engagementID, findingID shared.ID) (out ports.TicketStatusProgress, err error) {
	if tenant.IsZero() || mappingID.IsZero() || engagementID.IsZero() || findingID.IsZero() {
		return out, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		item, e := scanTicketStatusProgress(tx.QueryRow(ctx, `SELECT `+ticketStatusProgressCols+` FROM ticket_status_sync WHERE tenant_id=$1 AND mapping_id=$2 AND engagement_id=$3 AND finding_id=$4`, tenant.String(), mappingID.String(), engagementID.String(), findingID.String()))
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		out = item
		return e
	})
	return out, ticketWriteError(err)
}

func (s *TicketStore) CreateTicketStatusProgress(ctx context.Context, tenant shared.ID, item ports.TicketStatusProgress) (out ports.TicketStatusProgress, created bool, err error) {
	if tenant.IsZero() || item.TenantID != tenant || item.MappingID.IsZero() || item.EngagementID.IsZero() || item.FindingID.IsZero() || !item.DesiredState.Valid() || item.SourceRevision == "" || item.CheckedAt.IsZero() {
		return out, false, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO ticket_status_sync (tenant_id,mapping_id,engagement_id,finding_id,desired_state,applied_state,source_revision,transition_intent_id,update_intent_id,integration_author,version,episode,checked_at,created_at,updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),NULLIF($9,''),$10,1,1,$11,$11,$11)
			ON CONFLICT (tenant_id,mapping_id,finding_id,engagement_id) DO NOTHING RETURNING `+ticketStatusProgressCols,
			tenant.String(), item.MappingID.String(), item.EngagementID.String(), item.FindingID.String(), string(item.DesiredState), string(item.AppliedState), item.SourceRevision, item.TransitionIntentID.String(), item.UpdateIntentID.String(), item.IntegrationAuthor, item.CheckedAt)
		fresh, e := scanTicketStatusProgress(row)
		if e == nil {
			out, created = fresh, true
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		out, e = s.GetTicketStatusProgress(ctx, tenant, item.MappingID, item.EngagementID, item.FindingID)
		return e
	})
	return out, created, ticketWriteError(err)
}

func (s *TicketStore) UpdateTicketStatusProgress(ctx context.Context, tenant shared.ID, item ports.TicketStatusProgress, expected int) (out ports.TicketStatusProgress, err error) {
	if tenant.IsZero() || item.TenantID != tenant || item.MappingID.IsZero() || item.EngagementID.IsZero() || item.FindingID.IsZero() || !item.DesiredState.Valid() || item.SourceRevision == "" || item.CheckedAt.IsZero() || item.Episode < 1 || expected < 1 {
		return out, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `UPDATE ticket_status_sync SET desired_state=$5,applied_state=$6,source_revision=$7,transition_intent_id=NULLIF($8,''),update_intent_id=NULLIF($9,''),integration_author=$10,episode=$11,checked_at=$12,updated_at=$12,version=version+1
			WHERE tenant_id=$1 AND mapping_id=$2 AND engagement_id=$3 AND finding_id=$4 AND version=$13 RETURNING `+ticketStatusProgressCols,
			tenant.String(), item.MappingID.String(), item.EngagementID.String(), item.FindingID.String(), string(item.DesiredState), string(item.AppliedState), item.SourceRevision, item.TransitionIntentID.String(), item.UpdateIntentID.String(), item.IntegrationAuthor, item.Episode, item.CheckedAt, expected)
		out, err = scanTicketStatusProgress(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrConflict
		}
		return err
	})
	return out, ticketWriteError(err)
}

func (s *TicketStore) ListTicketStatusTargets(ctx context.Context, tenant shared.ID, limit int) (out []ports.TicketStatusTarget, err error) {
	if tenant.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT i.id,i.mapping_id FROM ticket_intents i JOIN ticket_mappings m ON m.tenant_id=i.tenant_id AND m.id=i.mapping_id
			LEFT JOIN ticket_status_sync s ON s.tenant_id=i.tenant_id AND s.mapping_id=i.mapping_id AND s.engagement_id=i.engagement_id AND s.finding_id=i.finding_id
			WHERE i.tenant_id=$1 AND i.state='done' AND i.action='create' AND i.remote_id<>'' AND m.status_transitions<>'{}'::jsonb
			ORDER BY s.checked_at NULLS FIRST,s.version NULLS FIRST,i.id LIMIT $2`, tenant.String(), limit)
		if e != nil {
			return e
		}
		var refs []ticketTargetRef
		for rows.Next() {
			var intentID, mappingID shared.ID
			if e := rows.Scan(&intentID, &mappingID); e != nil {
				return e
			}
			refs = append(refs, ticketTargetRef{intentID, mappingID})
		}
		if e := rows.Err(); e != nil {
			return e
		}
		rows.Close()
		for _, ref := range refs {
			target, e := loadTicketStatusTarget(ctx, tx, tenant, ref.intentID, ref.mappingID)
			if e != nil {
				return e
			}
			out = append(out, target)
		}
		return nil
	})
	return out, ticketWriteError(err)
}

func ticketGroupFromRow(row rowScanner) (ports.TicketGroup, error) {
	var group ports.TicketGroup
	err := row.Scan(&group.ID, &group.TenantID, &group.MappingID, &group.ProjectID, &group.Vulnerability,
		&group.IntegrationID, &group.Endpoint, &group.ProjectKey, &group.IssueType, &group.SecurityLevel,
		&group.IntentID, &group.Remote.ID, &group.Remote.URL, &group.CreatedAt, &group.UpdatedAt, &group.Revision)
	return group, err
}

const ticketGroupCols = `id,tenant_id,mapping_id,project_id,vulnerability_id,integration_id,endpoint,project_key,issue_type,security_level,intent_id,remote_id,remote_url,created_at,updated_at,revision`

func sameTicketGroupDestination(a, b ports.TicketGroup) bool {
	return a.IntegrationID == b.IntegrationID && a.Endpoint == b.Endpoint && a.ProjectKey == b.ProjectKey &&
		a.IssueType == b.IssueType && a.SecurityLevel == b.SecurityLevel
}

func (s *TicketStore) ValidateTicketGroupDestination(ctx context.Context, tenant shared.ID, candidate ports.TicketGroup) error {
	if tenant.IsZero() || candidate.TenantID != tenant || candidate.MappingID.IsZero() {
		return shared.ErrValidation
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		existing, err := ticketGroupFromRow(tx.QueryRow(ctx, `SELECT `+ticketGroupCols+` FROM ticket_groups WHERE tenant_id=$1 AND mapping_id=$2 LIMIT 1`, tenant.String(), candidate.MappingID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !sameTicketGroupDestination(existing, candidate) {
			return shared.ErrConflict
		}
		return nil
	}))
}

func (s *TicketStore) GetTicketGroup(ctx context.Context, tenant, mappingID, projectID shared.ID, vulnerability string) (group ports.TicketGroup, found bool, err error) {
	if tenant.IsZero() || mappingID.IsZero() || projectID.IsZero() || vulnerability == "" {
		return group, false, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		group, e = ticketGroupFromRow(tx.QueryRow(ctx, `SELECT `+ticketGroupCols+` FROM ticket_groups WHERE tenant_id=$1 AND mapping_id=$2 AND project_id=$3 AND vulnerability_id=$4`, tenant.String(), mappingID.String(), projectID.String(), vulnerability))
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if group.Remote.ID == "" && !group.IntentID.IsZero() {
			previous, e := scanTicketIntent(tx.QueryRow(ctx, `SELECT `+intentCols+` FROM ticket_intents WHERE tenant_id=$1 AND id=$2`, tenant.String(), group.IntentID.String()))
			if e != nil {
				return e
			}
			if previous.State == writeintent.Done {
				group.Remote = ticketing.RemoteTicket{ID: previous.RemoteID, URL: previous.RemoteURL}
			}
		}
		found = true
		return nil
	})
	return group, found, ticketWriteError(err)
}

func (s *TicketStore) CreateOrGetGroupedIntent(ctx context.Context, tenant shared.ID, group ports.TicketGroup, member ports.TicketGroupMember, intent ticketing.Intent, audit ports.AuditEntry) (out ticketing.Intent, created bool, err error) {
	if tenant.IsZero() || group.TenantID != tenant || group.ID.IsZero() || group.MappingID != intent.MappingID || group.ProjectID.IsZero() || group.Vulnerability == "" || group.IntegrationID != intent.IntegrationID || group.Endpoint == "" || group.ProjectKey == "" || group.IssueType == "" || member.EngagementID != intent.EngagementID || member.FindingID != intent.FindingID || (intent.Action != ticketing.Create && intent.Action != ticketing.Update) || group.Revision < 0 {
		return out, false, shared.ErrValidation
	}
	if err = intent.Validate(); err != nil {
		return out, false, err
	}
	err = NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		tx, e := ticketTx(txctx, tenant)
		if e != nil {
			return e
		}
		if old, found, e := s.FindTicketRequest(txctx, tenant, intent.MappingID, intent.EngagementID, intent.FindingID, intent.RequestKey); e != nil {
			return e
		} else if found {
			if !sameTicketCommand(old, intent) {
				return shared.ErrConflict
			}
			out = old
			return nil
		}
		_, e = tx.Exec(txctx, `INSERT INTO ticket_groups(tenant_id,id,mapping_id,project_id,vulnerability_id,integration_id,endpoint,project_key,issue_type,security_level,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11) ON CONFLICT(tenant_id,mapping_id,project_id,vulnerability_id) DO NOTHING`, tenant.String(), group.ID.String(), group.MappingID.String(), group.ProjectID.String(), group.Vulnerability, group.IntegrationID.String(), group.Endpoint, group.ProjectKey, group.IssueType, group.SecurityLevel, group.CreatedAt.UTC())
		if e != nil {
			return e
		}
		persisted, e := ticketGroupFromRow(tx.QueryRow(txctx, `SELECT `+ticketGroupCols+` FROM ticket_groups WHERE tenant_id=$1 AND mapping_id=$2 AND project_id=$3 AND vulnerability_id=$4 FOR UPDATE`, tenant.String(), group.MappingID.String(), group.ProjectID.String(), group.Vulnerability))
		if e != nil {
			return e
		}
		if !sameTicketGroupDestination(persisted, group) {
			return shared.ErrConflict
		}
		if persisted.Revision != group.Revision {
			return fmt.Errorf("%w: %w", shared.ErrConflict, ticketing.ErrGroupBusy)
		}
		if !persisted.IntentID.IsZero() {
			previous, e := s.GetIntent(txctx, tenant, persisted.IntentID)
			if e != nil {
				return e
			}
			if previous.State != writeintent.Done && previous.State != writeintent.Failed {
				return fmt.Errorf("%w: %w", shared.ErrConflict, ticketing.ErrGroupBusy)
			}
			if persisted.Remote.ID == "" && previous.State == writeintent.Done {
				persisted.Remote = ticketing.RemoteTicket{ID: previous.RemoteID, URL: previous.RemoteURL}
			}
			if (persisted.Remote.ID != "" && intent.Action != ticketing.Update) || (persisted.Remote.ID == "" && intent.Action != ticketing.Create) {
				return fmt.Errorf("%w: %w", shared.ErrConflict, ticketing.ErrGroupBusy)
			}
		} else if intent.Action != ticketing.Create {
			return shared.ErrConflict
		}
		out, created, e = s.CreateOrGetIntent(txctx, tenant, intent)
		if e != nil {
			return e
		}
		if !created {
			return shared.ErrConflict
		}
		if _, e = tx.Exec(txctx, `INSERT INTO ticket_group_members(tenant_id,group_id,engagement_id,finding_id,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, tenant.String(), persisted.ID.String(), member.EngagementID.String(), member.FindingID.String(), group.UpdatedAt.UTC()); e != nil {
			return e
		}
		if _, e = tx.Exec(txctx, `UPDATE ticket_groups SET intent_id=$3,remote_id=$4,remote_url=$5,revision=revision+1,updated_at=$6 WHERE tenant_id=$1 AND id=$2`, tenant.String(), persisted.ID.String(), out.ID.String(), persisted.Remote.ID, persisted.Remote.URL, group.UpdatedAt.UTC()); e != nil {
			return e
		}
		return NewAuditLog(s.pool).Record(txctx, audit)
	})
	return out, created, ticketWriteError(err)
}

func (s *TicketStore) CompleteGroupedIntent(ctx context.Context, tenant, intentID shared.ID, remote ticketing.RemoteTicket, at time.Time) error {
	if tenant.IsZero() || intentID.IsZero() || at.IsZero() {
		return shared.ErrValidation
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ticket_groups SET remote_id=$3,remote_url=$4,updated_at=$5 WHERE tenant_id=$1 AND intent_id=$2`, tenant.String(), intentID.String(), remote.ID, remote.URL, at.UTC())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrNotFound
		}
		return nil
	}))
}

func (s *TicketStore) ListAutoPushEvents(ctx context.Context, tenant shared.ID, now time.Time, limit int) (out []ports.TicketAutoPushEvent, err error) {
	if tenant.IsZero() || limit < 1 || limit > 100 {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT event_id,occurred_at,engagement_id,finding_id,to_status
			FROM ticket_auto_push_receipts
			WHERE tenant_id=$1 AND completed_at IS NULL AND available_at<=$2
			ORDER BY available_at,event_id LIMIT $3`, tenant.String(), now.UTC(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var event ports.TicketAutoPushEvent
			if err := rows.Scan(&event.ID, &event.OccurredAt, &event.EngagementID, &event.FindingID, &event.ToStatus); err != nil {
				return err
			}
			out = append(out, event)
		}
		return rows.Err()
	})
	return out, ticketWriteError(err)
}

func (s *TicketStore) CompleteAutoPushEvent(ctx context.Context, tenant shared.ID, event ports.TicketAutoPushEvent, at time.Time) error {
	if tenant.IsZero() || event.ID.IsZero() || event.OccurredAt.IsZero() || at.IsZero() {
		return shared.ErrValidation
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ticket_auto_push_receipts SET completed_at=$3,updated_at=$3
			WHERE tenant_id=$1 AND event_id=$2`, tenant.String(), event.ID.String(), at.UTC())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrNotFound
		}
		return nil
	}))
}

func (s *TicketStore) DeferAutoPushEvent(ctx context.Context, tenant shared.ID, event ports.TicketAutoPushEvent, retryAt time.Time) error {
	if tenant.IsZero() || event.ID.IsZero() || event.OccurredAt.IsZero() || retryAt.IsZero() {
		return shared.ErrValidation
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ticket_auto_push_receipts SET available_at=$3,updated_at=$3
			WHERE tenant_id=$1 AND event_id=$2 AND completed_at IS NULL`, tenant.String(), event.ID.String(), retryAt.UTC())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrNotFound
		}
		return nil
	}))
}

func ticketWriteError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "23505" {
			return shared.ErrConflict
		}
		if pgErr.Code == "23503" {
			return shared.ErrNotFound
		}
	}
	return err
}
func nullableJSON(v []byte) any {
	if len(v) == 0 {
		return nil
	}
	return string(v)
}
func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

const mappingCols = `id,tenant_id,integration_id,COALESCE(project_id,''),COALESCE(engagement_id,''),
    project_key,issue_type,component,labels,priority_map,security_level,summary_template,description_template,field_values,transition_name,data_class,locale,waiver_reason,auto_push_enabled,auto_push_min_severity,auto_push_enabled_at,grouping_mode,status_transitions,version,created_at,updated_at`

func scanTicketMapping(row rowScanner) (ticketing.Mapping, error) {
	var m ticketing.Mapping
	var project, engagement string
	var labels, priorities, fields, statusTransitions []byte
	err := row.Scan(&m.ID, &m.TenantID, &m.IntegrationID, &project, &engagement,
		&m.ProjectKey, &m.IssueType, &m.Component, &labels, &priorities, &m.SecurityLevel, &m.SummaryTemplate, &m.DescriptionTemplate, &fields, &m.Transition, &m.DataClass, &m.Locale, &m.WaiverReason, &m.AutoPushEnabled, &m.AutoPushMinSeverity, &m.AutoPushEnabledAt, &m.GroupingMode, &statusTransitions,
		&m.Version, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return ticketing.Mapping{}, err
	}
	if project != "" {
		m.Scope = ticketing.Project
		m.ScopeID = shared.ID(project)
	} else {
		m.Scope = ticketing.Engagement
		m.ScopeID = shared.ID(engagement)
	}
	if err = json.Unmarshal(labels, &m.Labels); err != nil {
		return ticketing.Mapping{}, err
	}
	if err = json.Unmarshal(priorities, &m.PriorityMap); err != nil {
		return ticketing.Mapping{}, err
	}
	if err = json.Unmarshal(fields, &m.FieldValues); err != nil {
		return ticketing.Mapping{}, err
	}
	if err = json.Unmarshal(statusTransitions, &m.StatusTransitions); err != nil {
		return ticketing.Mapping{}, err
	}
	return m, nil
}
func (s *TicketStore) CreateMapping(ctx context.Context, tenant shared.ID, m ticketing.Mapping) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.GroupingMode == "" {
		m.GroupingMode = ticketing.GroupingFinding
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if tenant.IsZero() || tenant != m.TenantID {
		return shared.ErrValidation
	}
	var project, engagement any
	if m.Scope == ticketing.Project {
		project = m.ScopeID.String()
	} else {
		engagement = m.ScopeID.String()
	}
	if m.Labels == nil {
		m.Labels = []string{}
	}
	if m.PriorityMap == nil {
		m.PriorityMap = map[string]string{}
	}
	if m.FieldValues == nil {
		m.FieldValues = map[string]string{}
	}
	if m.StatusTransitions == nil {
		m.StatusTransitions = map[ticketing.SyncState]string{}
	}
	if m.DataClass == "" {
		m.DataClass = "summary"
	}
	if m.Locale == "" {
		m.Locale = "en"
	}
	if m.StatusTransitions == nil {
		m.StatusTransitions = map[ticketing.SyncState]string{}
	}
	labels, err := json.Marshal(m.Labels)
	if err != nil {
		return shared.ErrValidation
	}
	priorities, err := json.Marshal(m.PriorityMap)
	if err != nil {
		return shared.ErrValidation
	}
	fields, err := json.Marshal(m.FieldValues)
	if err != nil {
		return shared.ErrValidation
	}
	statusTransitions, err := json.Marshal(m.StatusTransitions)
	if err != nil {
		return shared.ErrValidation
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ticket_mappings
            (id,tenant_id,integration_id,project_id,engagement_id,project_key,issue_type,
			 component,labels,priority_map,security_level,summary_template,description_template,field_values,transition_name,data_class,locale,waiver_reason,auto_push_enabled,auto_push_min_severity,auto_push_enabled_at,grouping_mode,status_transitions,version,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13,$14::jsonb,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb,$24,$25,$26)`,
			m.ID.String(), tenant.String(), m.IntegrationID.String(), project, engagement, m.ProjectKey,
			m.IssueType, m.Component, string(labels), string(priorities), m.SecurityLevel, m.SummaryTemplate, m.DescriptionTemplate, string(fields), m.Transition, string(m.DataClass), m.Locale, m.WaiverReason, m.AutoPushEnabled, string(m.AutoPushMinSeverity), m.AutoPushEnabledAt, string(m.GroupingMode), string(statusTransitions), m.Version,
			m.CreatedAt.UTC(), m.UpdatedAt.UTC())
		return err
	}))
}
func (s *TicketStore) CreateMappingAudited(ctx context.Context, tenant shared.ID, m ticketing.Mapping, audit ports.AuditEntry) error {
	return NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		if err := s.CreateMapping(txctx, tenant, m); err != nil {
			return err
		}
		return NewAuditLog(s.pool).Record(txctx, audit)
	})
}
func (s *TicketStore) GetMapping(ctx context.Context, tenant, id shared.ID) (ticketing.Mapping, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Mapping{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return ticketing.Mapping{}, shared.ErrValidation
	}
	var m ticketing.Mapping
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		m, e = scanTicketMapping(tx.QueryRow(ctx, `SELECT `+mappingCols+` FROM ticket_mappings WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ticketing.Mapping{}, shared.ErrNotFound
	}
	if err != nil {
		return ticketing.Mapping{}, fmt.Errorf("get ticket mapping: %w", err)
	}
	return m, nil
}
func (s *TicketStore) ListMappings(ctx context.Context, tenant shared.ID, limit int, after shared.ID) (out []ticketing.Mapping, err error) {
	if tenant.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+mappingCols+` FROM ticket_mappings WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, tenant.String(), after.String(), limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			m, e := scanTicketMapping(rows)
			if e != nil {
				return e
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, ticketWriteError(err)
}
func (s *TicketStore) ListScopedMappings(ctx context.Context, tenant shared.ID, scope ticketing.Scope, scopeID shared.ID, limit int) (out []ticketing.Mapping, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	if scope == "" {
		if !scopeID.IsZero() {
			return nil, shared.ErrValidation
		}
		return s.ListMappings(ctx, tenant, limit, "")
	}
	if scopeID.IsZero() || (scope != ticketing.Project && scope != ticketing.Engagement) {
		return nil, shared.ErrValidation
	}
	column := "engagement_id"
	if scope == ticketing.Project {
		column = "project_id"
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+mappingCols+` FROM ticket_mappings WHERE tenant_id=$1 AND `+column+`=$2 ORDER BY id LIMIT $3`, tenant.String(), scopeID.String(), limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			m, scanErr := scanTicketMapping(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, ticketWriteError(err)
}
func (s *TicketStore) ListFindingMappings(ctx context.Context, tenant, engagementID shared.ID, limit int) (out []ticketing.Mapping, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || engagementID.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var projectID string
		if e := tx.QueryRow(ctx, `SELECT COALESCE(project_id,'') FROM engagements WHERE tenant_id=$1 AND id=$2`, tenant.String(), engagementID.String()).Scan(&projectID); errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT `+mappingCols+` FROM ticket_mappings m
			WHERE m.tenant_id=$1 AND (m.engagement_id=$2 OR ($3<>'' AND m.project_id=$3))
			ORDER BY m.id LIMIT $4`, tenant.String(), engagementID.String(), projectID, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			m, scanErr := scanTicketMapping(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, ticketWriteError(err)
}
func (s *TicketStore) UpdateMapping(ctx context.Context, tenant shared.ID, m ticketing.Mapping, expected int) (out ticketing.Mapping, err error) {
	if m.GroupingMode == "" {
		m.GroupingMode = ticketing.GroupingFinding
	}
	if err = m.Validate(); err != nil {
		return out, err
	}
	if tenant.IsZero() || m.TenantID != tenant || expected < 1 {
		return out, shared.ErrValidation
	}
	if m.DataClass == "" {
		m.DataClass = "summary"
	}
	if m.Locale == "" {
		m.Locale = "en"
	}
	labels, _ := json.Marshal(m.Labels)
	priorities, _ := json.Marshal(m.PriorityMap)
	fields, _ := json.Marshal(m.FieldValues)
	statusTransitions, _ := json.Marshal(m.StatusTransitions)
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `UPDATE ticket_mappings SET project_key=$3,issue_type=$4,component=$5,labels=$6::jsonb,priority_map=$7::jsonb,security_level=$8,summary_template=$9,description_template=$10,field_values=$11::jsonb,transition_name=$12,data_class=$13,locale=$14,waiver_reason=$15,auto_push_enabled=$16,auto_push_min_severity=$17,auto_push_enabled_at=$18,grouping_mode=$19,status_transitions=$20::jsonb,version=version+1,updated_at=$21 WHERE tenant_id=$1 AND id=$2 AND version=$22 RETURNING `+mappingCols, tenant.String(), m.ID.String(), m.ProjectKey, m.IssueType, m.Component, string(labels), string(priorities), m.SecurityLevel, m.SummaryTemplate, m.DescriptionTemplate, string(fields), m.Transition, string(m.DataClass), m.Locale, m.WaiverReason, m.AutoPushEnabled, string(m.AutoPushMinSeverity), m.AutoPushEnabledAt, string(m.GroupingMode), string(statusTransitions), m.UpdatedAt.UTC(), expected)
		var e error
		out, e = scanTicketMapping(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrConflict
		}
		return e
	})
	return out, ticketWriteError(err)
}
func (s *TicketStore) UpdateMappingAudited(ctx context.Context, tenant shared.ID, m ticketing.Mapping, expected int, audit ports.AuditEntry) (out ticketing.Mapping, err error) {
	err = NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		var e error
		out, e = s.UpdateMapping(txctx, tenant, m, expected)
		if e != nil {
			return e
		}
		return NewAuditLog(s.pool).Record(txctx, audit)
	})
	return out, err
}
func (s *TicketStore) DeleteMapping(ctx context.Context, tenant, id shared.ID, expected int) error {
	if tenant.IsZero() || id.IsZero() || expected < 1 {
		return shared.ErrValidation
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `DELETE FROM ticket_mappings m WHERE tenant_id=$1 AND id=$2 AND version=$3 AND NOT EXISTS (SELECT 1 FROM ticket_intents i WHERE i.tenant_id=m.tenant_id AND i.mapping_id=m.id)`, tenant.String(), id.String(), expected)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrConflict
		}
		return nil
	}))
}
func (s *TicketStore) DeleteMappingAudited(ctx context.Context, tenant, id shared.ID, expected int, audit ports.AuditEntry) error {
	return NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		if err := s.DeleteMapping(txctx, tenant, id, expected); err != nil {
			return err
		}
		return NewAuditLog(s.pool).Record(txctx, audit)
	})
}

const linkCols = `id,tenant_id,finding_id,engagement_id,COALESCE(integration_id,''),external_id,external_url,created_at`

func scanTicketLink(row rowScanner) (ticketing.Link, error) {
	var link ticketing.Link
	err := row.Scan(&link.ID, &link.TenantID, &link.FindingID, &link.EngagementID,
		&link.IntegrationID, &link.ExternalID, &link.ExternalURL, &link.CreatedAt)
	return link, err
}
func (s *TicketStore) CreateLink(ctx context.Context, tenant shared.ID, link ticketing.Link) (ticketing.Link, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Link{}, false, err
	}
	if err := link.Validate(); err != nil {
		return ticketing.Link{}, false, err
	}
	if tenant.IsZero() || tenant != link.TenantID {
		return ticketing.Link{}, false, shared.ErrValidation
	}
	var persisted ticketing.Link
	created := false
	err := ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var integration any
		if !link.IntegrationID.IsZero() {
			integration = link.IntegrationID.String()
		}
		tag, e := tx.Exec(ctx, `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,integration_id,external_id,external_url,created_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT (tenant_id,finding_id,external_url) DO NOTHING`,
			link.ID.String(), tenant.String(), link.FindingID.String(), link.EngagementID.String(),
			integration, link.ExternalID, link.ExternalURL, link.CreatedAt.UTC())
		if e != nil {
			return e
		}
		created = tag.RowsAffected() == 1
		persisted, e = scanTicketLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM ticket_links
            WHERE tenant_id=$1 AND finding_id=$2 AND external_url=$3`,
			tenant.String(), link.FindingID.String(), link.ExternalURL))
		if e != nil {
			return e
		}
		if persisted.EngagementID != link.EngagementID || persisted.IntegrationID != link.IntegrationID ||
			persisted.ExternalID != link.ExternalID {
			return shared.ErrConflict
		}
		return nil
	}))
	if err != nil {
		return ticketing.Link{}, false, err
	}
	return persisted, created, nil
}
func (s *TicketStore) ListLinks(ctx context.Context, tenant, finding shared.ID) ([]ticketing.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || finding.IsZero() {
		return nil, shared.ErrValidation
	}
	out := make([]ticketing.Link, 0)
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+linkCols+` FROM ticket_links
			WHERE tenant_id=$1 AND finding_id=$2 ORDER BY created_at DESC,id DESC LIMIT 100`,
			tenant.String(), finding.String())
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			item, scanErr := scanTicketLink(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}
func (s *TicketStore) GetLink(ctx context.Context, tenant, id shared.ID) (ticketing.Link, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Link{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return ticketing.Link{}, shared.ErrValidation
	}
	var link ticketing.Link
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		link, e = scanTicketLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM ticket_links WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ticketing.Link{}, shared.ErrNotFound
	}
	if err != nil {
		return ticketing.Link{}, fmt.Errorf("get ticket link: %w", err)
	}
	return link, nil
}
func (s *TicketStore) DeleteLink(ctx context.Context, tenant, id shared.ID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || id.IsZero() {
		return shared.ErrValidation
	}
	return requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM ticket_links WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrNotFound
		}
		return nil
	})
}

const intentCols = `id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,
    payload_digest,correlation_marker,state,version,attempts,lease_until,remote_id,remote_url,error_code,COALESCE(payload_snapshot,'null'::jsonb),COALESCE(mapping_version,0),COALESCE(connection_revision,0),COALESCE(credential_revision,0),security_level,created_at,updated_at`

func scanTicketIntent(row rowScanner) (ticketing.Intent, error) {
	var i ticketing.Intent
	err := row.Scan(&i.ID, &i.TenantID, &i.IntegrationID, &i.MappingID, &i.FindingID, &i.EngagementID,
		&i.Action, &i.RequestKey, &i.PayloadDigest, &i.Marker, &i.State, &i.Version, &i.Attempts,
		&i.LeaseUntil, &i.RemoteID, &i.RemoteURL, &i.ErrorCode, &i.Snapshot, &i.MappingVersion, &i.ConnectionRevision, &i.CredentialRevision, &i.SecurityLevel, &i.CreatedAt, &i.UpdatedAt)
	if string(i.Snapshot) == "null" {
		i.Snapshot = nil
	}
	return i, err
}
func sameTicketCommand(a, b ticketing.Intent) bool {
	return a.IntegrationID == b.IntegrationID && a.MappingID == b.MappingID && a.FindingID == b.FindingID &&
		a.EngagementID == b.EngagementID && a.Action == b.Action && a.RequestKey == b.RequestKey &&
		a.PayloadDigest == b.PayloadDigest
}
func (s *TicketStore) CreateOrGetIntent(ctx context.Context, tenant shared.ID, i ticketing.Intent) (ticketing.Intent, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if err := i.Validate(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if tenant.IsZero() || tenant != i.TenantID || i.State != writeintent.Pending || i.Version != 1 ||
		i.Attempts != 0 || i.LeaseUntil != nil {
		return ticketing.Intent{}, false, shared.ErrValidation
	}
	var saved ticketing.Intent
	created := false
	err := ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var requiredEngagement, requiredProject, engagementProject string
		e := tx.QueryRow(ctx, `SELECT COALESCE(m.engagement_id,''), COALESCE(m.project_id,''), COALESCE(e.project_id,'')
			FROM ticket_mappings m
			JOIN findings f ON f.tenant_id=m.tenant_id AND f.id=$4 AND f.engagement_id=$5
			JOIN engagements e ON e.tenant_id=f.tenant_id AND e.id=f.engagement_id
			WHERE m.tenant_id=$1 AND m.integration_id=$2 AND m.id=$3
			FOR KEY SHARE OF m,e`,
			tenant.String(), i.IntegrationID.String(), i.MappingID.String(), i.FindingID.String(), i.EngagementID.String()).
			Scan(&requiredEngagement, &requiredProject, &engagementProject)
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if e != nil {
			return e
		}
		if requiredEngagement != "" && requiredEngagement != i.EngagementID.String() {
			return shared.ErrValidation
		}
		if requiredProject != "" && requiredProject != engagementProject {
			return shared.ErrValidation
		}
		tag, e := tx.Exec(ctx, `INSERT INTO ticket_intents
            (id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,
             payload_digest,correlation_marker,state,version,attempts,lease_until,remote_id,remote_url,error_code,payload_snapshot,mapping_version,connection_revision,credential_revision,security_level,created_at,updated_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21,$22,$23,$24)
            ON CONFLICT (tenant_id,integration_id,request_key) DO NOTHING`,
			i.ID.String(), tenant.String(), i.IntegrationID.String(), i.MappingID.String(), i.FindingID.String(),
			i.EngagementID.String(), string(i.Action), i.RequestKey, i.PayloadDigest, i.Marker, string(i.State),
			i.Version, i.Attempts, nil, i.RemoteID, i.RemoteURL, i.ErrorCode, nullableJSON(i.Snapshot), nullableInt(i.MappingVersion), nullableInt(i.ConnectionRevision), nullableInt(i.CredentialRevision), i.SecurityLevel, i.CreatedAt.UTC(), i.UpdatedAt.UTC())
		if e != nil {
			return e
		}
		created = tag.RowsAffected() == 1
		saved, e = scanTicketIntent(tx.QueryRow(ctx, `SELECT `+intentCols+` FROM ticket_intents
            WHERE tenant_id=$1 AND integration_id=$2 AND request_key=$3`, tenant.String(),
			i.IntegrationID.String(), i.RequestKey))
		if e != nil {
			return e
		}
		if !sameTicketCommand(saved, i) {
			return shared.ErrConflict
		}
		return nil
	}))
	if err != nil {
		return ticketing.Intent{}, false, err
	}
	return saved, created, nil
}
func (s *TicketStore) CreateOrGetIntentAudited(ctx context.Context, tenant shared.ID, i ticketing.Intent, audit ports.AuditEntry) (out ticketing.Intent, created bool, err error) {
	if err = ctx.Err(); err != nil {
		return out, false, err
	}
	if err = i.Validate(); err != nil {
		return out, false, err
	}
	if tenant.IsZero() || tenant != i.TenantID || i.State != writeintent.Pending || i.Version != 1 || i.Attempts != 0 || i.LeaseUntil != nil {
		return out, false, shared.ErrValidation
	}
	err = NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		if i.Action == ticketing.Create {
			tx, e := ticketTx(txctx, tenant)
			if e != nil {
				return e
			}
			// Lock the canonical finding before looking for another active command.
			// This serializes distinct request keys without imposing a global unique
			// constraint on the foundation store.
			var findingID string
			e = tx.QueryRow(txctx, `SELECT id FROM findings WHERE tenant_id=$1 AND id=$2 AND engagement_id=$3 FOR NO KEY UPDATE`, tenant.String(), i.FindingID.String(), i.EngagementID.String()).Scan(&findingID)
			if errors.Is(e, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			if e != nil {
				return e
			}
			// A same-key replay is idempotent even if a later, distinct command is
			// now active for the finding. Validate its immutable command facts
			// before applying the no-blind-repeat gate, matching the memory store.
			existing, queryErr := scanTicketIntent(tx.QueryRow(txctx, `SELECT `+intentCols+` FROM ticket_intents
				WHERE tenant_id=$1 AND integration_id=$2 AND request_key=$3`, tenant.String(), i.IntegrationID.String(), i.RequestKey))
			if queryErr == nil {
				if !sameTicketCommand(existing, i) {
					return shared.ErrConflict
				}
				out, created = existing, false
				return nil
			}
			if !errors.Is(queryErr, pgx.ErrNoRows) {
				return queryErr
			}
			var blocked bool
			e = tx.QueryRow(txctx, `SELECT TRUE FROM ticket_intents
				WHERE tenant_id=$1 AND integration_id=$2 AND finding_id=$3 AND action='create' AND request_key<>$4
					AND state IN ('pending','in_flight','uncertain') LIMIT 1`, tenant.String(), i.IntegrationID.String(), i.FindingID.String(), i.RequestKey).Scan(&blocked)
			if e == nil && blocked {
				return shared.ErrConflict
			}
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
		}
		var e error
		out, created, e = s.CreateOrGetIntent(txctx, tenant, i)
		if e != nil {
			return e
		}
		if !created {
			return nil
		}
		return NewAuditLog(s.pool).Record(txctx, audit)
	})
	return out, created, err
}
func (s *TicketStore) GetIntent(ctx context.Context, tenant, id shared.ID) (ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return ticketing.Intent{}, shared.ErrValidation
	}
	var i ticketing.Intent
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		i, e = scanTicketIntent(tx.QueryRow(ctx, `SELECT `+intentCols+` FROM ticket_intents
            WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ticketing.Intent{}, shared.ErrNotFound
	}
	if err != nil {
		return ticketing.Intent{}, fmt.Errorf("get ticket intent: %w", err)
	}
	return i, nil
}
func (s *TicketStore) ListFindingIntents(ctx context.Context, tenant, finding shared.ID, limit int) (out []ticketing.Intent, err error) {
	if tenant.IsZero() || finding.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+intentCols+` FROM ticket_intents WHERE tenant_id=$1 AND finding_id=$2 ORDER BY created_at DESC,id DESC LIMIT $3`, tenant.String(), finding.String(), limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			i, e := scanTicketIntent(rows)
			if e != nil {
				return e
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, ticketWriteError(err)
}
func (s *TicketStore) ListDueIntents(ctx context.Context, tenant shared.ID, now time.Time, limit int) (out []ticketing.Intent, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || now.IsZero() || limit < 1 || limit > 200 {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+intentCols+` FROM ticket_intents i
			WHERE i.tenant_id=$1 AND (
				(i.state='in_flight' AND i.lease_until<=$2)
				OR (i.state='pending' AND NOT EXISTS (
					SELECT 1 FROM ticket_dispatch_breakers b
					WHERE b.tenant_id=i.tenant_id AND b.integration_id=i.integration_id
						AND b.project_key=i.payload_snapshot #>> '{fields,project,key}'
						AND b.issue_type=i.payload_snapshot #>> '{fields,issuetype,id}'
						AND ((b.gate_until IS NOT NULL AND b.gate_until>$2) OR (b.active_intent_id IS NOT NULL AND b.lease_until>$2))
				))
			) ORDER BY i.updated_at,i.id LIMIT $3`, tenant.String(), now.UTC(), limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			i, e := scanTicketIntent(rows)
			if e != nil {
				return e
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, ticketWriteError(err)
}
func (s *TicketStore) TransitionIntent(ctx context.Context, tenant, id shared.ID, expected int, change ticketing.IntentTransition, at time.Time) (ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() || expected < 1 || at.IsZero() {
		return ticketing.Intent{}, shared.ErrValidation
	}
	var result ticketing.Intent
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		result, e = scanTicketIntent(tx.QueryRow(ctx, `SELECT `+intentCols+` FROM ticket_intents
            WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant.String(), id.String()))
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if e != nil {
			return e
		}
		if result.Version != expected {
			return shared.ErrConflict
		}
		next, e := result.Apply(change, at)
		if e != nil {
			return e
		}
		if next.State == writeintent.Done {
			desired, linkErr := next.CompletionLink()
			if linkErr != nil {
				return linkErr
			}
			if _, linkErr = tx.Exec(ctx, `INSERT INTO ticket_links
                (id,tenant_id,finding_id,engagement_id,integration_id,external_id,external_url,created_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                ON CONFLICT (tenant_id,finding_id,external_url) DO NOTHING`,
				desired.ID.String(), tenant.String(), desired.FindingID.String(), desired.EngagementID.String(),
				desired.IntegrationID.String(), desired.ExternalID, desired.ExternalURL, desired.CreatedAt.UTC()); linkErr != nil {
				return linkErr
			}
			existing, linkErr := scanTicketLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM ticket_links
                WHERE tenant_id=$1 AND finding_id=$2 AND external_url=$3 FOR UPDATE`,
				tenant.String(), desired.FindingID.String(), desired.ExternalURL))
			if linkErr != nil {
				return linkErr
			}
			reconciled, linkErr := ticketing.ReconcileLink(existing, desired)
			if linkErr != nil {
				return linkErr
			}
			if reconciled.IntegrationID != existing.IntegrationID || reconciled.ExternalID != existing.ExternalID {
				if _, linkErr = tx.Exec(ctx, `UPDATE ticket_links
                    SET integration_id=$3, external_id=$4
                    WHERE tenant_id=$1 AND id=$2`, tenant.String(), reconciled.ID.String(),
					reconciled.IntegrationID.String(), reconciled.ExternalID); linkErr != nil {
					return linkErr
				}
			}
		}
		result, e = scanTicketIntent(tx.QueryRow(ctx, `UPDATE ticket_intents
            SET state=$3,version=$4,attempts=$5,lease_until=$6,remote_id=$7,remote_url=$8,error_code=$9,updated_at=$10
			WHERE tenant_id=$1 AND id=$2 AND version=$11 RETURNING `+intentCols,
			tenant.String(), id.String(), string(next.State), next.Version, next.Attempts,
			next.LeaseUntil, next.RemoteID, next.RemoteURL, next.ErrorCode, next.UpdatedAt, expected))
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrConflict
		}
		return e
	})
	if err != nil {
		return ticketing.Intent{}, ticketWriteError(err)
	}
	return result, nil
}
func (s *TicketStore) TransitionIntentAudited(ctx context.Context, tenant, id shared.ID, expected int, change ticketing.IntentTransition, at time.Time, audit ports.AuditEntry) (out ticketing.Intent, err error) {
	err = NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		var e error
		out, e = s.TransitionIntent(txctx, tenant, id, expected, change, at)
		if e != nil {
			return e
		}
		return NewAuditLog(s.pool).Record(txctx, audit)
	})
	return out, err
}

func validTicketAudit(entry ports.AuditEntry) bool {
	return entry.Actor != "" && entry.Action != "" && entry.Target != "" && !entry.At.IsZero()
}

func isRateLimited(code string) bool { return code == "rate_limited" || code == "http_429" }

// RetryIntentAudited atomically records an explicit duplicate-risk decision and
// returns a failed or uncertain command to pending. A still-active Retry-After
// gate is authoritative and cannot be cleared by a human retry.
func (s *TicketStore) RetryIntentAudited(ctx context.Context, tenant, id shared.ID, expected int, at time.Time, audit ports.AuditEntry) (out ticketing.Intent, err error) {
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if tenant.IsZero() || id.IsZero() || expected < 1 || at.IsZero() || !validTicketAudit(audit) {
		return out, shared.ErrValidation
	}
	err = NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		current, e := s.GetIntent(txctx, tenant, id)
		if e != nil {
			return e
		}
		if current.Version != expected || (current.State != writeintent.Failed && current.State != writeintent.Uncertain) {
			return shared.ErrConflict
		}
		tx, e := ticketTx(txctx, tenant)
		if e != nil {
			return e
		}
		var findingID string
		e = tx.QueryRow(txctx, `SELECT id FROM findings WHERE tenant_id=$1 AND id=$2 AND engagement_id=$3 FOR NO KEY UPDATE`, tenant.String(), current.FindingID.String(), current.EngagementID.String()).Scan(&findingID)
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if e != nil {
			return e
		}
		var blocked bool
		e = tx.QueryRow(txctx, `SELECT TRUE FROM ticket_intents
			WHERE tenant_id=$1 AND integration_id=$2 AND finding_id=$3 AND action='create' AND id<>$4
				AND state IN ('pending','in_flight','uncertain') LIMIT 1`, tenant.String(), current.IntegrationID.String(), current.FindingID.String(), current.ID.String()).Scan(&blocked)
		if e == nil && blocked {
			return shared.ErrConflict
		}
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		tuple, e := current.DispatchTarget()
		if e != nil {
			return e
		}
		br, e := lockBreaker(txctx, tx, tuple, at)
		if e != nil {
			return e
		}
		if isRateLimited(br.code) && br.gate != nil && at.Before(*br.gate) {
			return shared.ErrConflict
		}
		event := writeintent.RetryFailed
		if current.State == writeintent.Uncertain {
			event = writeintent.ReconcileAbsent
		}
		out, e = s.TransitionIntent(txctx, tenant, id, expected, ticketing.IntentTransition{Event: event}, at)
		if e != nil {
			return e
		}
		// A separate command may be in flight for this tuple. Retry only clears
		// the failure gate; it must never erase that command's dispatch fence.
		if _, e = tx.Exec(txctx, `UPDATE ticket_dispatch_breakers SET gate_until=NULL,breaker_code='',version=version+1,updated_at=$5 WHERE tenant_id=$1 AND integration_id=$2 AND project_key=$3 AND issue_type=$4`, tuple.TenantID.String(), tuple.IntegrationID.String(), tuple.ProjectKey, tuple.IssueType, at.UTC()); e != nil {
			return e
		}
		return NewAuditLog(s.pool).Record(txctx, audit)
	})
	return out, err
}

type breakerRow struct {
	active      shared.ID
	lease, gate *time.Time
	code        string
	version     int
}

func ticketTx(ctx context.Context, tenant shared.ID) (pgx.Tx, error) {
	tx, ok, err := contextTenantTx(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: ticket transaction required", shared.ErrValidation)
	}
	return tx, nil
}
func lockBreaker(ctx context.Context, tx pgx.Tx, t ticketing.DispatchTuple, now time.Time) (breakerRow, error) {
	_, err := tx.Exec(ctx, `INSERT INTO ticket_dispatch_breakers(tenant_id,integration_id,project_key,issue_type,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, t.TenantID.String(), t.IntegrationID.String(), t.ProjectKey, t.IssueType, now.UTC())
	if err != nil {
		return breakerRow{}, err
	}
	return readBreaker(ctx, tx, t)
}
func readBreaker(ctx context.Context, tx pgx.Tx, t ticketing.DispatchTuple) (breakerRow, error) {
	var r breakerRow
	err := tx.QueryRow(ctx, `SELECT COALESCE(active_intent_id,''),lease_until,gate_until,breaker_code,version FROM ticket_dispatch_breakers WHERE tenant_id=$1 AND integration_id=$2 AND project_key=$3 AND issue_type=$4 FOR UPDATE`, t.TenantID.String(), t.IntegrationID.String(), t.ProjectKey, t.IssueType).Scan(&r.active, &r.lease, &r.gate, &r.code, &r.version)
	return r, err
}
func (s *TicketStore) AcquireDispatch(ctx context.Context, tenant, id shared.ID, expected int, now, leaseUntil time.Time) (out ticketing.Intent, claimed bool, err error) {
	if tenant.IsZero() || id.IsZero() || expected < 1 || now.IsZero() || !leaseUntil.After(now) {
		return out, false, shared.ErrValidation
	}
	err = NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		current, e := s.GetIntent(txctx, tenant, id)
		if e != nil {
			return e
		}
		if current.Version != expected || current.State != writeintent.Pending {
			return shared.ErrConflict
		}
		tuple, e := current.DispatchTarget()
		if e != nil {
			return e
		}
		tx, e := ticketTx(txctx, tenant)
		if e != nil {
			return e
		}
		br, e := lockBreaker(txctx, tx, tuple, now)
		if e != nil {
			return e
		}
		if br.gate != nil && now.Before(*br.gate) {
			return nil
		}
		if !br.active.IsZero() && br.lease != nil && now.Before(*br.lease) {
			return nil
		}
		if !br.active.IsZero() && br.lease != nil && !now.Before(*br.lease) {
			old, e := s.GetIntent(txctx, tenant, br.active)
			if e == nil && old.State == writeintent.InFlight {
				if _, e = s.TransitionIntent(txctx, tenant, old.ID, old.Version, ticketing.IntentTransition{Event: writeintent.LeaseExpired}, now); e != nil {
					return e
				}
			}
		}
		out, e = s.TransitionIntent(txctx, tenant, id, expected, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &leaseUntil}, now)
		if e != nil {
			return e
		}
		_, e = tx.Exec(txctx, `UPDATE ticket_dispatch_breakers SET active_intent_id=$5,lease_until=$6,updated_at=$7,version=version+1 WHERE tenant_id=$1 AND integration_id=$2 AND project_key=$3 AND issue_type=$4`, tuple.TenantID.String(), tuple.IntegrationID.String(), tuple.ProjectKey, tuple.IssueType, id.String(), leaseUntil.UTC(), now.UTC())
		claimed = e == nil
		return e
	})
	return out, claimed, err
}
func (s *TicketStore) FinishDispatch(ctx context.Context, tenant, id shared.ID, expected int, change ticketing.IntentTransition, at time.Time, cooldown *time.Time, code string) (out ticketing.Intent, err error) {
	if tenant.IsZero() || id.IsZero() || expected < 1 || at.IsZero() {
		return out, shared.ErrValidation
	}
	err = NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		current, e := s.GetIntent(txctx, tenant, id)
		if e != nil {
			return e
		}
		if current.Version != expected || current.State != writeintent.InFlight {
			return shared.ErrConflict
		}
		tuple, e := current.DispatchTarget()
		if e != nil {
			return e
		}
		tx, e := ticketTx(txctx, tenant)
		if e != nil {
			return e
		}
		br, e := lockBreaker(txctx, tx, tuple, at)
		if e != nil {
			return e
		}
		if br.active != id || br.lease == nil || !at.Before(*br.lease) {
			return shared.ErrConflict
		}
		out, e = s.TransitionIntent(txctx, tenant, id, expected, change, at)
		if e != nil {
			return e
		}
		gate := cooldown
		if change.Event == writeintent.Reject && (code == "http_400" || code == "http_401" || code == "http_403" || code == "http_404") {
			far := at.AddDate(100, 0, 0)
			gate = &far
		}
		if isRateLimited(code) {
			code = "rate_limited"
		}
		if _, e = tx.Exec(txctx, `UPDATE ticket_dispatch_breakers SET active_intent_id=NULL,lease_until=NULL,gate_until=$5,breaker_code=$6,updated_at=$7,version=version+1 WHERE tenant_id=$1 AND integration_id=$2 AND project_key=$3 AND issue_type=$4`, tuple.TenantID.String(), tuple.IntegrationID.String(), tuple.ProjectKey, tuple.IssueType, gate, code, at.UTC()); e != nil {
			return e
		}
		return nil
	})
	return out, err
}
func (s *TicketStore) ResetBreaker(ctx context.Context, tenant, integrationID shared.ID, project, issue string, audit ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || integrationID.IsZero() || project == "" || issue == "" || !validTicketAudit(audit) {
		return shared.ErrValidation
	}
	return NewTenantTransactionRunner(s.pool).Run(ctx, tenant, func(txctx context.Context) error {
		tx, e := ticketTx(txctx, tenant)
		if e != nil {
			return e
		}
		tuple := ticketing.DispatchTuple{TenantID: tenant, IntegrationID: integrationID, ProjectKey: project, IssueType: issue}
		br, e := readBreaker(txctx, tx, tuple)
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if e != nil {
			return e
		}
		if isRateLimited(br.code) && br.gate != nil && audit.At.Before(*br.gate) {
			return shared.ErrConflict
		}
		if _, e = tx.Exec(txctx, `UPDATE ticket_dispatch_breakers SET gate_until=NULL,breaker_code='',version=version+1,updated_at=$5 WHERE tenant_id=$1 AND integration_id=$2 AND project_key=$3 AND issue_type=$4`, tenant.String(), integrationID.String(), project, issue, audit.At.UTC()); e != nil {
			return e
		}
		return NewAuditLog(s.pool).Record(txctx, audit)
	})
}
