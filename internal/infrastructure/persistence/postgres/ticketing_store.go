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

const mappingCols = `id,tenant_id,integration_id,COALESCE(project_id,''),COALESCE(engagement_id,''),
    project_key,issue_type,component,labels,priority_map,security_level,version,created_at,updated_at`

func scanTicketMapping(row rowScanner) (ticketing.Mapping, error) {
	var m ticketing.Mapping
	var project, engagement string
	var labels, priorities []byte
	err := row.Scan(&m.ID, &m.TenantID, &m.IntegrationID, &project, &engagement,
		&m.ProjectKey, &m.IssueType, &m.Component, &labels, &priorities, &m.SecurityLevel,
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
	return m, nil
}
func (s *TicketStore) CreateMapping(ctx context.Context, tenant shared.ID, m ticketing.Mapping) error {
	if err := ctx.Err(); err != nil {
		return err
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
	labels, err := json.Marshal(m.Labels)
	if err != nil {
		return shared.ErrValidation
	}
	priorities, err := json.Marshal(m.PriorityMap)
	if err != nil {
		return shared.ErrValidation
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ticket_mappings
            (id,tenant_id,integration_id,project_id,engagement_id,project_key,issue_type,
             component,labels,priority_map,security_level,version,created_at,updated_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13,$14)`,
			m.ID.String(), tenant.String(), m.IntegrationID.String(), project, engagement, m.ProjectKey,
			m.IssueType, m.Component, string(labels), string(priorities), m.SecurityLevel, m.Version,
			m.CreatedAt.UTC(), m.UpdatedAt.UTC())
		return err
	}))
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
            WHERE tenant_id=$1 AND finding_id=$2 ORDER BY created_at DESC,id DESC`,
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
    payload_digest,correlation_marker,state,version,attempts,lease_until,remote_id,remote_url,error_code,created_at,updated_at`

func scanTicketIntent(row rowScanner) (ticketing.Intent, error) {
	var i ticketing.Intent
	err := row.Scan(&i.ID, &i.TenantID, &i.IntegrationID, &i.MappingID, &i.FindingID, &i.EngagementID,
		&i.Action, &i.RequestKey, &i.PayloadDigest, &i.Marker, &i.State, &i.Version, &i.Attempts,
		&i.LeaseUntil, &i.RemoteID, &i.RemoteURL, &i.ErrorCode, &i.CreatedAt, &i.UpdatedAt)
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
             payload_digest,correlation_marker,state,version,attempts,lease_until,remote_id,remote_url,error_code,created_at,updated_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
            ON CONFLICT (tenant_id,integration_id,request_key) DO NOTHING`,
			i.ID.String(), tenant.String(), i.IntegrationID.String(), i.MappingID.String(), i.FindingID.String(),
			i.EngagementID.String(), string(i.Action), i.RequestKey, i.PayloadDigest, i.Marker, string(i.State),
			i.Version, i.Attempts, nil, i.RemoteID, i.RemoteURL, i.ErrorCode, i.CreatedAt.UTC(), i.UpdatedAt.UTC())
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
