package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationSource projects durable source records into generic notification
// events. Every projection and its delivery jobs commit in one tenant transaction.
type NotificationSource struct {
	pool                  *pgxpool.Pool
	repo                  *NotificationRepository
	fleetStaleAfter       time.Duration
	incidentEnabled       bool
	vulnerabilityDisabled bool
}

func NewNotificationSource(pool *pgxpool.Pool, repo *NotificationRepository, fleetStaleAfter time.Duration, incidentEnabled bool) *NotificationSource {
	if fleetStaleAfter <= 0 {
		fleetStaleAfter = 10 * time.Minute
	}
	return &NotificationSource{pool: pool, repo: repo, fleetStaleAfter: fleetStaleAfter, incidentEnabled: incidentEnabled}
}

var _ ports.NotificationSource = (*NotificationSource)(nil)

func (s *NotificationSource) SetVulnerabilityEnabled(enabled bool) {
	s.vulnerabilityDisabled = !enabled
}

func (s *NotificationSource) Poll(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id FROM tenants WHERE id<>'' ORDER BY id`)
	if err != nil {
		return 0, fmt.Errorf("list notification tenants: %w", err)
	}
	var tenants []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		tenants = append(tenants, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	total := 0
	var failures []error
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		n, err := s.pollTenant(ctx, tenant, now.UTC(), limit)
		if err != nil {
			failures = append(failures, fmt.Errorf("poll notification sources for tenant %s: %w", tenant, err))
			continue
		}
		total += n
	}
	return total, errors.Join(failures...)
}

func (s *NotificationSource) pollTenant(ctx context.Context, tenant shared.ID, now time.Time, limit int) (int, error) {
	count := 0
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		// Serialize scheduler observations per tenant across worker failover.
		var acquired bool
		if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 78145))", tenant.String()).Scan(&acquired); err != nil {
			return err
		}
		if !acquired {
			return nil
		}
		if err := s.repo.reconcileTx(ctx, tx, tenant); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'framework','activation','v1',true,$2) ON CONFLICT DO NOTHING`, tenant, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			// Establish the current fleet episode without paging on agents that were
			// already stale when the framework was enabled.
			if _, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) SELECT tenant_id,'fleet_agent',id,((extract(epoch FROM last_seen_at)*1000000)::bigint*1000)::text,(last_seen_at <= $2::timestamptz-make_interval(secs=>$3)),$2 FROM fleet_agents WHERE tenant_id=$1 AND state IN ('active','stale') AND last_seen_at>created_at ON CONFLICT DO NOTHING`, tenant, now, s.fleetStaleAfter.Seconds()); err != nil {
				return err
			}
			return nil
		}
		var activated time.Time
		if err := tx.QueryRow(ctx, `SELECT observed_at FROM notification_source_state WHERE tenant_id=$1 AND source_kind='framework' AND source_id='activation'`, tenant).Scan(&activated); err != nil {
			return err
		}
		remaining := limit
		for _, poll := range []func(context.Context, pgx.Tx, shared.ID, time.Time, time.Time, int) (int, error){s.pollVulnerability, s.pollScans, s.pollQualityGates, s.pollSLA, s.pollIncidents} {
			if remaining <= 0 {
				break
			}
			n, err := poll(ctx, tx, tenant, activated, now, remaining)
			if err != nil {
				return err
			}
			count += n
			// Each source receives a bounded budget so sustained scans cannot starve SLA/fleet.
			remaining = limit
		}
		if remaining > 0 {
			n, err := s.pollFleet(ctx, tx, tenant, activated, now, remaining)
			if err != nil {
				return err
			}
			count += n
		}
		return nil
	})
	return count, err
}

func (s *NotificationSource) pollVulnerability(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, limit int) (int, error) {
	if s.vulnerabilityDisabled {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `SELECT o.id,o.payload,o.created_at,a.engagement_id,a.action_type,a.title,ra.severity FROM vulnerability_action_outbox o JOIN vulnerability_actions a ON a.tenant_id=o.tenant_id AND a.id=o.action_id JOIN vulnerability_risk_transitions t ON t.tenant_id=a.tenant_id AND t.id=a.transition_id JOIN vulnerability_risk_assessments ra ON ra.tenant_id=t.tenant_id AND ra.id=t.after_assessment_id WHERE o.tenant_id=$1 AND (o.state='pending' OR (o.state='delivering' AND o.locked_until<$3)) AND o.created_at >= $2 AND o.available_at <= $3 ORDER BY o.available_at,o.id FOR UPDATE OF o SKIP LOCKED LIMIT $4`, tenant, activated, now, limit)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type item struct {
		id                      shared.ID
		payload                 []byte
		at                      time.Time
		eng                     shared.ID
		action, title, severity string
	}
	var items []item
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.id, &v.payload, &v.at, &v.eng, &v.action, &v.title, &v.severity); err != nil {
			return 0, err
		}
		items = append(items, v)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, v := range items {
		data, _ := json.Marshal(map[string]any{"title": v.title, "summary": "A vulnerability risk action requires review.", "action_type": v.action, "outbox_id": v.id})
		e := notification.Event{TenantID: tenant, ID: stableID(tenant.String(), "vulnerability", v.id.String()), Type: notification.EventVulnerabilityAction, SourceKind: "vulnerability_action_outbox", SourceID: v.id.String(), EngagementID: v.eng, Severity: shared.Severity(v.severity), SchemaVersion: 1, OccurredAt: v.at, Data: data}
		if _, err := s.repo.publishTx(ctx, tx, e, ""); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE vulnerability_action_outbox SET state='delivered',locked_until=NULL,last_error='',delivered_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2`, tenant, v.id, now); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}

func (s *NotificationSource) pollScans(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, limit int) (int, error) {
	return s.pollCaptured(ctx, tx, tenant, "scan_job", now, limit, true)
}

func (s *NotificationSource) pollQualityGates(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, limit int) (int, error) {
	return s.pollCaptured(ctx, tx, tenant, "project_analysis_gate", now, limit, true)
}

func (s *NotificationSource) pollSLA(ctx context.Context, tx pgx.Tx, tenant shared.ID, _, now time.Time, limit int) (int, error) {
	leadRows, err := tx.Query(ctx, `SELECT DISTINCT lead_time_secs FROM notification_rules WHERE tenant_id=$1 AND enabled AND event_type='sla.approaching_deadline' ORDER BY lead_time_secs`, tenant)
	if err != nil {
		return 0, err
	}
	var leads []int64
	for leadRows.Next() {
		var lead int64
		if err := leadRows.Scan(&lead); err != nil {
			leadRows.Close()
			return 0, err
		}
		if lead > 0 {
			leads = append(leads, lead)
		}
	}
	if err := leadRows.Err(); err != nil {
		leadRows.Close()
		return 0, err
	}
	leadRows.Close()
	count := 0
	for _, lead := range leads {
		if count >= limit {
			break
		}
		rows, err := tx.Query(ctx, `SELECT ca.assessment_id,ca.engagement_id,ca.finding_id,a.remediate_by,a.tier FROM sla_current_assessments ca JOIN sla_assessments a ON a.tenant_id=ca.tenant_id AND a.id=ca.assessment_id JOIN sla_lifecycles l ON l.tenant_id=ca.tenant_id AND l.engagement_id=ca.engagement_id AND l.finding_id=ca.finding_id WHERE ca.tenant_id=$1 AND l.status IN ('open','mitigating') AND a.remediate_by>$2 AND a.remediate_by<=$2::timestamptz+make_interval(secs=>$3) AND NOT EXISTS (SELECT 1 FROM notification_events n WHERE n.tenant_id=$1 AND n.source_kind='sla_reminder' AND n.data->>'assessment_id'=ca.assessment_id AND (n.data->>'lead_time_seconds')::bigint=$3) ORDER BY a.remediate_by,ca.assessment_id LIMIT $4`, tenant, now, lead, limit-count)
		if err != nil {
			return count, err
		}
		type item struct {
			assessment   string
			eng, finding shared.ID
			deadline     time.Time
			tier         string
		}
		var items []item
		for rows.Next() {
			var v item
			if err := rows.Scan(&v.assessment, &v.eng, &v.finding, &v.deadline, &v.tier); err != nil {
				rows.Close()
				return count, err
			}
			items = append(items, v)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return count, err
		}
		rows.Close()
		for _, v := range items {
			source := v.assessment + ":" + strconv.FormatInt(lead, 10) + ":" + v.deadline.UTC().Format(time.RFC3339Nano)
			data, _ := json.Marshal(map[string]any{"title": "Remediation SLA approaching", "summary": "A " + v.tier + " finding is approaching its remediation deadline.", "assessment_id": v.assessment, "engagement_id": v.eng, "finding_id": v.finding, "deadline": v.deadline, "lead_time_seconds": lead})
			e := notification.Event{TenantID: tenant, ID: stableID(tenant.String(), "sla", source), Type: notification.EventSLAApproaching, SourceKind: "sla_reminder", SourceID: source, EngagementID: v.eng, SchemaVersion: 1, OccurredAt: now, Data: data}
			if _, err := s.repo.publishTx(ctx, tx, e, ""); err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
}

func (s *NotificationSource) pollIncidents(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, limit int) (int, error) {
	return s.pollCaptured(ctx, tx, tenant, "incident", now, limit, s.incidentEnabled)
}

func (s *NotificationSource) pollFleet(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, limit int) (int, error) {
	rows, err := tx.Query(ctx, `SELECT id,name,last_seen_at,state FROM fleet_agents WHERE tenant_id=$1 AND state IN ('active','stale') AND last_seen_at>created_at ORDER BY id`, tenant)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type item struct {
		id, name string
		last     time.Time
		state    string
	}
	var items []item
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.id, &v.name, &v.last, &v.state); err != nil {
			return 0, err
		}
		items = append(items, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	count := 0
	for _, v := range items {
		offline := now.Sub(v.last) >= s.fleetStaleAfter
		var oldFingerprint string
		var oldActive bool
		err := tx.QueryRow(ctx, `SELECT fingerprint,active FROM notification_source_state WHERE tenant_id=$1 AND source_kind='fleet_agent' AND source_id=$2`, tenant, v.id).Scan(&oldFingerprint, &oldActive)
		if err != nil && err != pgx.ErrNoRows {
			return count, err
		}
		fingerprint := strconv.FormatInt(v.last.UnixNano(), 10)
		if !offline {
			_, err = tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'fleet_agent',$2,$3,false,$4) ON CONFLICT(tenant_id,source_kind,source_id) DO UPDATE SET fingerprint=excluded.fingerprint,active=false,observed_at=excluded.observed_at`, tenant, v.id, fingerprint, now)
			if err != nil {
				return count, err
			}
			continue
		}
		if count >= limit {
			break
		}
		if oldActive && oldFingerprint == fingerprint {
			continue
		}
		source := v.id + ":" + fingerprint
		data, _ := json.Marshal(map[string]any{"title": "Fleet agent offline", "summary": "Agent " + v.name + " has missed its heartbeat freshness window.", "agent_id": v.id, "last_seen_at": v.last})
		e := notification.Event{TenantID: tenant, ID: stableID(tenant.String(), "fleet-offline", source), Type: notification.EventFleetAgentOffline, SourceKind: "fleet_agent_offline_episode", SourceID: source, SchemaVersion: 1, OccurredAt: now, Data: data}
		if _, err := s.repo.publishTx(ctx, tx, e, ""); err != nil {
			return count, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'fleet_agent',$2,$3,true,$4) ON CONFLICT(tenant_id,source_kind,source_id) DO UPDATE SET fingerprint=excluded.fingerprint,active=true,observed_at=excluded.observed_at`, tenant, v.id, fingerprint, now); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
