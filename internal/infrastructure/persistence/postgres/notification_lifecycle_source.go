package postgres

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	slaBreachStateKind    = "sla_breach"
	riskExpiringStateKind = "risk_acceptance_expiring"
	riskExpiredStateKind  = "risk_acceptance_expired"
	maxLifecycleBatch     = 64
)

type lifecycleSourceFact struct {
	assessment, acceptance                                    string
	engagement, finding                                       shared.ID
	deadline, breachedAt, accepted, expiry                    time.Time
	tier, severity, title, engagementName, teamID, assigneeID string
	version                                                   int
}

type lifecycleRow struct {
	fact   lifecycleSourceFact
	status string
}

func collectLifecycleRows(rows pgx.Rows) ([]lifecycleRow, error) {
	items := make([]lifecycleRow, 0)
	for rows.Next() {
		var item lifecycleRow
		if err := rows.Scan(&item.fact.assessment, &item.fact.engagement, &item.fact.finding, &item.fact.deadline, &item.fact.tier, &item.fact.title, &item.fact.engagementName, &item.fact.severity, &item.fact.teamID, &item.fact.assigneeID, &item.status, &item.fact.version, &item.fact.expiry); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, item)
	}
	err := rows.Err()
	rows.Close()
	return items, err
}

// pollLifecycle projects scheduler-owned threshold events in the same tenant
// transaction as their durable observation. Source state turns retries and
// leader failover into no-ops without depending on wall-clock precision.
func (s *NotificationSource) pollLifecycle(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	limit = min(limit, maxLifecycleBatch)
	leads, err := lifecycleLeads(ctx, tx, tenant)
	if err != nil {
		return 0, err
	}
	categories := []func(int) (int, error){
		func(budget int) (int, error) { return s.pollSLABreaches(ctx, tx, tenant, now, budget) },
		func(budget int) (int, error) {
			return s.pollRiskThreshold(ctx, tx, tenant, activated, now, 0, true, budget)
		},
	}
	for _, lead := range leads {
		categories = append(categories, func(budget int) (int, error) {
			return s.pollRiskThreshold(ctx, tx, tenant, activated, now, lead, false, budget)
		})
	}
	categories = append(categories, func(budget int) (int, error) { return s.pollEngagementWindows(ctx, tx, tenant, activated, now, budget) })
	return pollNotificationCategories(ctx, tx, tenant, "lifecycle_poll", now, limit, categories)
}

func pollNotificationCategories(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind string, now time.Time, limit int, categories []func(int) (int, error)) (int, error) {
	if limit <= 0 || len(categories) == 0 {
		return 0, nil
	}
	// Rotate even tiny batches across breach, expiry and every warning window.
	// Persist the cursor with observations so worker failover preserves fairness.
	fingerprint, _, _, err := lifecycleState(ctx, tx, tenant, kind, "category")
	if err != nil {
		return 0, err
	}
	start := max(0, lifecycleOrdinal(fingerprint)) % len(categories)
	budget := max(1, limit/len(categories))
	count, visited := 0, 0
	for visited < len(categories) && count < limit {
		n, err := categories[(start+visited)%len(categories)](min(budget, limit-count))
		if err != nil {
			return 0, err
		}
		count += n
		visited++
	}
	if err := upsertLifecycleState(ctx, tx, tenant, kind, "category", strconv.Itoa((start+visited)%len(categories)), true, now); err != nil {
		return 0, err
	}
	return count, nil
}

// baselineLifecycle establishes the current conditions when notifications are
// first enabled. It suppresses historical pages while retaining future expiry
// and threshold transitions for acceptances already on the finding.
func (s *NotificationSource) baselineLifecycle(ctx context.Context, tx pgx.Tx, tenant shared.ID, now time.Time) error {
	leads, err := lifecycleLeads(ctx, tx, tenant)
	if err != nil {
		return err
	}
	current := `WITH current(assessment,engagement,finding,deadline,tier,title,engagement_name,severity,team,assignee,status,version,expiry) AS (` + lifecycleCurrentQuery(`true`) + ` ORDER BY ca.finding_id FOR UPDATE OF l) `
	// Activation can cover a large existing finding inventory. Establish its
	// baseline in set-based writes rather than one round trip per finding.
	if _, err := tx.Exec(ctx, current+`
		INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
		SELECT $1,'sla_breach',finding || ':' || ((extract(epoch FROM deadline)*1000000)::bigint)::text,$3::text,true,$2
		FROM current WHERE deadline<$2 AND (status IN ('open','mitigating') OR (status='accepted_risk' AND expiry<$2))
		ON CONFLICT DO NOTHING`, tenant, now, strconv.Itoa(s.slaBreachMaxReminders)); err != nil {
		return err
	}
	acceptances := current + `, accepted AS (
		SELECT c.*,event.id AS acceptance FROM current c
		JOIN LATERAL (
			SELECT id FROM sla_lifecycle_events
			WHERE tenant_id=$1 AND engagement_id=c.engagement AND finding_id=c.finding
				AND after_version=c.version AND to_status='accepted_risk'
			ORDER BY occurred_at DESC,id DESC LIMIT 1
		) event ON true WHERE c.status='accepted_risk'
	) `
	if _, err := tx.Exec(ctx, acceptances+`
		INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
		SELECT $1,'risk_acceptance_expired',acceptance,expiry::text,true,$2
		FROM accepted WHERE expiry<$2 ON CONFLICT DO NOTHING`, tenant, now); err != nil {
		return err
	}
	if len(leads) == 0 {
		return nil
	}
	_, err = tx.Exec(ctx, acceptances+`
		INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
		SELECT $1,'risk_acceptance_expiring',acceptance || ':' || lead::text,expiry::text,true,$2
		FROM accepted CROSS JOIN unnest($3::bigint[]) lead
		WHERE expiry>$2 AND expiry-make_interval(secs=>lead::double precision)<$2
		ON CONFLICT DO NOTHING`, tenant, now, leads)
	return err
}

func (s *NotificationSource) pollSLABreaches(ctx context.Context, tx pgx.Tx, tenant shared.ID, now time.Time, limit int) (int, error) {
	query := strings.Replace(lifecycleCurrentQuery(`a.remediate_by <= $2 AND (l.status IN ('open','mitigating') OR (l.status='accepted_risk' AND l.acceptance_expires_at <= $2))`), `		WHERE`, `		LEFT JOIN notification_source_state st ON st.tenant_id=ca.tenant_id AND st.source_kind='sla_breach' AND st.source_id=ca.finding_id || ':' || ((extract(epoch FROM a.remediate_by)*1000000)::bigint)::text
		WHERE`, 1)
	query += ` AND (st.active IS NOT TRUE OR COALESCE(NULLIF(st.fingerprint,'')::int,-1) < ` + slaDueSQL() + `) ORDER BY a.remediate_by,ca.finding_id LIMIT $3 FOR UPDATE OF l`
	rows, err := tx.Query(ctx, query, tenant, now, limit, s.slaBreachMaxReminders)
	if err != nil {
		return 0, err
	}
	items, err := collectLifecycleRows(rows)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, item := range items {
		f, status := item.fact, item.status
		f.breachedAt = f.deadline
		if status == "accepted_risk" && f.expiry.After(f.breachedAt) {
			f.breachedAt = f.expiry
		}
		key := lifecycleBreachKey(f)
		oldFingerprint, oldActive, found, err := lifecycleState(ctx, tx, tenant, slaBreachStateKind, key)
		if err != nil {
			return count, err
		}
		due := latestSLABreachReminder(f.breachedAt, now, s.slaBreachMaxReminders)
		if due < 0 {
			continue
		}
		oldOrdinal := -1
		if found && oldActive {
			oldOrdinal = lifecycleOrdinal(oldFingerprint)
		}
		if oldOrdinal >= due {
			continue
		}
		// One event advances straight to the latest due reminder after downtime.
		source := key + ":" + strconv.Itoa(f.version) + ":" + strconv.Itoa(due)
		if err := s.publishLifecycle(ctx, tx, tenant, notification.EventSLABreached, "sla_breach_episode", source, f, reminderAt(f.breachedAt, due), due, 0); err != nil {
			return count, err
		}
		if err := upsertLifecycleState(ctx, tx, tenant, slaBreachStateKind, key, strconv.Itoa(due), true, now); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func slaDueSQL() string {
	start := `GREATEST(a.remediate_by,COALESCE(l.acceptance_expires_at,a.remediate_by))`
	return `CASE
		WHEN $4>=8 AND $2>=` + start + `+interval '128 days' THEN 8
		WHEN $4>=7 AND $2>=` + start + `+interval '64 days' THEN 7
		WHEN $4>=6 AND $2>=` + start + `+interval '32 days' THEN 6
		WHEN $4>=5 AND $2>=` + start + `+interval '16 days' THEN 5
		WHEN $4>=4 AND $2>=` + start + `+interval '8 days' THEN 4
		WHEN $4>=3 AND $2>=` + start + `+interval '4 days' THEN 3
		WHEN $4>=2 AND $2>=` + start + `+interval '2 days' THEN 2
		WHEN $4>=1 AND $2>=` + start + `+interval '1 day' THEN 1
		ELSE 0 END`
}

func lifecycleLeads(ctx context.Context, tx pgx.Tx, tenant shared.ID) ([]int64, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT lead_time_secs FROM notification_rules WHERE tenant_id=$1 AND enabled AND event_type='risk_acceptance.expiring' AND lead_time_secs>0 ORDER BY lead_time_secs`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var lead int64
		if err := rows.Scan(&lead); err != nil {
			return nil, err
		}
		out = append(out, lead)
	}
	return out, rows.Err()
}

func (s *NotificationSource) pollRiskThreshold(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, lead int64, expired bool, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	condition := `l.acceptance_expires_at <= $2`
	stateKind, typ := riskExpiredStateKind, notification.EventRiskAcceptanceExpired
	if !expired {
		condition = `l.acceptance_expires_at > $2 AND l.acceptance_expires_at <= $2::timestamptz+make_interval(secs=>$3::int)`
		stateKind, typ = riskExpiringStateKind, notification.EventRiskAcceptanceExpiring
	}
	query := lifecycleCurrentQuery(`l.status='accepted_risk' AND ` + condition)
	stateID := `accepted_event.id`
	if !expired {
		stateID += ` || ':' || ($3::bigint)::text`
	}
	query = strings.Replace(query, `		WHERE`, `		LEFT JOIN LATERAL (
			SELECT id FROM sla_lifecycle_events accepted_event
			WHERE accepted_event.tenant_id=ca.tenant_id AND accepted_event.engagement_id=ca.engagement_id
				AND accepted_event.finding_id=ca.finding_id AND accepted_event.after_version=l.version
				AND accepted_event.to_status='accepted_risk'
			ORDER BY accepted_event.occurred_at DESC,accepted_event.id DESC LIMIT 1
		) accepted_event ON true
		LEFT JOIN notification_source_state observed ON observed.tenant_id=ca.tenant_id
			AND observed.source_kind='`+stateKind+`' AND observed.source_id=`+stateID+`
		WHERE`, 1)
	query += ` AND observed.active IS NOT TRUE`
	var rows pgx.Rows
	var err error
	if expired {
		rows, err = tx.Query(ctx, query+` ORDER BY l.acceptance_expires_at,ca.finding_id LIMIT $3 FOR UPDATE OF l`, tenant, now, limit)
	} else {
		rows, err = tx.Query(ctx, query+` ORDER BY l.acceptance_expires_at,ca.finding_id LIMIT $4 FOR UPDATE OF l`, tenant, now, lead, limit)
	}
	if err != nil {
		return 0, err
	}
	items, err := collectLifecycleRows(rows)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, item := range items {
		f := item.fact
		if err := tx.QueryRow(ctx, `SELECT id,occurred_at FROM sla_lifecycle_events WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3 AND after_version=$4 AND to_status='accepted_risk' ORDER BY occurred_at DESC,id DESC LIMIT 1`, tenant, f.engagement, f.finding, f.version).Scan(&f.acceptance, &f.accepted); err != nil {
			return count, err
		}
		key := f.acceptance
		if !expired {
			key += ":" + strconv.FormatInt(lead, 10)
		}
		fingerprint := f.expiry.UTC().Format(time.RFC3339Nano)
		old, active, _, err := lifecycleState(ctx, tx, tenant, stateKind, key)
		if err != nil {
			return count, err
		}
		if active && old == fingerprint {
			continue
		}
		threshold := f.expiry
		if !expired {
			threshold = f.expiry.Add(-time.Duration(lead) * time.Second)
		}
		// A prior acceptance may legitimately cross a new threshold after activation,
		// but never retroactively page for a threshold it crossed before activation.
		if threshold.Before(activated) {
			if err := upsertLifecycleState(ctx, tx, tenant, stateKind, key, fingerprint, true, now); err != nil {
				return count, err
			}
			continue
		}
		source := key
		if err := s.publishLifecycle(ctx, tx, tenant, typ, stateKind, source, f, threshold, 0, lead); err != nil {
			return count, err
		}
		if err := upsertLifecycleState(ctx, tx, tenant, stateKind, key, fingerprint, true, now); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func lifecycleCurrentQuery(condition string) string {
	return `SELECT ca.assessment_id,ca.engagement_id,ca.finding_id,a.remediate_by,a.tier,COALESCE(f.title,''),COALESCE(eg.name,''),COALESCE(NULLIF(f.severity,''),ra.severity,''),COALESCE(oa.team_id,''),COALESCE(assignee.id,''),l.status,l.version,COALESCE(l.acceptance_expires_at,'epoch'::timestamptz)
		FROM sla_current_assessments ca
		JOIN sla_assessments a ON a.tenant_id=ca.tenant_id AND a.id=ca.assessment_id
		JOIN sla_lifecycles l ON l.tenant_id=ca.tenant_id AND l.engagement_id=ca.engagement_id AND l.finding_id=ca.finding_id
		JOIN findings f ON f.tenant_id=ca.tenant_id AND f.engagement_id=ca.engagement_id AND f.id=ca.finding_id
		LEFT JOIN engagements eg ON eg.tenant_id=ca.tenant_id AND eg.id=ca.engagement_id
		LEFT JOIN vulnerability_risk_assessments ra ON ra.tenant_id=f.tenant_id AND ra.id=f.risk_assessment_id
		LEFT JOIN ownership_assignments oa ON oa.tenant_id=ca.tenant_id AND oa.engagement_id=ca.engagement_id AND oa.finding_id=ca.finding_id
		LEFT JOIN users assignee ON assignee.ownership_tenant_id=oa.tenant_id AND assignee.id=oa.assignee_id AND NOT assignee.disabled
		WHERE ca.tenant_id=$1 AND a.tier<>'exception' AND ` + condition
}

func (s *NotificationSource) publishLifecycle(ctx context.Context, tx pgx.Tx, tenant shared.ID, typ notification.EventType, sourceKind, source string, f lifecycleSourceFact, at time.Time, reminder int, lead int64) error {
	title, summary := "Remediation SLA breached", "A finding exceeded its remediation deadline."
	data := map[string]any{"title": title, "summary": summary, "finding_id": f.finding, "engagement_id": f.engagement, "assessment_id": f.assessment, "deadline": f.deadline.UTC(), "tier": f.tier, "team_id": f.teamID, "assignee_user_id": f.assigneeID}
	vars := map[string]string{"severity": f.severity, "tier": f.tier, "deadline": f.deadline.UTC().Format(time.RFC3339), "engagement_name": f.engagementName, "finding_title": f.title, "reminder": strconv.Itoa(reminder)}
	if typ != notification.EventSLABreached {
		title, summary = "Risk acceptance", "A risk acceptance changed lifecycle state."
		data["title"], data["summary"] = title, summary
		data["acceptance_id"], data["acceptance_version"] = f.acceptance, f.version
		data["accepted_at"], data["expires_at"] = f.accepted.UTC(), f.expiry.UTC()
		if typ == notification.EventRiskAcceptanceExpiring {
			data["reminder"], data["lead_time_seconds"] = "expiry_warning", lead
			vars["lead_time_hours"] = strconv.FormatFloat(float64(lead)/3600, 'f', -1, 64)
			vars["reminder"] = "expiry_warning"
		}
		vars["accepted_at"], vars["expires_at"] = f.accepted.UTC().Format(time.RFC3339), f.expiry.UTC().Format(time.RFC3339)
	}
	if typ == notification.EventSLABreached {
		data["reminder"] = reminder
		data["episode_version"] = f.version
		data["breached_at"] = f.breachedAt.UTC()
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return appendNotificationSnapshotTx(ctx, tx, notification.SourceRecord{
		TenantID: tenant, SourceKind: sourceKind, SourceID: source, EventType: typ,
		EngagementID: f.engagement, Severity: shared.Severity(f.severity), OccurredAt: at.UTC(),
		Data: raw, SchemaVersion: 1, SubjectKind: "finding", SubjectID: f.finding.String(),
	}, vars)
}

func lifecycleBreachKey(f lifecycleSourceFact) string {
	return f.finding.String() + ":" + strconv.FormatInt(f.deadline.UTC().UnixMicro(), 10)
}

func lifecycleState(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind, id string) (string, bool, bool, error) {
	var fingerprint string
	var active bool
	err := tx.QueryRow(ctx, `SELECT fingerprint,active FROM notification_source_state WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenant, kind, id).Scan(&fingerprint, &active)
	if err == pgx.ErrNoRows {
		return "", false, false, nil
	}
	return fingerprint, active, err == nil, err
}

func upsertLifecycleState(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind, id, fingerprint string, active bool, observed time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,source_kind,source_id) DO UPDATE SET fingerprint=excluded.fingerprint,active=excluded.active,observed_at=excluded.observed_at`, tenant, kind, id, fingerprint, active, observed)
	return err
}

func lifecycleOrdinal(fingerprint string) int {
	n, err := strconv.Atoi(fingerprint)
	if err != nil {
		return -1
	}
	return n
}

func latestSLABreachReminder(deadline, now time.Time, max int) int {
	if now.Before(deadline) {
		return -1
	}
	ordinal := 0
	for n := 1; n <= max; n++ {
		if now.Before(reminderAt(deadline, n)) {
			break
		}
		ordinal = n
	}
	return ordinal
}

func reminderAt(deadline time.Time, ordinal int) time.Time {
	if ordinal <= 0 {
		return deadline.UTC()
	}
	return deadline.UTC().Add(time.Duration(1<<(ordinal-1)) * 24 * time.Hour)
}
