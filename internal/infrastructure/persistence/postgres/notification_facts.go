package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Source facts (#1344). The poller reads what an event says about its subject from the source rows
// at projection (the names its variables show, and everything the data needs when a captured record
// carries only its identity), and hands it to the event builder as context variables. The builder composes the event data and the template variables;
// these queries only read. A NULL leaves the fact out, so the builder can tell "missing" from
// "empty".

type factQuery struct {
	sql   string
	names []string
}

// capturedFactQueries read the subject of each captured source kind by its source ID.
var capturedFactQueries = map[string]factQuery{
	"scan_job": {
		sql: `SELECT j.id,j.kind,j.target,e.name,j.notification_snapshot::text FROM scan_jobs j JOIN engagements e ON e.id=j.engagement_id
			WHERE e.tenant_id=$1 AND j.id=$2`,
		names: []string{"scan_id", "scan_kind", "scan_target", "engagement_name", "notification_snapshot"},
	},
	"project_analysis_gate": {
		sql: `SELECT a.id,a.project_id,p.name,
			(SELECT count(*) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(a.payload->'gate'->'Results')='array' THEN a.payload->'gate'->'Results' ELSE '[]'::jsonb END) r
				WHERE r->>'Passed' IS DISTINCT FROM 'true')::text
			FROM project_analyses a LEFT JOIN projects p ON p.id=a.project_id WHERE a.tenant_id=$1 AND a.id=$2`,
		names: []string{"analysis_id", "project_id", "project_name", "failed_conditions"},
	},
	"incident": {
		sql: `SELECT ie.incident_id,ie.asset_id,ie.payload->>'Title',fa.name,eg.name FROM incident_events ie
			LEFT JOIN fleet_assets fa ON fa.tenant_id=ie.tenant_id AND fa.id=ie.asset_id
			LEFT JOIN engagements eg ON eg.tenant_id=ie.tenant_id AND eg.id=ie.payload->>'EngagementID'
			WHERE ie.tenant_id=$1 AND ie.incident_id=$2 AND ie.kind='created' ORDER BY ie.seq LIMIT 1`,
		names: []string{"incident_id", "asset_id", "incident_title", "asset_name", "engagement_name"},
	},
}

// capturedFacts reads the facts of one captured record. A source row that no longer exists yields
// no facts: the builder then falls back to the identity it has.
func capturedFacts(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind, sourceID string) (map[string]string, error) {
	q, ok := capturedFactQueries[kind]
	if !ok {
		return nil, nil
	}
	return readFacts(tx.QueryRow(ctx, q.sql, tenant, sourceID), q.names)
}

func readFacts(row pgx.Row, names []string) (map[string]string, error) {
	values := make([]*string, len(names))
	dest := make([]any, len(names))
	for i := range values {
		dest[i] = &values[i]
	}
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	facts := make(map[string]string, len(names))
	for i, name := range names {
		if values[i] != nil {
			facts[name] = *values[i]
		}
	}
	return facts, nil
}

// withFacts adds facts to an event's context variables. Variables the producer already set win.
func withFacts(raw json.RawMessage, facts map[string]string) (json.RawMessage, error) {
	if len(facts) == 0 {
		return raw, nil
	}
	c, err := notification.DecodeTemplateContext(raw)
	if err != nil {
		return nil, err
	}
	mergeFacts(&c, facts)
	return c.Encode()
}

func mergeFacts(c *notification.TemplateContext, facts map[string]string) {
	for name, value := range facts {
		if name == "notification_snapshot" {
			// This internal comparison record may contain 10,000 stable keys. It
			// is consumed below as a typed summary and must never enter template
			// variables or the event context.
			continue
		}
		if _, set := c.Vars[name]; !set {
			c.Vars[name] = value
		}
	}
}

// withScanFacts combines source facts and the terminal summary before encoding.
// The internal summary can contain 10,000 comparison keys, so an intermediate
// generic context encoding would exceed the public context budget.
func withScanFacts(raw json.RawMessage, facts map[string]string) (json.RawMessage, error) {
	c, err := notification.DecodeTemplateContext(raw)
	if err != nil {
		return nil, err
	}
	mergeFacts(&c, facts)
	if _, set := c.Vars["target"]; !set {
		// scan_target is an internal hydration fact and is not catalogued. Keep a
		// catalogued equivalent until the event builder turns it into display text.
		c.Vars["target"] = facts["scan_target"]
	}
	return withScanSummaryContext(c, facts["notification_snapshot"])
}

func scanSummaryPresent(encoded string) (bool, error) {
	if encoded == "" || encoded == "null" {
		return false, nil
	}
	var summary notification.ScanSummary
	if err := json.Unmarshal([]byte(encoded), &summary); err != nil {
		return false, err
	}
	return summary.TargetKey != "", nil
}

func withScanSummaryContext(c notification.TemplateContext, encoded string) (json.RawMessage, error) {
	if encoded == "" || encoded == "null" {
		return scanCompletedSnapshot(c)
	}
	var summary notification.ScanSummary
	if err := json.Unmarshal([]byte(encoded), &summary); err != nil {
		return nil, err
	}
	if summary.TargetKey == "" {
		return scanCompletedSnapshot(c) // legacy scan rows predate the terminal snapshot.
	}
	values, lists := summary.TemplateValues()
	for name, value := range values {
		// The terminal snapshot is authoritative for the aggregate facts of the
		// completed scan, including a stale source record that carried old counts.
		c.Vars[name] = value
	}
	if len(lists) != 0 {
		if c.Lists == nil {
			c.Lists = map[string][]map[string]string{}
		}
		for name, items := range lists {
			if _, exists := c.Lists[name]; !exists {
				c.Lists[name] = items
			}
		}
	}
	return scanCompletedSnapshot(c)
}

func scanCompletedSnapshot(context notification.TemplateContext) (json.RawMessage, error) {
	spec, ok := notification.LookupEvent(notification.EventScanCompleted)
	if !ok {
		return nil, errors.New("scan.completed event specification is unavailable")
	}
	return spec.SnapshotWithLists(context.Vars, context.Lists).Encode()
}
