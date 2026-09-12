package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// pollOwnership participates in the existing notification maintenance transaction.
// Publish's complete rule fan-out, delivery jobs and intent completion commit
// together. Crashes leave either the original pending intent or all deliveries;
// the source key remains stable across retries and does not depend on a channel.
func (s *NotificationSource) pollOwnership(ctx context.Context, tx pgx.Tx, tenant shared.ID, limit int) (int, error) {
	// Select only transport metadata: full decision evidence may be several MiB.
	rows, err := tx.Query(ctx, `SELECT i.id,d.id,d.engagement_id,d.finding_id,d.created_at,
		d.payload->>'actor',d.payload->'result'->>'reason',
		COALESCE(d.payload->'before'->>'team_id',''),COALESCE(d.payload->'after'->>'team_id',''),
		COALESCE(d.payload->'before'->>'assignee_id',''),COALESCE(d.payload->'after'->>'assignee_id','')
		FROM ownership_intents i
		JOIN ownership_decisions d ON d.tenant_id=i.tenant_id AND d.engagement_id=i.engagement_id
		AND d.finding_id=i.finding_id AND d.id=i.decision_id
		WHERE i.tenant_id=$1 AND i.kind='notification' AND i.state='pending'
		ORDER BY i.created_at,i.id LIMIT $2 FOR UPDATE OF i SKIP LOCKED`, tenant, ownershipLimit(limit))
	if err != nil {
		return 0, err
	}
	type item struct {
		id   shared.ID
		at   time.Time
		data notification.OwnershipChanged
	}
	var items []item
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.id, &v.data.DecisionID, &v.data.EngagementID, &v.data.FindingID, &v.at,
			&v.data.Actor, &v.data.Reason, &v.data.OldTeamID, &v.data.NewTeamID,
			&v.data.OldAssigneeID, &v.data.NewAssigneeID); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, v := range items {
		v.data.Title = "Finding ownership changed"
		v.data.Summary = "A finding's team or assignee changed."
		data, err := json.Marshal(v.data)
		if err != nil {
			return 0, err
		}
		e := notification.Event{TenantID: tenant, ID: stableID(tenant.String(), "ownership_decision", v.data.DecisionID.String()),
			Type: notification.EventOwnershipChanged, SourceKind: "ownership_decision", SourceID: v.data.DecisionID.String(),
			EngagementID: v.data.EngagementID, SchemaVersion: 1, OccurredAt: v.at, Data: data}
		if _, err := s.repo.publishTx(ctx, tx, e, ""); err != nil {
			return 0, err
		}
		if err := ownershipCAS(tx.Exec(ctx, `UPDATE ownership_intents SET state='processed'
			WHERE tenant_id=$1 AND id=$2 AND kind='notification' AND state='pending'`, tenant, v.id)); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}
