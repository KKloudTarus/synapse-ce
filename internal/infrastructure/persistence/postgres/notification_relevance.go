package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The source facts the notification worker re-checks before a send (ports.NotificationRelevance).
// Which event asks which fact is decided by the event builders in the notification use case.

func (r *NotificationRepository) ScanJobSucceeded(ctx context.Context, tenant shared.ID, scanJobID string) (bool, error) {
	return r.exists(ctx, tenant, `SELECT EXISTS(
		SELECT 1 FROM scan_jobs j
		JOIN engagements e ON e.id=j.engagement_id
		WHERE e.tenant_id=$1 AND j.id=$2 AND j.status='succeeded'
			AND j.finished_at IS NOT NULL
	)`, tenant, scanJobID)
}

func (r *NotificationRepository) SLAReminderDue(ctx context.Context, tenant shared.ID, reminder ports.SLAReminder) (bool, error) {
	return r.exists(ctx, tenant, `SELECT EXISTS(SELECT 1 FROM sla_current_assessments ca JOIN sla_assessments a ON a.tenant_id=ca.tenant_id AND a.id=ca.assessment_id JOIN sla_lifecycles l ON l.tenant_id=ca.tenant_id AND l.engagement_id=ca.engagement_id AND l.finding_id=ca.finding_id WHERE ca.tenant_id=$1 AND ca.engagement_id=$2 AND ca.finding_id=$3 AND ca.assessment_id=$4 AND a.remediate_by=$5 AND a.remediate_by>now() AND a.tier<>'exception' AND l.status IN ('open','mitigating'))`,
		tenant, reminder.EngagementID, reminder.FindingID, reminder.AssessmentID, reminder.Deadline)
}

func (r *NotificationRepository) FleetAgentLastSeen(ctx context.Context, tenant shared.ID, agentID string, lastSeen time.Time) (bool, error) {
	return r.exists(ctx, tenant, `SELECT EXISTS(SELECT 1 FROM fleet_agents WHERE tenant_id=$1 AND id=$2 AND state IN ('active','stale') AND last_seen_at=$3)`, tenant, agentID, lastSeen)
}

func (r *NotificationRepository) exists(ctx context.Context, tenant shared.ID, query string, args ...any) (bool, error) {
	var found bool
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, args...).Scan(&found)
	})
	return found, err
}
