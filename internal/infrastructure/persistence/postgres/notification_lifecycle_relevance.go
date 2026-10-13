package postgres

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.NotificationLifecycleRelevance = (*NotificationRepository)(nil)

func (r *NotificationRepository) SLABreachCurrent(ctx context.Context, tenant shared.ID, engagement, finding string, deadline time.Time, version int) (bool, error) {
	return r.exists(ctx, tenant, `SELECT EXISTS (
		SELECT 1 FROM sla_current_assessments ca
		JOIN sla_assessments a ON a.tenant_id=ca.tenant_id AND a.id=ca.assessment_id
		JOIN sla_lifecycles l ON l.tenant_id=ca.tenant_id AND l.engagement_id=ca.engagement_id AND l.finding_id=ca.finding_id
		WHERE ca.tenant_id=$1 AND ca.engagement_id=$2 AND ca.finding_id=$3
		AND a.remediate_by=$4 AND a.remediate_by<=now() AND a.tier<>'exception'
		AND l.version>=$5 AND NOT EXISTS (
			SELECT 1 FROM sla_lifecycle_events closed
			WHERE closed.tenant_id=l.tenant_id AND closed.engagement_id=l.engagement_id
				AND closed.finding_id=l.finding_id AND closed.after_version>$5
				AND closed.to_status IN ('accepted_risk','remediated')
		)
		AND (l.status IN ('open','mitigating') OR (l.status='accepted_risk' AND l.acceptance_expires_at<=now()))
	)`, tenant, engagement, finding, deadline, version)
}

func (r *NotificationRepository) RiskAcceptanceCurrent(ctx context.Context, tenant shared.ID, engagement, finding string, version int, expiry time.Time, expiring bool) (bool, error) {
	return r.exists(ctx, tenant, `SELECT EXISTS (
		SELECT 1 FROM sla_lifecycles l
		WHERE l.tenant_id=$1 AND l.engagement_id=$2 AND l.finding_id=$3
		AND l.status='accepted_risk' AND l.version=$4 AND l.acceptance_expires_at=$5
		AND (($6 AND l.acceptance_expires_at>now()) OR (NOT $6 AND l.acceptance_expires_at<=now()))
	)`, tenant, engagement, finding, version, expiry, expiring)
}
