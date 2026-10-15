package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NotificationLifecycleFactsReader struct{ pool *pgxpool.Pool }

var _ ports.NotificationLifecycleFactsReader = (*NotificationLifecycleFactsReader)(nil)
var _ ports.NotificationApproverFactsReader = (*NotificationLifecycleFactsReader)(nil)

func NewNotificationLifecycleFactsReader(pool *pgxpool.Pool) *NotificationLifecycleFactsReader {
	return &NotificationLifecycleFactsReader{pool: pool}
}

func (r *NotificationLifecycleFactsReader) SnapshotNotificationLifecycleFacts(ctx context.Context, tenant, engagement shared.ID, actor string) (facts ports.NotificationLifecycleFacts, err error) {
	if current, ok := shared.TenantFrom(ctx); ok && shared.TenantOrDefault(current) != shared.TenantOrDefault(tenant) {
		return facts, fmt.Errorf("%w: notification facts tenant mismatch", shared.ErrValidation)
	}
	err = WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		if !engagement.IsZero() {
			if err := tx.QueryRow(ctx, `SELECT name FROM engagements WHERE tenant_id=$1 AND id=$2`, tenant, engagement).Scan(&facts.EngagementName); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT u.id FROM notification_engagement_settings s JOIN users u ON u.ownership_tenant_id=s.tenant_id AND u.id=s.lead_user_id WHERE s.tenant_id=$1 AND s.engagement_id=$2 AND NOT u.disabled AND u.role=ANY($3)`, tenant, engagement, humanNotificationRoles).Scan(&facts.LeadUserID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if actor = strings.TrimSpace(actor); actor != "" {
			if err := tx.QueryRow(ctx, `SELECT id,name FROM users WHERE ownership_tenant_id=$1 AND id=$2 AND NOT disabled AND role=ANY($3)`, tenant, actor, humanNotificationRoles).Scan(&facts.ActorUserID, &facts.ActorName); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		return nil
	})
	return facts, err
}

func (r *NotificationLifecycleFactsReader) SnapshotNotificationApprovers(ctx context.Context, tenant shared.ID) (ids []shared.ID, err error) {
	if current, ok := shared.TenantFrom(ctx); ok && shared.TenantOrDefault(current) != shared.TenantOrDefault(tenant) {
		return nil, fmt.Errorf("%w: notification facts tenant mismatch", shared.ErrValidation)
	}
	err = WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id FROM users WHERE ownership_tenant_id=$1 AND NOT disabled AND role IN ('admin','reviewer') ORDER BY id`, tenant)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id shared.ID
			if e := rows.Scan(&id); e != nil {
				return e
			}
			ids = append(ids, id)
		}
		if e := rows.Err(); e != nil {
			return e
		}
		return nil
	})
	return ids, err
}
