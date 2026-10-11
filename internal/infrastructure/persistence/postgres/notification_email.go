package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationEmailSettingsStore persists tenant-scoped relay metadata and its
// sealed transport credentials. Channel rows never contain a relay secret.
type NotificationEmailSettingsStore struct{ pool *pgxpool.Pool }

func NewNotificationEmailSettingsStore(pool *pgxpool.Pool) *NotificationEmailSettingsStore {
	return &NotificationEmailSettingsStore{pool: pool}
}

var _ ports.NotificationEmailSettingsStore = (*NotificationEmailSettingsStore)(nil)

func (s *NotificationEmailSettingsStore) GetNotificationEmailSettings(ctx context.Context, tenant shared.ID) (ports.NotificationEmailSettings, error) {
	out := ports.NotificationEmailSettings{TenantID: tenant}
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT revision,configured,host,port,sender,auth_mode,sealed,updated_at,updated_by
			FROM notification_email_settings WHERE tenant_id=$1`, tenant).Scan(&out.Revision, &out.Configured, &out.Host, &out.Port, &out.From, &out.AuthMode, &out.Sealed, &out.UpdatedAt, &out.UpdatedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return ports.NotificationEmailSettings{}, fmt.Errorf("get notification email settings: %w", err)
	}
	return out, nil
}

func (s *NotificationEmailSettingsStore) PutNotificationEmailSettings(ctx context.Context, in ports.NotificationEmailSettings) (ports.NotificationEmailSettings, error) {
	if !in.Configured && in.AuthMode == "" {
		in.AuthMode = "none"
	}
	err := WithTenant(ctx, s.pool, in.TenantID.String(), func(tx pgx.Tx) error {
		var tag pgconnCommandTag
		if in.Revision == 1 {
			command, err := tx.Exec(ctx, `INSERT INTO notification_email_settings(tenant_id,revision,configured,host,port,sender,auth_mode,sealed,updated_at,updated_by)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id) DO NOTHING`, in.TenantID, in.Revision, in.Configured, in.Host, in.Port, in.From, in.AuthMode, in.Sealed, in.UpdatedAt, in.UpdatedBy)
			if err != nil {
				return err
			}
			tag = pgconnCommandTag{affected: command.RowsAffected()}
		} else {
			command, err := tx.Exec(ctx, `UPDATE notification_email_settings SET configured=$3,host=$4,port=$5,sender=$6,auth_mode=$7,sealed=$8,updated_at=$9,updated_by=$10,revision=$2
				WHERE tenant_id=$1 AND revision=$2-1`, in.TenantID, in.Revision, in.Configured, in.Host, in.Port, in.From, in.AuthMode, in.Sealed, in.UpdatedAt, in.UpdatedBy)
			if err != nil {
				return err
			}
			tag = pgconnCommandTag{affected: command.RowsAffected()}
		}
		if tag.affected != 1 {
			return fmt.Errorf("notification email settings revision is stale: %w", shared.ErrConflict)
		}
		return nil
	})
	if err != nil {
		return ports.NotificationEmailSettings{}, fmt.Errorf("put notification email settings: %w", err)
	}
	in.Sealed = ""
	return in, nil
}

// pgconnCommandTag keeps this adapter independent of a pgconn import solely to
// check RowsAffected in the two mutually exclusive statements above.
type pgconnCommandTag struct{ affected int64 }

func (s *NotificationEmailSettingsStore) ListNotificationEmailDomains(ctx context.Context, tenant shared.ID) ([]string, error) {
	result := make([]string, 0)
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT domain FROM notification_email_domains WHERE tenant_id=$1 ORDER BY domain`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var domain string
			if err := rows.Scan(&domain); err != nil {
				return err
			}
			result = append(result, domain)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list notification email domains: %w", err)
	}
	return result, nil
}

func (s *NotificationEmailSettingsStore) AddNotificationEmailDomain(ctx context.Context, tenant shared.ID, domain string, at time.Time) error {
	return WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_email_domains(tenant_id,domain,created_at) VALUES($1,$2,$3) ON CONFLICT(tenant_id,domain) DO NOTHING`, tenant, domain, at)
		return err
	})
}

func (s *NotificationEmailSettingsStore) DeleteNotificationEmailDomain(ctx context.Context, tenant shared.ID, domain string) error {
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM notification_email_domains WHERE tenant_id=$1 AND domain=$2`, tenant, domain)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrNotFound
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete notification email domain: %w", err)
	}
	return nil
}

func (s *NotificationEmailSettingsStore) VerifiedNotificationEmailRecipients(ctx context.Context, tenant shared.ID, recipients []string) (map[string]bool, error) {
	found := make(map[string]bool, len(recipients))
	if len(recipients) == 0 {
		return found, nil
	}
	normalizedRecipients := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		normalized, err := userdom.NormalizeContactEmail(recipient)
		if err != nil {
			return nil, fmt.Errorf("normalize notification email recipient: %w", err)
		}
		normalizedRecipients = append(normalizedRecipients, normalized)
	}
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT c.value
			FROM user_contacts c
			JOIN users u ON u.ownership_tenant_id=c.tenant_id AND u.id=c.user_id AND NOT u.disabled
			JOIN identity_memberships m ON m.tenant_id=c.tenant_id AND m.legacy_user_id=c.user_id AND m.state='active'
			WHERE c.tenant_id=$1 AND c.kind='email' AND c.verified_at IS NOT NULL AND c.value=ANY($2)`, tenant, normalizedRecipients)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				return err
			}
			normalized, err := userdom.NormalizeContactEmail(value)
			if err != nil {
				return fmt.Errorf("normalize stored notification email recipient: %w", err)
			}
			found[normalized] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("check verified notification email recipients: %w", err)
	}
	return found, nil
}
