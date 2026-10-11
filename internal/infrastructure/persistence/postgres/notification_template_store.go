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

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.NotificationTemplateStore = (*NotificationTemplateStore)(nil)

// NotificationTemplateStore is the PostgreSQL ports.NotificationTemplateStore over
// notification_templates and notification_template_versions (0195). Every statement runs inside
// WithTenant, so forced RLS confines it to the caller's tenant; the one-active index and the
// append-only trigger back the rules the store checks first.
type NotificationTemplateStore struct{ pool *pgxpool.Pool }

// NewNotificationTemplateStore returns a store over pool.
func NewNotificationTemplateStore(pool *pgxpool.Pool) *NotificationTemplateStore {
	return &NotificationTemplateStore{pool: pool}
}

const templateColumns = `tenant_id, id, name, event_type, family, locale, status, latest_version,
	COALESCE(active_version, 0), revision, created_at, created_by, updated_at, updated_by`

const versionColumns = `tenant_id, template_id, version, fields, checksum, created_at, created_by`

func (s *NotificationTemplateStore) CreateNotificationTemplate(ctx context.Context, t notification.Template, fields map[string]string) (notification.Template, notification.TemplateVersion, error) {
	if err := t.ValidateNew(); err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	if err := notification.ValidateTemplateFields(t.Family, fields); err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	t.Status, t.LatestVersion, t.ActiveVersion, t.Revision = notification.TemplateDraft, 1, 0, 1
	t.UpdatedAt, t.UpdatedBy = t.CreatedAt, t.CreatedBy
	v := newTemplateVersion(t.TenantID, t.ID, 1, fields, t.CreatedAt, t.CreatedBy)
	encoded, err := json.Marshal(v.Fields)
	if err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	err = WithTenant(ctx, s.pool, t.TenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO notification_templates(tenant_id, id, name, event_type, family, locale, status,
				latest_version, active_version, revision, created_at, created_by, updated_at, updated_by)
			VALUES($1, $2, $3, $4, $5, $6, 'draft', 1, NULL, 1, $7, $8, $7, $8) ON CONFLICT (tenant_id, id) DO NOTHING`,
			t.TenantID, t.ID, t.Name, string(t.EventType), string(t.Family), string(t.Locale), t.CreatedAt, t.CreatedBy)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: notification template %s already exists", shared.ErrConflict, t.ID)
		}
		return insertTemplateVersion(ctx, tx, v, encoded)
	})
	if err != nil {
		return notification.Template{}, notification.TemplateVersion{}, templateStoreError("create notification template", err)
	}
	return t, v, nil
}

func (s *NotificationTemplateStore) AppendNotificationTemplateVersion(ctx context.Context, u ports.NotificationTemplateUpdate) (notification.Template, notification.TemplateVersion, error) {
	if err := u.Validate(); err != nil {
		return notification.Template{}, notification.TemplateVersion{}, err
	}
	var head notification.Template
	var v notification.TemplateVersion
	err := WithTenant(ctx, s.pool, u.TenantID.String(), func(tx pgx.Tx) error {
		var err error
		if head, err = lockTemplate(ctx, tx, u.TenantID, u.ID, u.ExpectedRevision); err != nil {
			return err
		}
		if err := notification.ValidateTemplateFields(head.Family, u.Fields); err != nil {
			return err
		}
		v = newTemplateVersion(u.TenantID, u.ID, head.LatestVersion+1, u.Fields, u.At, u.Actor)
		encoded, err := json.Marshal(v.Fields)
		if err != nil {
			return err
		}
		if err := insertTemplateVersion(ctx, tx, v, encoded); err != nil {
			return err
		}
		name := head.Name
		if u.Name != "" {
			name = u.Name
		}
		head, err = scanTemplate(tx.QueryRow(ctx, `UPDATE notification_templates
			SET name=$3, latest_version=$4, revision=revision+1, updated_at=$5, updated_by=$6
			WHERE tenant_id=$1 AND id=$2 RETURNING `+templateColumns, u.TenantID, u.ID, name, v.Version, u.At, u.Actor))
		return err
	})
	if err != nil {
		return notification.Template{}, notification.TemplateVersion{}, templateStoreError("append notification template version", err)
	}
	return head, v, nil
}

func (s *NotificationTemplateStore) ActivateNotificationTemplate(ctx context.Context, c ports.NotificationTemplateChange) (notification.Template, shared.ID, error) {
	if err := c.Validate(); err != nil {
		return notification.Template{}, "", err
	}
	var head notification.Template
	var archived shared.ID
	err := WithTenant(ctx, s.pool, c.TenantID.String(), func(tx pgx.Tx) error {
		var err error
		if head, err = lockTemplate(ctx, tx, c.TenantID, c.ID, c.ExpectedRevision); err != nil {
			return err
		}
		version := c.Version
		if version == 0 {
			version = head.LatestVersion
		}
		if version > head.LatestVersion {
			return fmt.Errorf("notification template version %d: %w", version, shared.ErrNotFound)
		}
		// Retire the key's current active template first, so the unique index sees one active row.
		err = tx.QueryRow(ctx, `UPDATE notification_templates
			SET status='archived', revision=revision+1, updated_at=$6, updated_by=$7
			WHERE tenant_id=$1 AND event_type=$2 AND family=$3 AND locale=$4 AND status='active' AND id<>$5
			RETURNING id`, c.TenantID, string(head.EventType), string(head.Family), string(head.Locale), c.ID, c.At, c.Actor).Scan(&archived)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		head, err = scanTemplate(tx.QueryRow(ctx, `UPDATE notification_templates
			SET status='active', active_version=$3, revision=revision+1, updated_at=$4, updated_by=$5
			WHERE tenant_id=$1 AND id=$2 RETURNING `+templateColumns, c.TenantID, c.ID, version, c.At, c.Actor))
		return err
	})
	if err != nil {
		return notification.Template{}, "", templateStoreError("activate notification template", err)
	}
	return head, archived, nil
}

func (s *NotificationTemplateStore) ArchiveNotificationTemplate(ctx context.Context, c ports.NotificationTemplateChange) (notification.Template, error) {
	if err := c.Validate(); err != nil {
		return notification.Template{}, err
	}
	var head notification.Template
	err := WithTenant(ctx, s.pool, c.TenantID.String(), func(tx pgx.Tx) error {
		var err error
		if _, err = lockTemplate(ctx, tx, c.TenantID, c.ID, c.ExpectedRevision); err != nil {
			return err
		}
		head, err = scanTemplate(tx.QueryRow(ctx, `UPDATE notification_templates
			SET status='archived', revision=revision+1, updated_at=$3, updated_by=$4
			WHERE tenant_id=$1 AND id=$2 RETURNING `+templateColumns, c.TenantID, c.ID, c.At, c.Actor))
		return err
	})
	if err != nil {
		return notification.Template{}, templateStoreError("archive notification template", err)
	}
	return head, nil
}

func (s *NotificationTemplateStore) GetNotificationTemplate(ctx context.Context, tenant, id shared.ID) (notification.Template, error) {
	var head notification.Template
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		head, err = scanTemplate(tx.QueryRow(ctx, `SELECT `+templateColumns+` FROM notification_templates WHERE tenant_id=$1 AND id=$2`, tenant, id))
		return err
	})
	if err != nil {
		return notification.Template{}, templateStoreError("read notification template", err)
	}
	return head, nil
}

func (s *NotificationTemplateStore) ListNotificationTemplates(ctx context.Context, tenant shared.ID, q ports.NotificationTemplateQuery) ([]notification.Template, error) {
	limit := ports.ClampNotificationTemplatePage(q.Limit, ports.DefaultNotificationTemplatePage, ports.MaxNotificationTemplatePage)
	var out []notification.Template
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+templateColumns+` FROM notification_templates
			WHERE tenant_id=$1 AND ($2='' OR event_type=$2) AND ($3='' OR family=$3) AND ($4='' OR locale=$4)
			AND ($5='' OR status=$5) AND id > $6
			ORDER BY id LIMIT $7`,
			tenant, string(q.EventType), string(q.Family), string(q.Locale), string(q.Status), q.AfterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			head, err := scanTemplate(rows)
			if err != nil {
				return err
			}
			out = append(out, head)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, templateStoreError("list notification templates", err)
	}
	return out, nil
}

func (s *NotificationTemplateStore) GetNotificationTemplateVersion(ctx context.Context, tenant, id shared.ID, version int) (notification.TemplateVersion, error) {
	var v notification.TemplateVersion
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		v, err = scanTemplateVersion(tx.QueryRow(ctx, `SELECT `+versionColumns+` FROM notification_template_versions
			WHERE tenant_id=$1 AND template_id=$2 AND version=$3`, tenant, id, version))
		return err
	})
	if err != nil {
		return notification.TemplateVersion{}, templateStoreError("read notification template version", err)
	}
	return v, nil
}

func (s *NotificationTemplateStore) ListNotificationTemplateVersions(ctx context.Context, tenant, id shared.ID, before, limit int) ([]notification.TemplateVersion, error) {
	limit = ports.ClampNotificationTemplatePage(limit, ports.DefaultNotificationTemplateVersionPage, ports.MaxNotificationTemplateVersionPage)
	out := []notification.TemplateVersion{}
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notification_templates WHERE tenant_id=$1 AND id=$2)`, tenant, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return pgx.ErrNoRows
		}
		rows, err := tx.Query(ctx, `SELECT `+versionColumns+` FROM notification_template_versions
			WHERE tenant_id=$1 AND template_id=$2 AND ($3 <= 0 OR version < $3)
			ORDER BY version DESC LIMIT $4`, tenant, id, before, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanTemplateVersion(rows)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, templateStoreError("list notification template versions", err)
	}
	return out, nil
}

func (s *NotificationTemplateStore) ActiveNotificationTemplate(ctx context.Context, tenant shared.ID, key notification.TemplateKey) (notification.Template, notification.TemplateVersion, bool, error) {
	var head notification.Template
	var v notification.TemplateVersion
	found := false
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		head, err = scanTemplate(tx.QueryRow(ctx, `SELECT `+templateColumns+` FROM notification_templates
			WHERE tenant_id=$1 AND event_type=$2 AND family=$3 AND locale=$4 AND status='active'`,
			tenant, string(key.EventType), string(key.Family), string(key.Locale)))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		v, err = scanTemplateVersion(tx.QueryRow(ctx, `SELECT `+versionColumns+` FROM notification_template_versions
			WHERE tenant_id=$1 AND template_id=$2 AND version=$3`, tenant, head.ID, head.ActiveVersion))
		found = err == nil
		return err
	})
	if err != nil {
		return notification.Template{}, notification.TemplateVersion{}, false, templateStoreError("resolve notification template", err)
	}
	if !found {
		return notification.Template{}, notification.TemplateVersion{}, false, nil
	}
	return head, v, true, nil
}

// lockTemplate reads the head FOR UPDATE and checks the caller's revision.
func lockTemplate(ctx context.Context, tx pgx.Tx, tenant, id shared.ID, expectedRevision int) (notification.Template, error) {
	head, err := scanTemplate(tx.QueryRow(ctx, `SELECT `+templateColumns+` FROM notification_templates
		WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id))
	if err != nil {
		return notification.Template{}, err
	}
	if head.Revision != expectedRevision {
		return notification.Template{}, fmt.Errorf("%w: notification template revision is stale", shared.ErrConflict)
	}
	return head, nil
}

func insertTemplateVersion(ctx context.Context, tx pgx.Tx, v notification.TemplateVersion, encoded []byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO notification_template_versions(tenant_id, template_id, version, fields, checksum, created_at, created_by)
		VALUES($1, $2, $3, $4, $5, $6, $7)`, v.TenantID, v.TemplateID, v.Version, encoded, v.Checksum, v.CreatedAt, v.CreatedBy)
	return err
}

func newTemplateVersion(tenant, id shared.ID, version int, fields map[string]string, at time.Time, actor string) notification.TemplateVersion {
	copied := notification.CloneFields(fields)
	return notification.TemplateVersion{TenantID: tenant, TemplateID: id, Version: version, Fields: copied,
		Checksum: notification.TemplateChecksum(copied), CreatedAt: at, CreatedBy: actor}
}

func scanTemplate(row pgx.Row) (notification.Template, error) {
	var t notification.Template
	var eventType, family, locale, status string
	err := row.Scan(&t.TenantID, &t.ID, &t.Name, &eventType, &family, &locale, &status, &t.LatestVersion,
		&t.ActiveVersion, &t.Revision, &t.CreatedAt, &t.CreatedBy, &t.UpdatedAt, &t.UpdatedBy)
	if err != nil {
		return notification.Template{}, err
	}
	t.EventType, t.Family, t.Locale = notification.EventType(eventType), notification.TemplateFamily(family), tenancy.Locale(locale)
	t.Status = notification.TemplateStatus(status)
	return t, nil
}

func scanTemplateVersion(row pgx.Row) (notification.TemplateVersion, error) {
	var v notification.TemplateVersion
	var raw []byte
	if err := row.Scan(&v.TenantID, &v.TemplateID, &v.Version, &raw, &v.Checksum, &v.CreatedAt, &v.CreatedBy); err != nil {
		return notification.TemplateVersion{}, err
	}
	if err := json.Unmarshal(raw, &v.Fields); err != nil {
		return notification.TemplateVersion{}, fmt.Errorf("decode notification template fields: %w", err)
	}
	return v, nil
}

// templateStoreError maps a missing row to shared.ErrNotFound and a lost race on the one-active
// index or the primary key to shared.ErrConflict. Database messages name constraints, never
// template source, so wrapping them leaks no content.
func templateStoreError(op string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", op, shared.ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if pgErr.ConstraintName == "notification_templates_one_active" {
			return fmt.Errorf("%s: %w: another template is already active for this key", op, shared.ErrConflict)
		}
		return fmt.Errorf("%s: %w: the template changed concurrently", op, shared.ErrConflict)
	}
	if errors.As(err, &pgErr) && (pgErr.Code == "40001" || pgErr.Code == "40P01") {
		return fmt.Errorf("%s: %w: the template changed concurrently", op, shared.ErrConflict)
	}
	return fmt.Errorf("%s: %w", op, err)
}
