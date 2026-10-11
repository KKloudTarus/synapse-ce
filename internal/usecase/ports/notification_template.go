package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// NotificationTemplateStore persists tenant message templates and their append-only versions
// (EPIC #1327 WS2, #1369). Every method is confined to one tenant: a template of another tenant
// reads as shared.ErrNotFound.
//
// Lifecycle. CreateNotificationTemplate stores a draft with version 1. AppendNotificationTemplateVersion
// adds the next version without changing what renders. ActivateNotificationTemplate makes a chosen
// version render (a rollback is activating an earlier version) and, in the same transaction,
// archives any other active template with the same key, so exactly one template per
// (tenant, event type, family, locale) is active; a concurrent activation that would leave two
// active is refused with shared.ErrConflict. ArchiveNotificationTemplate retires a template.
//
// Every mutation takes the head revision the caller read; a mismatch is shared.ErrConflict. Invalid
// input is shared.ErrValidation, and errors never echo template source.
type NotificationTemplateStore interface {
	CreateNotificationTemplate(ctx context.Context, t notification.Template, fields map[string]string) (notification.Template, notification.TemplateVersion, error)
	AppendNotificationTemplateVersion(ctx context.Context, u NotificationTemplateUpdate) (notification.Template, notification.TemplateVersion, error)
	// ActivateNotificationTemplate returns the activated head and the ID of the template it
	// archived, or "" when the key had no other active template.
	ActivateNotificationTemplate(ctx context.Context, c NotificationTemplateChange) (notification.Template, shared.ID, error)
	ArchiveNotificationTemplate(ctx context.Context, c NotificationTemplateChange) (notification.Template, error)

	GetNotificationTemplate(ctx context.Context, tenant, id shared.ID) (notification.Template, error)
	ListNotificationTemplates(ctx context.Context, tenant shared.ID, q NotificationTemplateQuery) ([]notification.Template, error)
	GetNotificationTemplateVersion(ctx context.Context, tenant, id shared.ID, version int) (notification.TemplateVersion, error)
	// ListNotificationTemplateVersions returns versions newest first, those below before when
	// before > 0, at most limit (clamped to MaxNotificationTemplateVersionPage).
	ListNotificationTemplateVersions(ctx context.Context, tenant, id shared.ID, before, limit int) ([]notification.TemplateVersion, error)
	// ActiveNotificationTemplate returns the active template for exactly key, with the version
	// that renders; found is false when the key has none. Wildcard and locale fallback belong to
	// the resolver (#1371), which calls this once per tier.
	ActiveNotificationTemplate(ctx context.Context, tenant shared.ID, key notification.TemplateKey) (t notification.Template, v notification.TemplateVersion, found bool, err error)
}

// NotificationTemplateUpdate appends a version. Name, when not empty, renames the template in the
// same write; the key cannot change.
type NotificationTemplateUpdate struct {
	TenantID         shared.ID
	ID               shared.ID
	Name             string
	Fields           map[string]string
	ExpectedRevision int
	Actor            string
	At               time.Time
}

// NotificationTemplateChange is a status change. Version selects the version to activate; zero
// means the latest. Archive ignores it.
type NotificationTemplateChange struct {
	TenantID         shared.ID
	ID               shared.ID
	Version          int
	ExpectedRevision int
	Actor            string
	At               time.Time
}

// NotificationTemplateQuery filters a template listing. Empty fields match everything. Results are
// ordered by ID; AfterID continues a previous page.
type NotificationTemplateQuery struct {
	EventType notification.EventType
	Family    notification.TemplateFamily
	Locale    tenancy.Locale
	Status    notification.TemplateStatus
	AfterID   shared.ID
	Limit     int
}

// Page bounds of the template store.
const (
	DefaultNotificationTemplatePage        = 100
	MaxNotificationTemplatePage            = 500
	DefaultNotificationTemplateVersionPage = 50
	MaxNotificationTemplateVersionPage     = 200
)

// Validate checks an update before a store touches the database. The fields depend on the
// template's family, so a store checks them with notification.ValidateTemplateFields once it has
// read the head.
func (u NotificationTemplateUpdate) Validate() error {
	if err := validateTemplateTarget(u.TenantID, u.ID, u.ExpectedRevision, u.Actor, u.At); err != nil {
		return err
	}
	if u.Name != "" {
		return notification.ValidateTemplateName(u.Name)
	}
	return nil
}

// Validate checks a status change before a store touches the database.
func (c NotificationTemplateChange) Validate() error {
	if c.Version < 0 {
		return fmt.Errorf("%w: template version must not be negative", shared.ErrValidation)
	}
	return validateTemplateTarget(c.TenantID, c.ID, c.ExpectedRevision, c.Actor, c.At)
}

func validateTemplateTarget(tenant, id shared.ID, expectedRevision int, actor string, at time.Time) error {
	if tenant.IsZero() {
		return fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	if err := notification.ValidateTemplateID(id); err != nil {
		return err
	}
	if expectedRevision <= 0 {
		return fmt.Errorf("%w: expected template revision is required", shared.ErrValidation)
	}
	if at.IsZero() {
		return fmt.Errorf("%w: change time is required", shared.ErrValidation)
	}
	return notification.ValidateTemplateActor(actor)
}

// ClampNotificationTemplatePage bounds a listing limit.
func ClampNotificationTemplatePage(limit, def, max int) int {
	if limit <= 0 {
		return def
	}
	if limit > max {
		return max
	}
	return limit
}
