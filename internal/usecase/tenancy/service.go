// Package tenancy serves the tenant-wide presentation settings (#1359): the settings API reads and
// writes them, and the send-time render (#1365) and digests (#1377) read the parsed values through
// TenantLocale.
package tenancy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TenantLocale is what a renderer needs: the language and a loaded time zone.
type TenantLocale struct {
	Locale   domain.Locale
	Location *time.Location
}

// Update is the settings a tenant administrator saves. Revision is the revision the caller read;
// 0 saves a tenant's first settings.
type Update struct {
	DefaultLocale domain.Locale `json:"default_locale"`
	TimeZone      string        `json:"time_zone"`
	Revision      int           `json:"revision"`
}

// Service reads and writes tenant settings.
type Service struct {
	store ports.TenantSettingsStore
	audit ports.AuditLogger
	clock ports.Clock
}

// NewService wires the settings store, the audit log and the clock.
func NewService(store ports.TenantSettingsStore, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, errors.New("tenancy: store, audit log and clock are required")
	}
	return &Service{store: store, audit: audit, clock: clock}, nil
}

// Settings returns the tenant's saved settings, or the defaults when it never saved any.
func (s *Service) Settings(ctx context.Context, tenant shared.ID) (domain.Settings, error) {
	if tenant.IsZero() {
		return domain.Settings{}, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	saved, found, err := s.store.GetTenantSettings(ctx, tenant)
	if err != nil {
		return domain.Settings{}, err
	}
	if !found {
		return domain.Defaults(tenant), nil
	}
	return saved, nil
}

// Save validates and stores the settings, guarded by the revision the caller read, and records
// who changed what.
func (s *Service) Save(ctx context.Context, tenant shared.ID, actor string, in Update) (domain.Settings, error) {
	if actor == "" {
		return domain.Settings{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if in.Revision < 0 {
		return domain.Settings{}, fmt.Errorf("%w: revision must not be negative", shared.ErrValidation)
	}
	next := domain.Settings{
		TenantID:      tenant,
		DefaultLocale: in.DefaultLocale,
		TimeZone:      in.TimeZone,
		UpdatedAt:     s.clock.Now().UTC(),
		UpdatedBy:     actor,
	}
	if err := next.Validate(); err != nil {
		return domain.Settings{}, err
	}
	saved, err := s.store.SaveTenantSettings(ctx, next, in.Revision)
	if err != nil {
		return domain.Settings{}, err
	}
	err = s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "tenant.settings.updated",
		Target: tenant.String(),
		Metadata: map[string]string{
			"default_locale": string(saved.DefaultLocale),
			"time_zone":      saved.TimeZone,
			"revision":       fmt.Sprint(saved.Revision),
		},
		At: saved.UpdatedAt,
	})
	if err != nil {
		return domain.Settings{}, fmt.Errorf("record tenant settings change: %w", err)
	}
	return saved, nil
}

// TenantLocale returns the parsed locale and time zone for rendering. A tenant that never saved
// settings gets the defaults, and a stored zone this build can no longer load falls back to UTC,
// so the render path never fails because settings are missing. A store error is still returned.
func (s *Service) TenantLocale(ctx context.Context, tenant shared.ID) (TenantLocale, error) {
	settings, err := s.Settings(ctx, tenant)
	if err != nil {
		return TenantLocale{}, err
	}
	locale := settings.DefaultLocale
	if !locale.Valid() {
		locale = domain.DefaultLocale
	}
	location, err := domain.LoadTimeZone(settings.TimeZone)
	if err != nil {
		location = time.UTC
	}
	return TenantLocale{Locale: locale, Location: location}, nil
}
