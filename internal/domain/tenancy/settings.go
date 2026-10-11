// Package tenancy holds tenant-wide presentation settings: the language and the time zone that
// message templates and digests render in (#1359).
//
// The locale is a closed set so a template lookup can never miss. The time zone is an IANA name,
// stored as a name rather than an offset, so daylight saving is resolved at render time.
//
// The package does not embed the IANA database itself. The binaries that validate or render zones
// (synapse-api and synapse-worker) import time/tzdata, so the CLI and the agents do not carry it.
package tenancy

import (
	"fmt"
	"regexp"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Locale is a language a tenant's messages render in.
type Locale string

const (
	LocaleEnglish    Locale = "en"
	LocaleVietnamese Locale = "vi"
)

// Defaults for a tenant that never saved settings. Reading them is never an error.
const (
	DefaultLocale   = LocaleEnglish
	DefaultTimeZone = "UTC"
)

// Locales lists every supported locale in display order.
func Locales() []Locale { return []Locale{LocaleEnglish, LocaleVietnamese} }

// Valid reports whether l is a supported locale.
func (l Locale) Valid() bool { return l == LocaleEnglish || l == LocaleVietnamese }

// timeZoneShape bounds a zone name before it reaches time.LoadLocation, which also reads files for
// some inputs. It matches the CHECK on tenant_settings.time_zone.
var timeZoneShape = regexp.MustCompile(`^[A-Za-z0-9_+/-]{1,64}$`)

// LoadTimeZone parses an IANA zone name. It rejects the empty name and "Local", which
// time.LoadLocation accepts but which mean the server's zone rather than a tenant's choice.
func LoadTimeZone(name string) (*time.Location, error) {
	if name == "Local" || !timeZoneShape.MatchString(name) {
		return nil, fmt.Errorf("%w: time zone %q is not an IANA zone name", shared.ErrValidation, name)
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("%w: unknown time zone %q", shared.ErrValidation, name)
	}
	return location, nil
}

// Settings is one tenant's saved presentation settings. Revision guards concurrent edits; zero
// means the tenant has never saved them.
type Settings struct {
	TenantID      shared.ID
	DefaultLocale Locale
	TimeZone      string
	Revision      int
	UpdatedAt     time.Time
	UpdatedBy     string
}

// Defaults returns the settings of a tenant that never saved any.
func Defaults(tenant shared.ID) Settings {
	return Settings{TenantID: tenant, DefaultLocale: DefaultLocale, TimeZone: DefaultTimeZone}
}

// Validate checks the locale and loads the zone, so a saved zone is one this build can render in.
func (s Settings) Validate() error {
	if s.TenantID.IsZero() {
		return fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	if !s.DefaultLocale.Valid() {
		return fmt.Errorf("%w: default locale must be one of en, vi", shared.ErrValidation)
	}
	_, err := LoadTimeZone(s.TimeZone)
	return err
}
