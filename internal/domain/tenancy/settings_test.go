package tenancy

import (
	"errors"
	"testing"
	// The package leaves the IANA database to the binaries; tests embed it so they pass on any host.
	_ "time/tzdata"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDefaultsValidate(t *testing.T) {
	got := Defaults("tenant")
	if got.DefaultLocale != LocaleEnglish || got.TimeZone != "UTC" || got.Revision != 0 {
		t.Fatalf("defaults = %+v, want en, UTC and revision 0", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestValidateAcceptsSupportedLocalesAndIANAZones(t *testing.T) {
	for _, locale := range Locales() {
		for _, zone := range []string{"UTC", "Asia/Ho_Chi_Minh", "America/Argentina/Buenos_Aires", "Etc/GMT+7"} {
			s := Settings{TenantID: "tenant", DefaultLocale: locale, TimeZone: zone}
			if err := s.Validate(); err != nil {
				t.Errorf("locale %s zone %s: %v", locale, zone, err)
			}
		}
	}
}

func TestValidateRejectsUnknownLocaleAndZone(t *testing.T) {
	cases := []struct {
		name string
		s    Settings
	}{
		{"missing tenant", Settings{DefaultLocale: LocaleEnglish, TimeZone: "UTC"}},
		{"free-text locale", Settings{TenantID: "t", DefaultLocale: "fr", TimeZone: "UTC"}},
		{"region-tagged locale", Settings{TenantID: "t", DefaultLocale: "en-US", TimeZone: "UTC"}},
		{"empty zone", Settings{TenantID: "t", DefaultLocale: LocaleEnglish, TimeZone: ""}},
		{"server-local zone", Settings{TenantID: "t", DefaultLocale: LocaleEnglish, TimeZone: "Local"}},
		{"unknown zone", Settings{TenantID: "t", DefaultLocale: LocaleEnglish, TimeZone: "Mars/Olympus_Mons"}},
		{"offset instead of a name", Settings{TenantID: "t", DefaultLocale: LocaleEnglish, TimeZone: "+07:00"}},
		{"path traversal", Settings{TenantID: "t", DefaultLocale: LocaleEnglish, TimeZone: "../../etc/passwd"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.s.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestLoadTimeZoneResolvesDaylightSavingByName(t *testing.T) {
	location, err := LoadTimeZone("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	if location.String() != "Europe/Berlin" {
		t.Fatalf("location = %s, want Europe/Berlin", location)
	}
}
