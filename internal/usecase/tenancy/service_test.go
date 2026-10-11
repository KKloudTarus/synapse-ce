package tenancy

import (
	"context"
	"errors"
	"testing"
	"time"
	// The binaries embed the IANA database; tests embed it too so they pass on any host.
	_ "time/tzdata"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fakeAudit struct {
	entries []ports.AuditEntry
	err     error
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	if a.err != nil {
		return a.err
	}
	a.entries = append(a.entries, e)
	return nil
}

// failingStore stands in for a database that is down.
type failingStore struct{}

func (failingStore) GetTenantSettings(context.Context, shared.ID) (domain.Settings, bool, error) {
	return domain.Settings{}, false, errors.New("database unavailable")
}

func (failingStore) SaveTenantSettings(context.Context, domain.Settings, int) (domain.Settings, error) {
	return domain.Settings{}, errors.New("database unavailable")
}

var now = time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC)

func newService(t *testing.T) (*Service, *fakeAudit) {
	t.Helper()
	audit := &fakeAudit{}
	svc, err := NewService(memory.NewTenantSettingsStore(), audit, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return svc, audit
}

func TestSettingsDefaultForATenantThatNeverSaved(t *testing.T) {
	svc, _ := newService(t)
	got, err := svc.Settings(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if got.DefaultLocale != domain.LocaleEnglish || got.TimeZone != "UTC" || got.Revision != 0 {
		t.Fatalf("settings = %+v, want the defaults at revision 0", got)
	}
}

func TestSaveValidatesStoresAndAudits(t *testing.T) {
	svc, audit := newService(t)
	ctx := context.Background()
	saved, err := svc.Save(ctx, "tenant", "admin", Update{DefaultLocale: domain.LocaleVietnamese, TimeZone: "Asia/Ho_Chi_Minh"})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || saved.UpdatedBy != "admin" || !saved.UpdatedAt.Equal(now) {
		t.Fatalf("saved = %+v, want revision 1 by admin at the clock time", saved)
	}
	got, err := svc.Settings(ctx, "tenant")
	if err != nil || got.DefaultLocale != domain.LocaleVietnamese || got.TimeZone != "Asia/Ho_Chi_Minh" {
		t.Fatalf("settings after save = %+v, %v", got, err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(audit.entries))
	}
	entry := audit.entries[0]
	if entry.Action != "tenant.settings.updated" || entry.Target != "tenant" || entry.Metadata["time_zone"] != "Asia/Ho_Chi_Minh" {
		t.Fatalf("audit entry = %+v", entry)
	}
}

func TestSaveRejectsInvalidInputWithoutWriting(t *testing.T) {
	svc, audit := newService(t)
	ctx := context.Background()
	for _, in := range []Update{
		{DefaultLocale: "fr", TimeZone: "UTC"},
		{DefaultLocale: "en", TimeZone: "Mars/Olympus_Mons"},
		{DefaultLocale: "en", TimeZone: "Local"},
		{DefaultLocale: "en", TimeZone: "UTC", Revision: -1},
	} {
		if _, err := svc.Save(ctx, "tenant", "admin", in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("save %+v: want ErrValidation, got %v", in, err)
		}
	}
	if _, err := svc.Save(ctx, "tenant", "", Update{DefaultLocale: "en", TimeZone: "UTC"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("save without an actor: want ErrValidation, got %v", err)
	}
	if got, _ := svc.Settings(ctx, "tenant"); got.Revision != 0 {
		t.Fatalf("an invalid save wrote settings: %+v", got)
	}
	if len(audit.entries) != 0 {
		t.Fatalf("an invalid save was audited: %+v", audit.entries)
	}
}

func TestSaveRejectsAStaleRevision(t *testing.T) {
	svc, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.Save(ctx, "tenant", "admin", Update{DefaultLocale: "en", TimeZone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	// A second administrator who read the page before the first save still holds revision 0.
	if _, err := svc.Save(ctx, "tenant", "other", Update{DefaultLocale: "vi", TimeZone: "UTC"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale save: want ErrConflict, got %v", err)
	}
	if _, err := svc.Save(ctx, "tenant", "other", Update{DefaultLocale: "vi", TimeZone: "UTC", Revision: 1}); err != nil {
		t.Fatalf("save at the current revision: %v", err)
	}
}

func TestSettingsAreIsolatedPerTenant(t *testing.T) {
	svc, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.Save(ctx, "tenant-a", "admin", Update{DefaultLocale: "vi", TimeZone: "Asia/Ho_Chi_Minh"}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Settings(ctx, "tenant-b")
	if err != nil || got.DefaultLocale != domain.LocaleEnglish || got.TimeZone != "UTC" {
		t.Fatalf("tenant-b sees %+v, %v; want its own defaults", got, err)
	}
}

func TestTenantLocaleNeverFailsOnMissingSettings(t *testing.T) {
	svc, _ := newService(t)
	ctx := context.Background()
	got, err := svc.TenantLocale(ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if got.Locale != domain.LocaleEnglish || got.Location != time.UTC {
		t.Fatalf("default locale = %+v, want en and UTC", got)
	}
	if _, err := svc.Save(ctx, "tenant", "admin", Update{DefaultLocale: "vi", TimeZone: "Europe/Berlin"}); err != nil {
		t.Fatal(err)
	}
	got, err = svc.TenantLocale(ctx, "tenant")
	if err != nil || got.Locale != domain.LocaleVietnamese || got.Location.String() != "Europe/Berlin" {
		t.Fatalf("saved locale = %+v, %v", got, err)
	}
	// Daylight saving is resolved from the zone name at render time.
	summer := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC).In(got.Location)
	winter := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).In(got.Location)
	if summer.Hour() != 14 || winter.Hour() != 13 {
		t.Fatalf("Berlin hours = %d/%d, want 14 in summer and 13 in winter", summer.Hour(), winter.Hour())
	}
}

func TestTenantLocaleFallsBackToUTCForAZoneThatNoLongerLoads(t *testing.T) {
	store := memory.NewTenantSettingsStore()
	// A row written by an older build whose zone this build cannot load.
	if _, err := store.SaveTenantSettings(context.Background(), domain.Settings{TenantID: "tenant", DefaultLocale: "vi", TimeZone: "Retired/Zone"}, 0); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(store, &fakeAudit{}, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.TenantLocale(context.Background(), "tenant")
	if err != nil || got.Locale != domain.LocaleVietnamese || got.Location != time.UTC {
		t.Fatalf("locale = %+v, %v; want vi with a UTC fallback", got, err)
	}
}

func TestTenantLocaleReturnsAStoreError(t *testing.T) {
	svc, err := NewService(failingStore{}, &fakeAudit{}, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TenantLocale(context.Background(), "tenant"); err == nil {
		t.Fatal("a store error must not be hidden behind the defaults")
	}
}

func TestSaveFailsWhenTheAuditRecordFails(t *testing.T) {
	audit := &fakeAudit{err: errors.New("audit down")}
	svc, err := NewService(memory.NewTenantSettingsStore(), audit, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Save(context.Background(), "tenant", "admin", Update{DefaultLocale: "en", TimeZone: "UTC"}); err == nil {
		t.Fatal("save must report a failed audit record")
	}
}
