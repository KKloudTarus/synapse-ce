package builtin

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

func TestCatalogVersionsChangedScanPagerAssetsIndependently(t *testing.T) {
	catalog := New()
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		template, ok := catalog.Builtin(notification.EventScanCompleted, notification.FamilyPager, locale)
		if !ok || !strings.HasSuffix(template.Ref, "@v2") {
			t.Fatalf("scan pager %s ref=%q, want v2", locale, template.Ref)
		}
	}
	for _, tc := range []struct {
		event  notification.EventType
		family notification.TemplateFamily
		locale tenancy.Locale
	}{
		{event: notification.EventScanCompleted, family: notification.FamilyChat, locale: tenancy.LocaleEnglish},
		{event: notification.EventIncidentCreated, family: notification.FamilyPager, locale: tenancy.LocaleVietnamese},
	} {
		template, ok := catalog.Builtin(tc.event, tc.family, tc.locale)
		if !ok || !strings.HasSuffix(template.Ref, "@v1") {
			t.Fatalf("unchanged %s/%s/%s ref=%q, want v1", tc.event, tc.family, tc.locale, template.Ref)
		}
	}
}
