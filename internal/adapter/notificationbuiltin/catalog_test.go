package notificationbuiltin

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

func TestCatalogCoversRoutableEventsFamiliesAndLocales(t *testing.T) {
	catalog := New()
	events := []notification.EventType{
		notification.EventVulnerabilityAction, notification.EventScanCompleted,
		notification.EventQualityGateFailed, notification.EventSLAApproaching,
		notification.EventFleetAgentOffline, notification.EventIncidentCreated,
		notification.EventOwnershipChanged,
	}
	families := []notification.TemplateFamily{notification.FamilyChat, notification.FamilyEmail, notification.FamilyPager, notification.FamilyWebhook}
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		for _, family := range families {
			if template, ok := catalog.Builtin(notification.AnyEventType, family, locale); !ok || template.Ref == "" {
				t.Fatalf("missing wildcard %s/%s", family, locale)
			}
			for _, event := range events {
				template, ok := catalog.Builtin(event, family, locale)
				if !ok || template.Ref == "" || len(template.Fields) == 0 {
					t.Fatalf("missing %s/%s/%s", event, family, locale)
				}
			}
		}
	}
	vi, ok := catalog.Builtin(notification.EventScanCompleted, notification.FamilyChat, tenancy.LocaleVietnamese)
	if !ok || !strings.Contains(vi.Fields["title"], "Quét") {
		t.Fatalf("Vietnamese content lost diacritics: %+v", vi)
	}
}

func TestCatalogReturnsDefensiveFieldCopies(t *testing.T) {
	catalog := New()
	first, ok := catalog.Builtin(notification.EventScanCompleted, notification.FamilyChat, tenancy.LocaleEnglish)
	if !ok {
		t.Fatal("missing scan chat template")
	}
	first.Fields["title"] = "changed"
	again, _ := catalog.Builtin(notification.EventScanCompleted, notification.FamilyChat, tenancy.LocaleEnglish)
	if again.Fields["title"] == "changed" {
		t.Fatal("catalog field mutation escaped")
	}
}
