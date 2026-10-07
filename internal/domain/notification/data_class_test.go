package notification

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDefaultDataClassPerFamily(t *testing.T) {
	for typ, want := range map[ChannelType]DataClass{
		ChannelSlack: DataClassSignal, ChannelTeams: DataClassSignal, ChannelTelegram: DataClassSignal, ChannelGoogleChat: DataClassSignal, ChannelDiscord: DataClassSignal,
		ChannelEmail: DataClassSummary, ChannelWebhook: DataClassSummary,
	} {
		if got := DefaultDataClass(typ); got != want {
			t.Errorf("DefaultDataClass(%s) = %s, want %s", typ, got, want)
		}
		if got := (Channel{Type: typ}).Class(); got != want {
			t.Errorf("a %s channel without a class reads as %s, want %s", typ, got, want)
		}
	}
}

func TestEffectiveDataClassLowerWins(t *testing.T) {
	cases := []struct {
		channel    DataClass
		engagement EngagementNotifications
		want       DataClass
		deliver    bool
	}{
		{DataClassDetail, EngagementNotificationsInherit, DataClassDetail, true},
		{DataClassDetail, EngagementNotificationsSignal, DataClassSignal, true},
		{DataClassSignal, EngagementNotificationsSignal, DataClassSignal, true},
		{DataClassSummary, EngagementNotificationsNone, "", false},
		{"", EngagementNotificationsInherit, DataClassSignal, true},
	}
	for _, c := range cases {
		got, deliver := EffectiveDataClass(c.channel, c.engagement)
		if got != c.want || deliver != c.deliver {
			t.Errorf("EffectiveDataClass(%q, %s) = %q/%v, want %q/%v", c.channel, c.engagement, got, deliver, c.want, c.deliver)
		}
	}
}

func TestRaisesOrdersClassesAndSettings(t *testing.T) {
	if !DataClassSignal.Raises(DataClassDetail) || DataClassDetail.Raises(DataClassSummary) || DataClassSummary.Raises(DataClassSummary) {
		t.Fatal("data class order is wrong")
	}
	if !EngagementNotificationsNone.Raises(EngagementNotificationsSignal) || !EngagementNotificationsSignal.Raises(EngagementNotificationsInherit) ||
		EngagementNotificationsInherit.Raises(EngagementNotificationsNone) {
		t.Fatal("engagement setting order is wrong")
	}
}

// TestFilterExposesOnlyEachClassVariables is the #1360 golden test: each class keeps exactly the
// variables declared at or below it.
func TestFilterExposesOnlyEachClassVariables(t *testing.T) {
	spec, _ := LookupEvent(EventIncidentCreated)
	full := TemplateContext{Vars: map[string]string{
		"event_type": "incident.created", "event_label": "Incident created", "occurred_at": "2026-09-27T08:00:00Z",
		"severity": "critical", "title": "Suspicious login", "summary": "Fleet correlation created an incident.",
		"engagement_name": "Q3 audit", "asset_name": "db-1", "undeclared": "x",
	}}
	signal := map[string]string{"event_type": "incident.created", "event_label": "Incident created", "occurred_at": "2026-09-27T08:00:00Z", "severity": "critical"}
	summary := map[string]string{"title": "Suspicious login", "summary": "Fleet correlation created an incident.", "engagement_name": "Q3 audit"}
	want := map[DataClass]map[string]string{
		DataClassSignal:  signal,
		DataClassSummary: merge(signal, summary),
		DataClassDetail:  merge(signal, summary, map[string]string{"asset_name": "db-1"}),
	}
	for class, vars := range want {
		if got := full.Filter(spec, class).Vars; !reflect.DeepEqual(got, vars) {
			t.Errorf("%s exposes %v, want %v", class, got, vars)
		}
	}
}

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func TestChannelRefusesAnUnknownClass(t *testing.T) {
	now := time.Now()
	c := Channel{TenantID: "t", ID: "c", Name: "Hook", Type: ChannelWebhook, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now, DataClass: "secret"}
	if err := c.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown class = %v, want ErrValidation", err)
	}
}

func TestEngagementSettingValidate(t *testing.T) {
	now := time.Now()
	valid := EngagementNotificationSetting{TenantID: "t", EngagementID: "e", ExternalNotifications: EngagementNotificationsNone, Revision: 1, UpdatedAt: &now, UpdatedBy: "admin"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid setting: %v", err)
	}
	for name, mutate := range map[string]func(*EngagementNotificationSetting){
		"value":    func(s *EngagementNotificationSetting) { s.ExternalNotifications = "some" },
		"revision": func(s *EngagementNotificationSetting) { s.Revision = 0 },
		"actor":    func(s *EngagementNotificationSetting) { s.UpdatedBy = " " },
	} {
		s := valid
		mutate(&s)
		if err := s.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
}
