package notification

import (
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

func TestEveryChannelTypeHasAFamily(t *testing.T) {
	want := map[ChannelType]TemplateFamily{ChannelWebhook: FamilyWebhook, ChannelSlack: FamilyChat, ChannelEmail: FamilyEmail}
	for channelType, family := range want {
		if got, ok := FamilyForChannelType(channelType); !ok || got != family {
			t.Errorf("%s: family = %q ok=%v, want %q", channelType, got, ok, family)
		}
	}
	if _, ok := FamilyForChannelType("carrier_pigeon"); ok {
		t.Error("an unknown channel type has a family")
	}
}

func TestLocaleChain(t *testing.T) {
	for locale, want := range map[tenancy.Locale][]tenancy.Locale{
		"vi": {"vi", "*", "en"},
		"en": {"en", "*"},
		"":   {"en", "*"},
		"fr": {"en", "*"},
	} {
		if got := LocaleChain(locale); !reflect.DeepEqual(got, want) {
			t.Errorf("LocaleChain(%q) = %v, want %v", locale, got, want)
		}
	}
}

func TestTemplateBindingValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		binding TemplateBinding
		channel ChannelType
		ok      bool
	}{
		"empty":            {TemplateBinding{}, ChannelWebhook, true},
		"locale only":      {TemplateBinding{Locale: "vi"}, ChannelEmail, true},
		"template":         {TemplateBinding{TemplateID: "t1", Locale: "en"}, ChannelSlack, true},
		"wildcard locale":  {TemplateBinding{Locale: "*"}, ChannelSlack, false},
		"unknown locale":   {TemplateBinding{Locale: "en-US"}, ChannelSlack, false},
		"type w/o family":  {TemplateBinding{TemplateID: "t1"}, "carrier_pigeon", false},
		"unprintable id":   {TemplateBinding{TemplateID: "t\n1"}, ChannelSlack, false},
		"unknown, no bind": {TemplateBinding{}, "carrier_pigeon", true},
		"custom body":      {TemplateBinding{TemplateID: "t1", CustomBody: true}, ChannelWebhook, true},
		"custom, unbound":  {TemplateBinding{CustomBody: true}, ChannelWebhook, false},
		"custom on slack":  {TemplateBinding{TemplateID: "t1", CustomBody: true}, ChannelSlack, false},
		"custom on email":  {TemplateBinding{TemplateID: "t1", CustomBody: true}, ChannelEmail, false},
	} {
		err := tc.binding.Validate(tc.channel)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, shared.ErrValidation)) {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

func TestTemplateKeyCovers(t *testing.T) {
	if !(TemplateKey{EventType: AnyEventType}).Covers(EventScanCompleted) || !(TemplateKey{EventType: EventScanCompleted}).Covers(EventScanCompleted) {
		t.Fatal("a key does not cover its own or a wildcard event")
	}
	if (TemplateKey{EventType: EventIncidentCreated}).Covers(EventScanCompleted) {
		t.Fatal("a key covers another event type")
	}
}
