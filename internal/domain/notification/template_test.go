package notification

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

func TestTemplateFamiliesDeclareFields(t *testing.T) {
	want := map[TemplateFamily]string{
		FamilyChat: "title,body", FamilyEmail: "subject,body", FamilyPager: "summary",
		FamilyTicket: "summary,description", FamilyWebhook: "body",
	}
	if len(TemplateFamilies()) != len(want) {
		t.Fatalf("families = %v", TemplateFamilies())
	}
	for _, family := range TemplateFamilies() {
		if !family.Valid() || strings.Join(family.Fields(), ",") != want[family] {
			t.Errorf("%s fields = %v", family, family.Fields())
		}
	}
	if TemplateFamily("sms").Valid() || TemplateFamily("").Valid() {
		t.Fatal("an undeclared family is valid")
	}
	fields := FamilyChat.Fields()
	fields[0] = "mutated"
	if FamilyChat.Fields()[0] != "title" {
		t.Fatal("Fields exposes the family table")
	}
}

func TestTemplateKeyValidate(t *testing.T) {
	valid := []TemplateKey{
		{EventScanCompleted, FamilyChat, tenancy.LocaleEnglish},
		{AnyEventType, FamilyWebhook, AnyLocale},
		{EventIncidentCreated, FamilyPager, tenancy.LocaleVietnamese},
	}
	for _, key := range valid {
		if err := key.Validate(); err != nil {
			t.Errorf("%+v: %v", key, err)
		}
	}
	invalid := []TemplateKey{
		{"made.up", FamilyChat, "en"},
		{"", FamilyChat, "en"},
		{EventScanCompleted, "sms", "en"},
		{EventScanCompleted, FamilyChat, "fr"},
		{EventScanCompleted, FamilyChat, ""},
	}
	for _, key := range invalid {
		if err := key.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v: want ErrValidation, got %v", key, err)
		}
	}
}

func TestTemplateValidateNew(t *testing.T) {
	base := Template{TenantID: "t", ID: "tpl", Name: "Scan digest", TemplateKey: TemplateKey{EventScanCompleted, FamilyChat, "en"},
		CreatedAt: time.Unix(1, 0), CreatedBy: "admin"}
	if err := base.ValidateNew(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Template){
		"no tenant":       func(tp *Template) { tp.TenantID = "" },
		"long id":         func(tp *Template) { tp.ID = shared.ID(strings.Repeat("x", MaxTemplateIDBytes+1)) },
		"control in id":   func(tp *Template) { tp.ID = "a\nb" },
		"long name":       func(tp *Template) { tp.Name = strings.Repeat("n", MaxTemplateNameRunes+1) },
		"trailing space":  func(tp *Template) { tp.Name = "name " },
		"control in name": func(tp *Template) { tp.Name = "a\tb" },
		"no time":         func(tp *Template) { tp.CreatedAt = time.Time{} },
		"no actor":        func(tp *Template) { tp.CreatedBy = "" },
	} {
		tp := base
		mutate(&tp)
		if err := tp.ValidateNew(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", name, err)
		}
	}
	// Names are counted in runes, so a full-length Vietnamese name fits.
	tp := base
	tp.Name = strings.Repeat("ệ", MaxTemplateNameRunes)
	if err := tp.ValidateNew(); err != nil {
		t.Fatalf("a %d-rune name: %v", MaxTemplateNameRunes, err)
	}
}

func TestValidateTemplateFields(t *testing.T) {
	if err := ValidateTemplateFields(FamilyEmail, map[string]string{"subject": "Scan {{.scan_id}}", "body": ""}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTemplateFields(FamilyChat, map[string]string{"body": strings.Repeat("a", MaxTemplateFieldBytes)}); err != nil {
		t.Fatalf("a field at the limit: %v", err)
	}
	cases := map[string]struct {
		family TemplateFamily
		fields map[string]string
	}{
		"unknown family": {"sms", map[string]string{"body": "x"}},
		"no fields":      {FamilyChat, nil},
		"foreign field":  {FamilyPager, map[string]string{"title": "x"}},
		"blank only":     {FamilyTicket, map[string]string{"summary": " \n"}},
		"too large":      {FamilyWebhook, map[string]string{"body": strings.Repeat("a", MaxTemplateFieldBytes+1)}},
		"invalid UTF-8":  {FamilyChat, map[string]string{"body": "\xff"}},
		"NUL":            {FamilyChat, map[string]string{"body": "a\x00"}},
	}
	for name, tc := range cases {
		err := ValidateTemplateFields(tc.family, tc.fields)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "aaaa") {
			t.Errorf("%s: the error echoes template source", name)
		}
	}
}

func TestTemplateChecksumIsStableAndKeyOrderFree(t *testing.T) {
	a := TemplateChecksum(map[string]string{"title": "t", "body": "b"})
	b := TemplateChecksum(map[string]string{"body": "b", "title": "t"})
	if a != b || len(a) != 64 {
		t.Fatalf("checksums %q %q", a, b)
	}
	if a == TemplateChecksum(map[string]string{"title": "t", "body": "B"}) {
		t.Fatal("different fields share a checksum")
	}
	// Pinned so a change to the encoding, which would orphan stored checksums, fails loudly.
	// sha256 of {"body":"b"}.
	if got := TemplateChecksum(map[string]string{"body": "b"}); got != "1c1f0ba7d68879259470a97321aec2add1c3949951676fab1fd0708fcc8b4c20" {
		t.Fatalf("checksum encoding changed: %s", got)
	}
}
