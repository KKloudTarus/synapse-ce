package alerting

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func valid() Alert {
	return Alert{ID: "a1", TenantID: "t1", Kind: KindIncidentCreated, Severity: shared.SeverityHigh, Title: "process: det.process_enumeration", OccurredAt: time.Unix(1, 0)}
}

func TestAlertValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid alert rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Alert){
		"no id":     func(a *Alert) { a.ID = "" },
		"no tenant": func(a *Alert) { a.TenantID = "" },
		"bad kind":  func(a *Alert) { a.Kind = "nope" },
		"bad sev":   func(a *Alert) { a.Severity = "loud" },
		"no title":  func(a *Alert) { a.Title = "  " },
		"no time":   func(a *Alert) { a.OccurredAt = time.Time{} },
	} {
		a := valid()
		mutate(&a)
		if err := a.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
}

func TestRuleMatches(t *testing.T) {
	rule := Rule{MinSeverity: shared.SeverityHigh}
	cases := map[shared.Severity]bool{
		shared.SeverityCritical: true,
		shared.SeverityHigh:     true,
		shared.SeverityMedium:   false,
		shared.SeverityLow:      false,
		shared.SeverityInfo:     false,
		shared.SeverityUnknown:  false,
	}
	for sev, want := range cases {
		a := valid()
		a.Severity = sev
		if got := rule.Matches(a); got != want {
			t.Errorf("severity %s: matches = %v, want %v", sev, got, want)
		}
	}
	// A test alert always goes through so an operator can verify the path.
	test := valid()
	test.Kind, test.Severity = KindTest, shared.SeverityInfo
	if !rule.Matches(test) {
		t.Fatal("test alert must match regardless of threshold")
	}
	if DefaultRule().MinSeverity != shared.SeverityMedium {
		t.Fatalf("default rule = %+v", DefaultRule())
	}
	if err := (Rule{MinSeverity: shared.SeverityUnknown}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown threshold accepted: %v", err)
	}
	if err := (Rule{MinSeverity: "silly"}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bogus threshold accepted: %v", err)
	}
}
