package suppression

import (
	"testing"
	"time"
)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestRuleValidate(t *testing.T) {
	ok := Rule{RuleKey: "generic-secret", Reason: "test fixtures", Expires: day("2026-12-31")}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	for name, r := range map[string]Rule{
		"no matcher": {Reason: "x", Expires: day("2026-12-31")},
		"no reason":  {RuleKey: "x", Expires: day("2026-12-31")},
		"no expiry":  {RuleKey: "x", Reason: "x"},
		"bad glob":   {Path: "[", Reason: "x", Expires: day("2026-12-31")},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestSuppressMatchAndExpiry(t *testing.T) {
	rs := Ruleset{
		{RuleKey: "generic-secret", Path: "testdata/**", Reason: "fixtures", Expires: day("2026-12-31")},
		{RuleKey: "CVE-2024-1", Reason: "not exploitable", Expires: day("2026-06-30")}, // expired vs now below
	}
	now := day("2026-09-01")

	// rule + path both match, active.
	if _, ok := rs.Suppress([]string{"generic-secret"}, "testdata/fixture.py", now); !ok {
		t.Error("active rule+path suppression must match")
	}
	// rule matches but path is outside the glob.
	if _, ok := rs.Suppress([]string{"generic-secret"}, "src/main.py", now); ok {
		t.Error("path outside the glob must NOT be suppressed")
	}
	// CVE rule is expired → must not suppress even though the key matches.
	if _, ok := rs.Suppress([]string{"CVE-2024-1"}, "", now); ok {
		t.Error("an expired suppression must not apply")
	}
	// Expired() surfaces it.
	if exp := rs.Expired(now); len(exp) != 1 || exp[0].RuleKey != "CVE-2024-1" {
		t.Errorf("Expired() = %+v, want the CVE rule", exp)
	}
	// On the expiry date itself the rule is still active (inclusive).
	if _, ok := rs.Suppress([]string{"CVE-2024-1"}, "", day("2026-06-30")); !ok {
		t.Error("a suppression must be active through its expiry date (inclusive)")
	}
}
