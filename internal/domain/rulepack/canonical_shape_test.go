package rulepack

import (
	"strings"
	"testing"
)

func TestValidationRejectsDeadPredicateFields(t *testing.T) {
	t.Run("non-in predicate carries values", func(t *testing.T) {
		spec := testSpec()
		spec.Rules[0].Matcher.All[0].Values = []string{"ignored"}
		if _, err := New(spec); err == nil {
			t.Fatal("non-in predicate must not carry the unused values field")
		}
	})

	t.Run("in predicate carries value", func(t *testing.T) {
		spec := testSpec()
		spec.Rules[0].Matcher.All[1].Value = "ignored"
		if _, err := New(spec); err == nil {
			t.Fatal("in predicate must not carry the unused value field")
		}
	})
}

func TestValidationBoundsAndCanonicalizesRuleIDShape(t *testing.T) {
	spec := testSpec()
	spec.Rules[0].ID = " det.test "
	if _, err := New(spec); err == nil {
		t.Fatal("rule id with surrounding whitespace must fail")
	}

	spec = testSpec()
	spec.Rules[0].ID = strings.Repeat("r", MaxIdentifierBytes+1)
	if _, err := New(spec); err == nil {
		t.Fatal("oversized rule id must fail")
	}
}
