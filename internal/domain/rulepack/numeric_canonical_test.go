package rulepack

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

func TestValidationRejectsNonCanonicalNumericMatcherValues(t *testing.T) {
	cases := []string{"01", "+1", " 1 ", "-0"}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			spec := testSpec()
			spec.Rules[0].Matcher.All = []detection.Predicate{{Field: detection.FieldProcUID, Op: detection.OpEquals, Value: value}}
			spec.RequiredFields = []detection.Field{detection.FieldProcUID}
			spec.PositiveFixtures[0].Event.Process.UID = 1
			spec.NegativeFixtures[0].Event.Process.UID = 2
			if _, err := New(spec); err == nil {
				t.Fatalf("non-canonical numeric matcher value %q must be rejected", value)
			}
		})
	}
}

func TestValidationAcceptsCanonicalNumericMatcherValue(t *testing.T) {
	spec := testSpec()
	spec.Rules[0].Matcher.All = []detection.Predicate{{Field: detection.FieldProcUID, Op: detection.OpEquals, Value: "1"}}
	spec.RequiredFields = []detection.Field{detection.FieldProcUID}
	spec.PositiveFixtures[0].Event.Process.UID = 1
	spec.NegativeFixtures[0].Event.Process.UID = 2
	if _, err := New(spec); err != nil {
		t.Fatalf("canonical numeric matcher value rejected: %v", err)
	}
}
