package rulepack

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

func TestCanonicalPredicateOrderingHasNoSeparatorCollision(t *testing.T) {
	spec := testSpec()
	arg := spec.Rules[0].Matcher.All[0]
	oneValueContainingSeparator := detection.Predicate{
		Field:  detection.FieldProcComm,
		Op:     detection.OpIn,
		Values: []string{"a\x1db"},
	}
	twoValues := detection.Predicate{
		Field:  detection.FieldProcComm,
		Op:     detection.OpIn,
		Values: []string{"a", "b"},
	}
	spec.Rules[0].Matcher.All = []detection.Predicate{arg, oneValueContainingSeparator, twoValues}
	first, err := New(spec)
	if err != nil {
		t.Fatalf("New first ordering: %v", err)
	}

	spec.Rules[0].Matcher.All = []detection.Predicate{twoValues, arg, oneValueContainingSeparator}
	second, err := New(spec)
	if err != nil {
		t.Fatalf("New second ordering: %v", err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("predicate declaration order changed digest: %s != %s", first.Digest, second.Digest)
	}
}

func TestValidationRejectsFixtureIDReuseAcrossCorpora(t *testing.T) {
	spec := testSpec()
	spec.NegativeFixtures[0].ID = spec.PositiveFixtures[0].ID
	if _, err := New(spec); err == nil {
		t.Fatal("positive/negative fixtures must not share an ID")
	}
}

func TestValidationBoundsRolloutCohortIdentifier(t *testing.T) {
	spec := testSpec()
	spec.RolloutCohort = []string{string(make([]byte, MaxIdentifierBytes+1))}
	if _, err := New(spec); err == nil {
		t.Fatal("oversized rollout cohort must fail")
	}
}

func TestVerifyRejectsWrongSignatureLengthBeforeVerification(t *testing.T) {
	p := seal(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Signature += "AAAA"
	if err := Verify(artifact, pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("oversized signature err = %v", err)
	}
}
