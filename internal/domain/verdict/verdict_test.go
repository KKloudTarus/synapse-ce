package verdict

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestVerdictValidate(t *testing.T) {
	cases := []struct {
		name string
		v    Verdict
		ok   bool
	}{
		{"valid", Verdict{Verifier: "reviewer", Score: 80, Rationale: "survived"}, true},
		{"score 0 valid", Verdict{Verifier: "reviewer", Score: 0, Rationale: "refuted"}, true},
		{"score 100 valid", Verdict{Verifier: "reviewer", Score: 100, Rationale: "proven"}, true},
		{"no verifier", Verdict{Verifier: " ", Score: 80, Rationale: "x"}, false},
		{"score negative", Verdict{Verifier: "reviewer", Score: -1, Rationale: "x"}, false},
		{"score over 100", Verdict{Verifier: "reviewer", Score: 101, Rationale: "x"}, false},
		{"no rationale", Verdict{Verifier: "reviewer", Score: 80, Rationale: " "}, false},
		{"rationale at byte limit", Verdict{Verifier: "reviewer", Score: 80, Rationale: strings.Repeat("a", MaxRationaleBytes)}, true},
		{"rationale over byte limit", Verdict{Verifier: "reviewer", Score: 80, Rationale: strings.Repeat("a", MaxRationaleBytes+1)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.v.Validate()
			if tc.ok {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestSelfConfirm(t *testing.T) {
	cases := []struct {
		name             string
		verifier, propBy string
		want             bool
	}{
		{"same actor self-confirms", "agent:1", "agent:1", true},
		{"distinct actors ok", "human:bob", "agent:1", false},
		{"empty proposer never self-confirms", "agent:1", "", false},
		{"both empty", "", "", false},
		{"whitespace-equal self-confirms", "agent:1", " agent:1 ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SelfConfirm(tc.verifier, tc.propBy); got != tc.want {
				t.Fatalf("SelfConfirm(%q,%q)=%v want %v", tc.verifier, tc.propBy, got, tc.want)
			}
		})
	}
}

func TestMeetsBar(t *testing.T) {
	if MeetsBar(EvidenceThreshold - 1) {
		t.Fatal("below threshold should not meet the bar")
	}
	if !MeetsBar(EvidenceThreshold) {
		t.Fatal("at threshold should meet the bar")
	}
}
