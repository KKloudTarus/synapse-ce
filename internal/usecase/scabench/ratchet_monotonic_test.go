package scabench

import (
	"os"
	"strings"
	"testing"
)

func TestReviewedRatchetDoesNotLoosenBaseline(t *testing.T) {
	baseline := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
	current := decodeRatchetFile(t, "corpus/ratchet.json")
	if err := ValidateRatchetTightening(baseline, current); err != nil {
		t.Fatalf("reviewed ratchet weakens baseline: %v", err)
	}
}

func TestValidateRatchetTighteningAllowsPinRefreshAndStricterThresholds(t *testing.T) {
	baseline := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
	current := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
	for i := range current.Floors {
		floor := &current.Floors[i]
		if floor.Expected.Engine != EngineOwned || *floor.MinimumRecall != 0 {
			continue
		}
		floor.Expected.EngineBinaryDigest = "sha256:" + strings.Repeat("a", 64)
		floor.Expected.DatabaseBuild += "-refreshed"
		floor.Expected.DatabaseDigest = "sha256:" + strings.Repeat("b", 64)
		minimumRecall := 0.01
		floor.MinimumRecall = &minimumRecall
		maximumFalseNegatives := *floor.MaximumFalseNegatives - 1
		floor.MaximumFalseNegatives = &maximumFalseNegatives
		if err := ValidateRatchetTightening(baseline, current); err != nil {
			t.Fatalf("pin refresh with stricter thresholds was rejected: %v", err)
		}
		return
	}
	t.Fatal("reviewed baseline has no owned zero-recall floor")
}

func TestValidateRatchetTighteningRejectsWeakerPolicy(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Ratchet)
		want string
	}{
		{
			name: "change oracle root",
			edit: func(ratchet *Ratchet) {
				ratchet.OracleDigest = "sha256:" + strings.Repeat("f", 64)
			},
			want: "changes baseline oracle digest",
		},
		{
			name: "change target identity",
			edit: func(ratchet *Ratchet) {
				ratchet.Floors[0].Expected.TargetDigest = "sha256:" + strings.Repeat("e", 64)
			},
			want: "changes baseline target digest",
		},
		{
			name: "lower minimum recall",
			edit: func(ratchet *Ratchet) {
				value := *ratchet.Floors[0].MinimumRecall - 0.01
				ratchet.Floors[0].MinimumRecall = &value
			},
			want: "lowers minimum recall",
		},
		{
			name: "raise maximum false negatives",
			edit: func(ratchet *Ratchet) {
				value := *ratchet.Floors[0].MaximumFalseNegatives + 1
				ratchet.Floors[0].MaximumFalseNegatives = &value
			},
			want: "raises maximum false negatives",
		},
		{
			name: "allow undefined precision",
			edit: func(ratchet *Ratchet) {
				ratchet.Floors[0].AllowUndefinedPrecision = true
				value := 0.0
				ratchet.Floors[0].MinimumPrecision = &value
			},
			want: "enables undefined precision",
		},
		{
			name: "change gate mode",
			edit: func(ratchet *Ratchet) {
				floor := &ratchet.Floors[len(ratchet.Floors)-1]
				floor.Mode = FloorGateModeAccuracy
				floor.Expected.CapabilityKind = ""
				floor.Expected.CapabilityDigest = ""
				minimum := 1
				floor.MinimumCovered = &minimum
				floor.MinimumAffectedRelations = &minimum
				floor.MinimumNegativeRelations = &minimum
			},
			want: "changes baseline mode",
		},
		{
			name: "remove governed floor",
			edit: func(ratchet *Ratchet) {
				ratchet.Floors = ratchet.Floors[1:]
			},
			want: "removes baseline floor",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
			current := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
			test.edit(&current)
			err := ValidateRatchetTightening(baseline, current)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateRatchetTightening() error = %v, want %q", err, test.want)
			}
		})
	}
}

func decodeRatchetFile(t *testing.T, path string) Ratchet {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ratchet, err := DecodeRatchet(file)
	if err != nil {
		t.Fatal(err)
	}
	return ratchet
}
