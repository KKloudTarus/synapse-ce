package scabench

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

const acceptedHistoricalRatchetBaselineSHA256 = "1047745eeaaf71855059a21d848c4336578c5dc62eeb5d7116c524860450876e"

func TestHistoricalRatchetBaselineMatchesAcceptedSnapshot(t *testing.T) {
	body, err := os.ReadFile("corpus/ratchet-baseline.json")
	if err != nil {
		t.Fatalf("read accepted historical ratchet baseline: %v", err)
	}
	digest := sha256.Sum256(body)
	if actual := hex.EncodeToString(digest[:]); actual != acceptedHistoricalRatchetBaselineSHA256 {
		t.Fatalf("accepted historical ratchet baseline SHA-256 = %s, want %s", actual, acceptedHistoricalRatchetBaselineSHA256)
	}
}

func TestCandidateRatchetRecordsProspectivePolicyExceptions(t *testing.T) {
	baseline := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
	candidate := decodeRatchetFile(t, "corpus/ratchet.json")
	candidateFloors := make(map[observationKey]RatchetFloor, len(candidate.Floors))
	for _, floor := range candidate.Floors {
		candidateFloors[observationKey{Engine: floor.Expected.Engine, TargetID: floor.Expected.TargetID}] = floor
	}
	for _, historical := range baseline.Floors {
		key := observationKey{Engine: historical.Expected.Engine, TargetID: historical.Expected.TargetID}
		current, found := candidateFloors[key]
		if !found {
			t.Errorf("candidate ratchet omits historical floor for engine %q target %q", key.Engine, key.TargetID)
			continue
		}
		if key.Engine != EngineOwned {
			if key.Engine == EngineGrype {
				switch key.TargetID {
				case "debian-12-13-slim-amd64":
					assertProspectiveUnknownDisposition(t, historical, current, 255, 258)
					continue
				case "sles-15-6-bci-base-45-31-amd64":
					assertProspectiveUnknownDisposition(t, historical, current, 453, 466)
					continue
				}
			}
			if !sameRatchetPolicy(historical, current) {
				t.Errorf("candidate changes comparator policy for engine %q target %q", key.Engine, key.TargetID)
			}
			continue
		}
		if key.TargetID != "sles-15-6-bci-base-45-31-amd64" {
			if !sameRatchetPolicy(historical, current) {
				t.Errorf("candidate changes owned policy for target %q", key.TargetID)
			}
			continue
		}
		assertSLESOwnedHistoricalDisposition(t, historical, current)
	}
}

func assertProspectiveUnknownDisposition(t *testing.T, historical, candidate RatchetFloor, previous, proposed int) {
	t.Helper()
	if historical.MaximumUnknown == nil || candidate.MaximumUnknown == nil ||
		*historical.MaximumUnknown != previous || *candidate.MaximumUnknown != proposed {
		t.Fatalf("maximum unknown = %v -> %v, want %d -> %d", historical.MaximumUnknown, candidate.MaximumUnknown, previous, proposed)
	}
	withoutException := candidate
	withoutException.MaximumUnknown = historical.MaximumUnknown
	if !sameRatchetPolicy(historical, withoutException) {
		t.Fatal("prospective disposition changes policy outside its explicit unknown threshold")
	}
}

func assertSLESOwnedHistoricalDisposition(t *testing.T, historical, candidate RatchetFloor) {
	t.Helper()
	if historical.Mode != candidate.Mode ||
		historical.MinimumCovered == nil || candidate.MinimumCovered == nil || *historical.MinimumCovered != *candidate.MinimumCovered ||
		historical.MinimumAffectedRelations == nil || candidate.MinimumAffectedRelations == nil || *historical.MinimumAffectedRelations != *candidate.MinimumAffectedRelations ||
		historical.MinimumNegativeRelations == nil || candidate.MinimumNegativeRelations == nil || *historical.MinimumNegativeRelations != *candidate.MinimumNegativeRelations {
		t.Fatal("SLES owned disposition changes fixed coverage policy")
	}
	if historical.MinimumPrecision == nil || candidate.MinimumPrecision == nil || *candidate.MinimumPrecision < *historical.MinimumPrecision {
		t.Fatal("SLES owned disposition lowers minimum precision")
	}
	if candidate.AllowUndefinedPrecision {
		t.Fatal("SLES owned policy must not allow undefined precision after recall tightens")
	}
	if historical.MaximumFalsePositives == nil || candidate.MaximumFalsePositives == nil || *candidate.MaximumFalsePositives > *historical.MaximumFalsePositives ||
		historical.MaximumIncomplete == nil || candidate.MaximumIncomplete == nil || *candidate.MaximumIncomplete > *historical.MaximumIncomplete ||
		historical.MaximumUnsupported == nil || candidate.MaximumUnsupported == nil || *candidate.MaximumUnsupported > *historical.MaximumUnsupported {
		t.Fatal("SLES owned disposition relaxes policy outside its explicit unknown threshold")
	}
	if historical.MinimumRecall == nil || candidate.MinimumRecall == nil || *historical.MinimumRecall != 0 || *candidate.MinimumRecall != 1 {
		t.Fatalf("SLES owned minimum recall = %v -> %v, want 0 -> 1", historical.MinimumRecall, candidate.MinimumRecall)
	}
	if historical.MaximumFalseNegatives == nil || candidate.MaximumFalseNegatives == nil || *historical.MaximumFalseNegatives != 16 || *candidate.MaximumFalseNegatives != 0 {
		t.Fatalf("SLES owned maximum false negatives = %v -> %v, want 16 -> 0", historical.MaximumFalseNegatives, candidate.MaximumFalseNegatives)
	}
	if historical.MaximumUnknown == nil || candidate.MaximumUnknown == nil || *historical.MaximumUnknown != 0 || *candidate.MaximumUnknown != 582 {
		t.Fatalf("SLES owned maximum unknown = %v -> %v, want historical 0, prior candidate 537, prospective 582", historical.MaximumUnknown, candidate.MaximumUnknown)
	}
}

func sameRatchetPolicy(left, right RatchetFloor) bool {
	return left.Mode == right.Mode &&
		left.AllowUndefinedPrecision == right.AllowUndefinedPrecision &&
		sameIntPointer(left.MinimumCovered, right.MinimumCovered) &&
		sameIntPointer(left.MinimumAffectedRelations, right.MinimumAffectedRelations) &&
		sameIntPointer(left.MinimumNegativeRelations, right.MinimumNegativeRelations) &&
		sameFloatPointer(left.MinimumPrecision, right.MinimumPrecision) &&
		sameFloatPointer(left.MinimumRecall, right.MinimumRecall) &&
		sameIntPointer(left.MaximumFalsePositives, right.MaximumFalsePositives) &&
		sameIntPointer(left.MaximumFalseNegatives, right.MaximumFalseNegatives) &&
		sameIntPointer(left.MaximumUnknown, right.MaximumUnknown) &&
		sameIntPointer(left.MaximumIncomplete, right.MaximumIncomplete) &&
		sameIntPointer(left.MaximumUnsupported, right.MaximumUnsupported)
}

func TestValidateRatchetTighteningAllowsPinRefreshAndStricterThresholds(t *testing.T) {
	baseline := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
	current := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
	for i := range current.Floors {
		floor := &current.Floors[i]
		if floor.MinimumRecall == nil || floor.MaximumFalseNegatives == nil || *floor.MinimumRecall >= 1 || *floor.MaximumFalseNegatives <= 0 {
			continue
		}
		floor.Expected.EngineBinaryDigest = "sha256:" + strings.Repeat("a", 64)
		floor.Expected.DatabaseBuild += "-refreshed"
		floor.Expected.DatabaseDigest = "sha256:" + strings.Repeat("b", 64)
		minimumRecall := *floor.MinimumRecall + 0.01
		floor.MinimumRecall = &minimumRecall
		maximumFalseNegatives := *floor.MaximumFalseNegatives - 1
		floor.MaximumFalseNegatives = &maximumFalseNegatives
		if err := ValidateRatchetTightening(baseline, current); err != nil {
			t.Fatalf("pin refresh with stricter thresholds was rejected: %v", err)
		}
		return
	}
	t.Fatal("reviewed baseline has no floor with room to tighten recall and false-negative limits")
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
