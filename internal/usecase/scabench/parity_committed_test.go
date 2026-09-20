package scabench

import (
	"os"
	"strings"
	"testing"
)

// TestOwnedRecallParityOnCommittedRatchet wires OwnedBeatsEachComparator to the committed SCA oracle ratchet:
// it builds each target's per-engine recall from the committed floors and asserts owned meets or beats every
// comparator, EXCEPT a documented known-gap allowlist. This enforces the #1037 relative-parity requirement on
// the real committed evidence (a NEW target where a comparator out-recalls owned fails the build) rather than
// leaving OwnedBeatsEachComparator as an unwired function.
//
// Known parity debt: on SLES 15.6, owned's OVAL-sourced rpm feed matches only patched ("< fixed") CVEs and
// misses the not-yet-fixed CVEs Grype catches (committed floors: owned recall 0 vs grype 0.125). That gap is
// disclosed to users by the rpm not-yet-fixed coverage warning (internal/usecase/sca) and closed for good only
// by ingesting not-yet-fixed rpm advisories (the #1037 recall follow-up). The allowlist is shrink-only: closing
// the gap (raising the owned SLES floor) makes the breach disappear, and this test then requires the stale
// exception be removed, so the debt cannot silently rot.
func TestOwnedRecallParityOnCommittedRatchet(t *testing.T) {
	f, err := os.Open("corpus/ratchet.json")
	if err != nil {
		t.Fatalf("open committed ratchet: %v", err)
	}
	defer func() { _ = f.Close() }()
	ratchet, err := DecodeRatchet(f)
	if err != nil {
		t.Fatalf("decode committed ratchet: %v", err)
	}

	// Build each target's per-engine recall from the committed floors, so OwnedBeatsEachComparator sees the
	// committed expectation as a Result.
	byTarget := map[string][]EngineResult{}
	for _, fl := range ratchet.Floors {
		if fl.MinimumRecall == nil {
			continue // an engine with no recall floor (e.g. an unsupported-only mode) is not a pinned baseline
		}
		byTarget[fl.Expected.TargetID] = append(byTarget[fl.Expected.TargetID], EngineResult{
			Engine:          fl.Expected.Engine,
			MetricsComplete: true,
			Recall:          fl.MinimumRecall,
		})
	}
	if len(byTarget) == 0 {
		t.Fatal("committed ratchet has no per-engine recall floors to check parity against")
	}

	knownDebt := map[string]bool{
		"sles-15-6-bci-base-45-31-amd64|grype": true,
	}
	sawKnown := map[string]bool{}
	for target, engines := range byTarget {
		ok, detail, perr := OwnedBeatsEachComparator(Result{Engines: engines})
		if perr != nil {
			t.Errorf("target %s: owned recall is undefined in the committed floors: %v", target, perr)
			continue
		}
		if ok {
			continue
		}
		for _, breach := range detail.Breaches {
			comparator := strings.Fields(breach)[0] // "grype recall 0.1250 exceeds owned recall 0.0000" -> "grype"
			key := target + "|" + comparator
			if !knownDebt[key] {
				t.Errorf("NEW owned-vs-comparator recall regression on the committed matrix: target %s: %s. Owned must meet or beat every pinned comparator; only a deliberately-accepted, followed-up gap belongs in the knownDebt allowlist.", target, breach)
			}
			sawKnown[key] = true
		}
	}
	for key := range knownDebt {
		if !sawKnown[key] {
			t.Errorf("tracked parity debt %q no longer breaches the committed floors: remove it from knownDebt (the gap is closed)", key)
		}
	}
}
