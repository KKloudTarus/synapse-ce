package rulepack

import "testing"

func TestReplayKeepsPositiveCorpusBeforeNegativeCorpus(t *testing.T) {
	p := seal(t)
	results, err := Replay(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	// "negative" sorts before "positive" lexically, so this assertion proves
	// Replay preserves corpus order instead of globally sorting all fixtures.
	if results[0].FixtureID != "positive" || results[1].FixtureID != "negative" {
		t.Fatalf("replay order = %q, %q; want positive corpus before negative corpus", results[0].FixtureID, results[1].FixtureID)
	}
}
