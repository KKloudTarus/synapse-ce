package sastbench

import "testing"

func TestAcceptPostTriageRequiresCompleteHistoricalImprovement(t *testing.T) {
	contract := PostTriageAcceptance{
		Corpus: "corpus", CorpusDigest: "digest", CandidateEngine: "owned + verifier", BaselineEngine: "old-owned + verifier",
		LineWindow: 0, ScoredCWEs: []string{"CWE-89"}, ExpectedCounts: map[string]int{"CWE-89": 4},
		Floors: CWEFloors{Recall: map[string]float64{"CWE-89": .5}},
	}
	baseline := acceptanceReport("old-owned + verifier", 2, 1, 1, 0)
	candidate := acceptanceReport("owned + verifier", 2, 0, 1, 1)
	if _, err := AcceptPostTriage(contract, candidate, baseline); err != nil {
		t.Fatalf("accept: %v", err)
	}
	candidate = acceptanceReport("owned + verifier", 1, 0, 2, 1)
	if _, err := AcceptPostTriage(contract, candidate, baseline); err == nil {
		t.Fatal("recall regression must fail acceptance")
	}
	candidate = acceptanceReport("owned + verifier", 2, 0, 1, 0)
	if _, err := AcceptPostTriage(contract, candidate, baseline); err == nil {
		t.Fatal("invalid count must fail acceptance")
	}
}

func acceptanceReport(engine string, tp, fp, fn, tn int) Report {
	precision, recall := 0.0, 0.0
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	return Report{Schema: ReportSchemaVersion, Stage: "post-triage", Corpus: "corpus", CorpusDigest: "digest", Engine: engine, LineWindow: 0, ScoredCWEs: []string{"CWE-89"}, CWEs: []CWEScore{{CWE: "CWE-89", Total: tp + fp + fn + tn, TP: tp, FP: fp, FN: fn, TN: tn, Precision: precision, Recall: recall}}}
}
