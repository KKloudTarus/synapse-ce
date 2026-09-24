package sastbench

import (
	"fmt"
	"math"
	"sort"
)

// PostTriageAcceptance fixes the historical comparison contract for one corpus. ExpectedCounts must be derived
// from the freshly loaded answer key; it prevents an artifact with partial rows or altered confusion totals from
// becoming a baseline.
type PostTriageAcceptance struct {
	Corpus          string
	CorpusDigest    string
	CandidateEngine string
	BaselineEngine  string
	LineWindow      int
	ScoredCWEs      []string
	ExpectedCounts  map[string]int
	Floors          CWEFloors
}

// AcceptPostTriage validates both artifacts completely, applies absolute floors, and requires every historical
// CWE to retain recall and precision while at least one precision improves.
func AcceptPostTriage(contract PostTriageAcceptance, candidate, baseline Report) ([]string, error) {
	if err := validateAcceptanceReport("candidate", contract, candidate, contract.CandidateEngine); err != nil {
		return nil, err
	}
	if err := validateAcceptanceReport("baseline", contract, baseline, contract.BaselineEngine); err != nil {
		return nil, err
	}
	if breaches := CheckRatchetByCWE(candidate, contract.Floors); len(breaches) > 0 {
		return breaches, fmt.Errorf("post-triage candidate breaches floors")
	}
	improved, detail, err := ImprovedOverBaseline(candidate, baseline, 1e-9)
	if err != nil {
		return nil, err
	}
	if !improved {
		return detail, fmt.Errorf("post-triage candidate does not improve historical baseline")
	}
	return detail, nil
}

func validateAcceptanceReport(name string, contract PostTriageAcceptance, report Report, engine string) error {
	if report.Schema != ReportSchemaVersion || report.Stage != "post-triage" || report.Corpus != contract.Corpus || report.CorpusDigest != contract.CorpusDigest || report.Engine != engine || report.LineWindow != contract.LineWindow {
		return fmt.Errorf("%s report does not match the post-triage acceptance contract", name)
	}
	if !sameStrings(report.ScoredCWEs, contract.ScoredCWEs) {
		return fmt.Errorf("%s report scored CWE set does not match acceptance contract", name)
	}
	if len(report.CWEs) != len(contract.ExpectedCounts) {
		return fmt.Errorf("%s report has incomplete or extra CWE rows", name)
	}
	seen := make(map[string]bool, len(report.CWEs))
	for _, score := range report.CWEs {
		expected, ok := contract.ExpectedCounts[score.CWE]
		if !ok || seen[score.CWE] || score.Total != expected || score.Total != score.TP+score.FP+score.FN+score.TN || score.TP < 0 || score.FP < 0 || score.FN < 0 || score.TN < 0 {
			return fmt.Errorf("%s report has invalid count for %s", name, score.CWE)
		}
		seen[score.CWE] = true
		precision, recall := 0.0, 0.0
		if score.TP+score.FP > 0 {
			precision = float64(score.TP) / float64(score.TP+score.FP)
		}
		if score.TP+score.FN > 0 {
			recall = float64(score.TP) / float64(score.TP+score.FN)
		}
		if math.Abs(score.Precision-precision) > 1e-9 || math.Abs(score.Recall-recall) > 1e-9 {
			return fmt.Errorf("%s report has invalid derived metrics for %s", name, score.CWE)
		}
	}
	return nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
