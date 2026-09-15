package scabench

import (
	"fmt"
	"sort"
)

// CandidateEvidenceSummary is the canonical, machine-readable release binding.
// It keeps the legacy Result wire contract unchanged while making the complete
// evidence roots visible to reviewers and publication tooling.
type CandidateEvidenceSummary struct {
	SchemaVersion             string `json:"schema_version"`
	CycleID                   string `json:"cycle_id"`
	FinalOracleDigest         string `json:"final_oracle_digest"`
	CyclePlanDigest           string `json:"cycle_plan_digest"`
	CycleLedgerDigest         string `json:"cycle_ledger_digest"`
	PublicationManifestDigest string `json:"publication_manifest_digest"`
	BundleEvidenceDigest      string `json:"bundle_evidence_digest"`
	ComparisonDigest          string `json:"comparison_digest"`
	FalsifierDigest           string `json:"falsifier_digest"`
	ResultDigest              string `json:"result_digest"`
	ReportDigest              string `json:"report_digest"`
	ContentDigest             string `json:"content_digest"`
}

func (summary CandidateEvidenceSummary) Validate() error {
	if summary.SchemaVersion != CandidateEvidenceSummarySchemaVersion {
		return fmt.Errorf("unsupported candidate evidence summary schema %q", summary.SchemaVersion)
	}
	if err := validateCycleID(summary.CycleID); err != nil {
		return err
	}
	for _, item := range []struct {
		name   string
		digest string
	}{
		{"final oracle", summary.FinalOracleDigest},
		{"cycle plan", summary.CyclePlanDigest},
		{"cycle ledger", summary.CycleLedgerDigest},
		{"publication manifest", summary.PublicationManifestDigest},
		{"bundle evidence", summary.BundleEvidenceDigest},
		{"comparison", summary.ComparisonDigest},
		{"falsifier", summary.FalsifierDigest},
		{"result", summary.ResultDigest},
		{"report", summary.ReportDigest},
		{"content", summary.ContentDigest},
	} {
		if !validSHA256Digest(item.digest) {
			return fmt.Errorf("candidate evidence summary %s digest is invalid", item.name)
		}
	}
	actual, err := digestCandidateEvidenceSummaryContent(summary)
	if err != nil {
		return err
	}
	if summary.ContentDigest != actual {
		return fmt.Errorf("candidate evidence summary content digest does not bind its roots")
	}
	return nil
}

func NewCandidateEvidenceSummary(cycleID, finalOracleDigest, planDigest, ledgerDigest, publicationDigest, bundleEvidenceDigest, comparisonDigest, falsifierDigest, resultDigest, reportDigest string) (CandidateEvidenceSummary, error) {
	summary := CandidateEvidenceSummary{
		SchemaVersion: CandidateEvidenceSummarySchemaVersion, CycleID: cycleID, FinalOracleDigest: finalOracleDigest,
		CyclePlanDigest: planDigest, CycleLedgerDigest: ledgerDigest, PublicationManifestDigest: publicationDigest,
		BundleEvidenceDigest: bundleEvidenceDigest, ComparisonDigest: comparisonDigest, FalsifierDigest: falsifierDigest,
		ResultDigest: resultDigest, ReportDigest: reportDigest,
	}
	contentDigest, err := digestCandidateEvidenceSummaryContent(summary)
	if err != nil {
		return CandidateEvidenceSummary{}, err
	}
	summary.ContentDigest = contentDigest
	if err := summary.Validate(); err != nil {
		return CandidateEvidenceSummary{}, err
	}
	return summary, nil
}

func DigestCandidateEvidenceSummary(summary CandidateEvidenceSummary) (string, error) {
	if err := summary.Validate(); err != nil {
		return "", err
	}
	encoded, err := CanonicalJSON(summary)
	if err != nil {
		return "", fmt.Errorf("encode candidate evidence summary: %w", err)
	}
	return SHA256Digest(encoded), nil
}

// DigestBundleEvidence binds every retained capture identity, including raw
// output roots, native comparison, process evidence, and environment digests.
func DigestBundleEvidence(repetitions []RepetitionEvidence) (string, error) {
	if len(repetitions) == 0 {
		return "", fmt.Errorf("bundle evidence requires repetitions")
	}
	copyRepetitions := append([]RepetitionEvidence(nil), repetitions...)
	sort.Slice(copyRepetitions, func(left, right int) bool {
		return copyRepetitions[left].Repetition < copyRepetitions[right].Repetition
	})
	for index := range copyRepetitions {
		if copyRepetitions[index].Repetition < 1 || len(copyRepetitions[index].Bundles) == 0 {
			return "", fmt.Errorf("bundle evidence repetition is incomplete")
		}
		copyRepetitions[index].Bundles = append([]BundleEvidenceIdentity(nil), copyRepetitions[index].Bundles...)
		sort.Slice(copyRepetitions[index].Bundles, func(left, right int) bool {
			return cycleCellKey(copyRepetitions[index].Bundles[left].TargetID, copyRepetitions[index].Bundles[left].Engine) < cycleCellKey(copyRepetitions[index].Bundles[right].TargetID, copyRepetitions[index].Bundles[right].Engine)
		})
		for _, identity := range copyRepetitions[index].Bundles {
			if err := identity.Validate(); err != nil {
				return "", err
			}
		}
	}
	body, err := CanonicalJSON(copyRepetitions)
	if err != nil {
		return "", fmt.Errorf("encode bundle evidence: %w", err)
	}
	return SHA256Digest(body), nil
}

func digestCandidateEvidenceSummaryContent(summary CandidateEvidenceSummary) (string, error) {
	summary.ContentDigest = ""
	body, err := CanonicalJSON(summary)
	if err != nil {
		return "", fmt.Errorf("encode candidate evidence summary content: %w", err)
	}
	return SHA256Digest(body), nil
}
