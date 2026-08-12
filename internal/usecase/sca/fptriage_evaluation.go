package sca

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AIEvaluationLabel is the human-reviewed ground truth for one golden-dataset case.
type AIEvaluationLabel string

const (
	AIEvaluationTruePositive  AIEvaluationLabel = "true_positive"
	AIEvaluationFalsePositive AIEvaluationLabel = "false_positive"
	AIEvaluationUncertain     AIEvaluationLabel = "uncertain"
)

// AIEvaluationDataset is a versioned, non-production corpus used to measure triage quality. Provenance
// and reviewer are required so an anonymous or unreviewed label cannot silently become a promotion gate.
type AIEvaluationDataset struct {
	SchemaVersion string             `json:"schema_version"`
	Version       string             `json:"version"`
	Provenance    string             `json:"provenance"`
	Reviewer      string             `json:"reviewer"`
	Cases         []AIEvaluationCase `json:"cases"`
}

// AIEvaluationCase contains only synthetic/review-approved source context. It deliberately mirrors the
// finding fields used by the production prompt and policy, while keeping production scan data out of CI.
type AIEvaluationCase struct {
	ID          string            `json:"id"`
	Label       AIEvaluationLabel `json:"label"`
	Language    string            `json:"language"`
	Framework   string            `json:"framework"`
	Adversarial bool              `json:"adversarial,omitempty"`
	Kind        finding.Kind      `json:"kind"`
	Severity    shared.Severity   `json:"severity"`
	CWE         string            `json:"cwe"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Source      string            `json:"source"`
}

// AIEvaluationRun identifies the exact model/prompt/policy combination being evaluated.
type AIEvaluationRun struct {
	ProposerProvider   string                     `json:"proposer_provider"`
	ProposerModel      string                     `json:"proposer_model"`
	VerifierProvider   string                     `json:"verifier_provider"`
	VerifierModel      string                     `json:"verifier_model"`
	IndependencePolicy ports.AIIndependencePolicy `json:"independence_policy"`
	PromptVersion      string                     `json:"prompt_version"`
	PolicyVersion      string                     `json:"policy_version"`
}

// AIEvaluationResult keeps the human label beside both model consensus and deterministic shadow-policy
// output. GateExempt is included as a tripwire and must always be false in an evaluation report.
type AIEvaluationResult struct {
	CaseID                 string            `json:"case_id"`
	Label                  AIEvaluationLabel `json:"label"`
	Language               string            `json:"language"`
	Framework              string            `json:"framework"`
	Kind                   finding.Kind      `json:"kind"`
	Severity               shared.Severity   `json:"severity"`
	CWE                    string            `json:"cwe"`
	Adversarial            bool              `json:"adversarial"`
	Covered                bool              `json:"covered"`
	ConsensusFalsePositive bool              `json:"consensus_false_positive"`
	WouldGateExempt        bool              `json:"would_gate_exempt"`
	GateExempt             bool              `json:"gate_exempt"`
	Critique               ports.AICritique  `json:"critique"`
}

// AIEvaluationMetrics are computed over a whole run or one segment. Precision/recall describe verified
// false-positive consensus; escape rate describes real bugs the deterministic policy would exempt.
type AIEvaluationMetrics struct {
	Total                   int     `json:"total"`
	Covered                 int     `json:"covered"`
	HumanFalsePositives     int     `json:"human_false_positives"`
	HumanTruePositives      int     `json:"human_true_positives"`
	ConsensusFalsePositives int     `json:"consensus_false_positives"`
	CorrectFalsePositives   int     `json:"correct_false_positives"`
	TruePositiveEscapes     int     `json:"true_positive_escapes"`
	VerifierComparisons     int     `json:"verifier_comparisons"`
	VerifierDisagreements   int     `json:"verifier_disagreements"`
	Precision               float64 `json:"precision"`
	Recall                  float64 `json:"recall"`
	FalseNegativeEscapeRate float64 `json:"false_negative_escape_rate"`
	DisagreementRate        float64 `json:"disagreement_rate"`
	Coverage                float64 `json:"coverage"`
}

// AIEvaluationReport is stable, machine-readable CI output. RunID hashes the dataset/version metadata
// and ordered decisions; no clock is included, so identical inputs and model replies produce identical
// bytes and the same ID.
type AIEvaluationReport struct {
	SchemaVersion  string                                    `json:"schema_version"`
	RunID          string                                    `json:"run_id"`
	DatasetVersion string                                    `json:"dataset_version"`
	DatasetSHA256  string                                    `json:"dataset_sha256"`
	Provenance     string                                    `json:"provenance"`
	Reviewer       string                                    `json:"reviewer"`
	Run            AIEvaluationRun                           `json:"run"`
	Metrics        AIEvaluationMetrics                       `json:"metrics"`
	Breakdowns     map[string]map[string]AIEvaluationMetrics `json:"breakdowns"`
	Results        []AIEvaluationResult                      `json:"results"`
}

// Validate rejects incomplete or ambiguously labelled datasets before any model call is made.
func (d AIEvaluationDataset) Validate() error {
	if d.SchemaVersion != "synapse-ai-triage-dataset-v1" || strings.TrimSpace(d.Version) == "" ||
		strings.TrimSpace(d.Provenance) == "" || strings.TrimSpace(d.Reviewer) == "" {
		return fmt.Errorf("AI evaluation dataset requires the v1 schema, version, provenance, and reviewer")
	}
	if len(d.Cases) == 0 {
		return fmt.Errorf("AI evaluation dataset has no cases")
	}
	seen := make(map[string]struct{}, len(d.Cases))
	seenFiles := make(map[string]struct{}, len(d.Cases))
	for i, c := range d.Cases {
		id := strings.TrimSpace(c.ID)
		if id == "" {
			return fmt.Errorf("AI evaluation case %d has no id", i)
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("AI evaluation case id %q is duplicated", id)
		}
		seen[id] = struct{}{}
		file := strings.TrimSpace(c.File)
		if _, exists := seenFiles[file]; exists {
			return fmt.Errorf("AI evaluation source file %q is duplicated", file)
		}
		seenFiles[file] = struct{}{}
		if c.Label != AIEvaluationTruePositive && c.Label != AIEvaluationFalsePositive && c.Label != AIEvaluationUncertain {
			return fmt.Errorf("AI evaluation case %q has invalid label %q", id, c.Label)
		}
		if (c.Kind != finding.KindSAST && c.Kind != finding.KindMisconfig) || !c.Severity.Valid() || strings.TrimSpace(c.Language) == "" ||
			strings.TrimSpace(c.Framework) == "" || strings.TrimSpace(c.File) == "" || c.Line < 1 ||
			strings.TrimSpace(c.Title) == "" || strings.TrimSpace(c.Source) == "" {
			return fmt.Errorf("AI evaluation case %q has incomplete dimensions or finding context", id)
		}
	}
	return nil
}

// LoadAIEvaluationDataset decodes and validates a golden dataset.
func LoadAIEvaluationDataset(data []byte) (AIEvaluationDataset, error) {
	var dataset AIEvaluationDataset
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&dataset); err != nil {
		return dataset, fmt.Errorf("decode AI evaluation dataset: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return dataset, fmt.Errorf("decode AI evaluation dataset: trailing JSON content")
	}
	if err := dataset.Validate(); err != nil {
		return dataset, err
	}
	return dataset, nil
}

// AIEvaluationSourceReader returns the reviewed source stored in a dataset, never production data.
type AIEvaluationSourceReader struct{ sources map[string]string }

// NewAIEvaluationSourceReader creates an in-memory reader suitable for fptriage.NewTriager.
func NewAIEvaluationSourceReader(dataset AIEvaluationDataset) AIEvaluationSourceReader {
	sources := make(map[string]string, len(dataset.Cases))
	for _, c := range dataset.Cases {
		sources[strings.TrimSpace(c.File)] = c.Source
	}
	return AIEvaluationSourceReader{sources: sources}
}

func (r AIEvaluationSourceReader) Snippet(_ context.Context, file string, _, _ int) (string, error) {
	source, ok := r.sources[strings.TrimSpace(file)]
	if !ok {
		return "", fmt.Errorf("evaluation source %q not found", file)
	}
	return source, nil
}

// EvaluateFPTriage runs the normal injected triager and the normal deterministic policy in shadow mode.
// It cannot produce gate authority: the report is rejected if any result sets GateExempt.
func EvaluateFPTriage(ctx context.Context, dataset AIEvaluationDataset, run AIEvaluationRun, triager ports.FPTriager) (AIEvaluationReport, error) {
	if err := dataset.Validate(); err != nil {
		return AIEvaluationReport{}, err
	}
	if triager == nil {
		return AIEvaluationReport{}, fmt.Errorf("AI evaluation triager is required")
	}
	if strings.TrimSpace(run.ProposerProvider) == "" || strings.TrimSpace(run.VerifierProvider) == "" ||
		strings.TrimSpace(run.ProposerModel) == "" || strings.TrimSpace(run.VerifierModel) == "" ||
		strings.TrimSpace(run.PromptVersion) == "" || strings.TrimSpace(run.PolicyVersion) == "" {
		return AIEvaluationReport{}, fmt.Errorf("AI evaluation run requires proposer/verifier provider and model identities, prompt, and policy versions")
	}
	if !agent.IndependentLLMs(run.ProposerProvider, run.ProposerModel, run.VerifierProvider, run.VerifierModel, string(run.IndependencePolicy)) {
		return AIEvaluationReport{}, fmt.Errorf("AI evaluation verifier does not satisfy %q independence", run.IndependencePolicy)
	}
	if run.PolicyVersion != EvaluationPolicyVersion() {
		return AIEvaluationReport{}, fmt.Errorf("AI evaluation policy version %q is not current %q", run.PolicyVersion, EvaluationPolicyVersion())
	}

	findings := make([]finding.Finding, 0, len(dataset.Cases))
	caseByKey := make(map[string]AIEvaluationCase, len(dataset.Cases))
	for _, c := range dataset.Cases {
		key := "ai-eval:" + strings.TrimSpace(c.ID)
		title := fmt.Sprintf("[eval:%s] %s (%s:%d)", c.ID, c.Title, c.File, c.Line)
		findings = append(findings, finding.Finding{
			Title: title, Description: c.Description, Severity: c.Severity, CWE: c.CWE,
			Kind: c.Kind, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, DedupKey: key,
			SourceLocation: &finding.SourceLocation{File: c.File, StartLine: c.Line, EndLine: c.Line},
		})
		caseByKey[key] = c
	}

	evidence := aiTriageEvidenceForCandidates(findings, nil)
	for _, item := range findings {
		c := caseByKey[item.DedupKey]
		if framework := strings.TrimSpace(c.Framework); framework != "" {
			evidence[item.DedupKey] = append(evidence[item.DedupKey], ports.AITriageEvidenceToken{
				ID: "ev:framework", Kind: ports.AITriageEvidenceKindFramework, Value: framework,
			})
		}
	}
	var critiques []ports.AICritique
	if contextual, ok := triager.(ports.EvidenceAwareFPTriager); ok {
		critiques = contextual.TriageWithEvidence(ctx, findings, "", evidence)
	} else {
		critiques = triager.Triage(ctx, findings, "")
	}
	result := &ScanResult{Findings: findings, AITriage: critiques}
	applyAIGatePolicyWithIndependence(result, true, aiTriageModeShadow, run.IndependencePolicy)
	critiqueByKey := make(map[string]ports.AICritique, len(result.AITriage))
	for _, critique := range result.AITriage {
		key := strings.TrimSpace(critique.DedupKey)
		if _, duplicate := critiqueByKey[key]; duplicate {
			return AIEvaluationReport{}, fmt.Errorf("AI evaluation returned duplicate critique for %q", key)
		}
		if key == "" {
			return AIEvaluationReport{}, fmt.Errorf("AI evaluation returned critique without a dedup key")
		}
		if !agent.SameModel(critique.ProposerModel, run.ProposerModel) ||
			!agent.SameModel(critique.VerifierModel, run.VerifierModel) ||
			critique.ProposerProvider != agent.CanonicalProviderID(run.ProposerProvider) ||
			critique.VerifierProvider != agent.CanonicalProviderID(run.VerifierProvider) ||
			critique.IndependencePolicy != run.IndependencePolicy || critique.PromptVersion != run.PromptVersion {
			return AIEvaluationReport{}, fmt.Errorf("AI evaluation critique metadata for %q does not match the run", key)
		}
		critiqueByKey[key] = critique
	}

	report := AIEvaluationReport{
		SchemaVersion: "synapse-ai-triage-evaluation-v2", DatasetVersion: dataset.Version,
		DatasetSHA256: evaluationDatasetDigest(dataset),
		Provenance:    dataset.Provenance, Reviewer: dataset.Reviewer, Run: run,
		Breakdowns: map[string]map[string]AIEvaluationMetrics{},
		Results:    make([]AIEvaluationResult, 0, len(dataset.Cases)),
	}
	for _, item := range findings {
		c := caseByKey[item.DedupKey]
		critique, covered := critiqueByKey[item.DedupKey]
		entry := AIEvaluationResult{
			CaseID: c.ID, Label: c.Label, Language: c.Language, Framework: c.Framework,
			Kind: c.Kind, Severity: c.Severity, CWE: c.CWE, Adversarial: c.Adversarial,
			Covered: covered, Critique: critique,
		}
		if covered {
			entry.ConsensusFalsePositive = hasVerifiedConsensus(critique)
			entry.WouldGateExempt = critique.WouldGateExempt
			entry.GateExempt = critique.GateExempt
		}
		if entry.GateExempt {
			return AIEvaluationReport{}, fmt.Errorf("shadow evaluation produced gate exemption for case %q", c.ID)
		}
		report.Results = append(report.Results, entry)
	}
	report.Metrics = evaluationMetrics(report.Results)
	report.Breakdowns = evaluationBreakdowns(report.Results)
	report.RunID = evaluationRunID(report)
	return report, nil
}

func evaluationMetrics(results []AIEvaluationResult) AIEvaluationMetrics {
	var m AIEvaluationMetrics
	m.Total = len(results)
	for _, r := range results {
		if r.Covered {
			m.Covered++
		}
		switch r.Label {
		case AIEvaluationFalsePositive:
			m.HumanFalsePositives++
		case AIEvaluationTruePositive:
			m.HumanTruePositives++
		}
		if r.ConsensusFalsePositive {
			m.ConsensusFalsePositives++
			if r.Label == AIEvaluationFalsePositive {
				m.CorrectFalsePositives++
			}
		}
		if r.WouldGateExempt && r.Label == AIEvaluationTruePositive {
			m.TruePositiveEscapes++
		}
		if r.Critique.VerifierVerdict != "" {
			m.VerifierComparisons++
			if r.Critique.Verdict != r.Critique.VerifierVerdict {
				m.VerifierDisagreements++
			}
		}
	}
	m.Precision = ratio(m.CorrectFalsePositives, m.ConsensusFalsePositives)
	m.Recall = ratio(m.CorrectFalsePositives, m.HumanFalsePositives)
	m.FalseNegativeEscapeRate = ratio(m.TruePositiveEscapes, m.HumanTruePositives)
	m.DisagreementRate = ratio(m.VerifierDisagreements, m.VerifierComparisons)
	m.Coverage = ratio(m.Covered, m.Total)
	return m
}

func evaluationBreakdowns(results []AIEvaluationResult) map[string]map[string]AIEvaluationMetrics {
	dimensions := map[string]func(AIEvaluationResult) string{
		"language":  func(r AIEvaluationResult) string { return r.Language },
		"kind":      func(r AIEvaluationResult) string { return string(r.Kind) },
		"cwe":       func(r AIEvaluationResult) string { return r.CWE },
		"severity":  func(r AIEvaluationResult) string { return string(r.Severity) },
		"framework": func(r AIEvaluationResult) string { return r.Framework },
	}
	out := make(map[string]map[string]AIEvaluationMetrics, len(dimensions))
	for dimension, keyFor := range dimensions {
		groups := map[string][]AIEvaluationResult{}
		for _, result := range results {
			key := strings.TrimSpace(keyFor(result))
			if key == "" {
				key = "unknown"
			}
			groups[key] = append(groups[key], result)
		}
		out[dimension] = make(map[string]AIEvaluationMetrics, len(groups))
		for key, group := range groups {
			out[dimension][key] = evaluationMetrics(group)
		}
	}
	return out
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func evaluationRunID(report AIEvaluationReport) string {
	copyReport := report
	copyReport.RunID = ""
	// Keep results canonical even if a future caller constructs a report manually.
	sort.SliceStable(copyReport.Results, func(i, j int) bool { return copyReport.Results[i].CaseID < copyReport.Results[j].CaseID })
	b, _ := json.Marshal(copyReport)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func evaluationDatasetDigest(dataset AIEvaluationDataset) string {
	copyDataset := dataset
	copyDataset.Cases = append([]AIEvaluationCase(nil), dataset.Cases...)
	sort.SliceStable(copyDataset.Cases, func(i, j int) bool { return copyDataset.Cases[i].ID < copyDataset.Cases[j].ID })
	b, _ := json.Marshal(copyDataset)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
