// Package reachbench defines the deterministic reachability accuracy corpus contract and its recall
// ratchet. It deliberately measures the public, derived labels rather than a particular analyzer tier, so
// Go, JVM, JavaScript, Python, and future engines can be compared without relabeling their evidence.
package reachbench

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	CorpusSchemaVersion = "synapse-reachability-corpus-v1"
	InputSchemaVersion  = "synapse-reachability-input-v1"
	ReportSchemaVersion = "synapse-reachability-report-v1"
)

// Label is the closed, user-visible reachability vocabulary. The labels are derived evidence labels: they
// do not change the domain verdict enum and therefore do not pre-empt the A-CORE coverage-model work.
type Label string

const (
	Reachable              Label = "reachable"
	ConditionallyReachable Label = "conditionally_reachable"
	PresentUnreached       Label = "present_unreached"
	NoAnalysis             Label = "no_analysis"
)

func (l Label) valid() bool {
	switch l {
	case Reachable, ConditionallyReachable, PresentUnreached, NoAnalysis:
		return true
	}
	return false
}

// Case is one labeled query against a fixture. Fixture is a repository-relative fixture id; Symbol is the
// exact canonical symbol queried. Keeping symbols explicit prevents a benchmark runner from quietly
// selecting a convenient symbol after an analyzer changes.
type Case struct {
	Name     string       `json:"name"`
	Language string       `json:"language"`
	Fixture  string       `json:"fixture"`
	Symbol   string       `json:"symbol"`
	Expected Label        `json:"expected"`
	Baseline BaselineCase `json:"baseline,omitempty"`
}

// BaselineCase binds one corpus case to the stable identifiers emitted by the external tools. Empty
// selectors are intentional: a baseline that has no corresponding analysis must report no_analysis, not
// silently drop the case from its denominator.
type BaselineCase struct {
	OSV        *OSVSelector     `json:"osv,omitempty"`
	SemgrepCE  *SemgrepSelector `json:"semgrep_ce,omitempty"`
	SnykSample *SnykSelector    `json:"snyk_sample,omitempty"`
}

type OSVSelector struct {
	AdvisoryIDs  []string `json:"advisory_ids"`
	SourceSuffix string   `json:"source_suffix"`
}

type SemgrepSelector struct {
	RuleID     string `json:"rule_id"`
	PathSuffix string `json:"path_suffix"`
}

// SnykSelector is deliberately a stable manual-sample locator, not a credential or API token. The sampled
// Snyk runbook produces the same reachbench report format after a human records this evidence id.
type SnykSelector struct {
	EvidenceID string `json:"evidence_id"`
}

// Corpus is one versioned, auditable set of reachability cases.
type Corpus struct {
	SchemaVersion string `json:"schema_version"`
	Cases         []Case `json:"cases"`
}

// Observation is one engine result for a case. Every corpus case must receive exactly one result; an engine
// cannot omit a difficult case and improve its measured recall.
type Observation struct {
	Case  string `json:"case"`
	Label Label  `json:"label"`
}

// Input is the portable hand-off between a fixture runner and the deterministic scorer. An adapter for an
// owned engine or an OSS baseline records its observations against the same embedded-or-checked-in corpus,
// then synapse-bench reduces the input without running either tool itself.
type Input struct {
	SchemaVersion string        `json:"schema_version"`
	Corpus        Corpus        `json:"corpus"`
	Observations  []Observation `json:"observations"`
}

// LanguageScore reports exact-label accuracy plus the positive-reachability precision and recall. Conditional
// reachability is positive too: treating it as absent is a false negative for prioritisation. Precision is
// equally important for the baseline comparison: a candidate cannot buy recall by labelling every case
// reachable.
type LanguageScore struct {
	Language          string  `json:"language"`
	Cases             int     `json:"cases"`
	Exact             int     `json:"exact"`
	ExactAccuracy     float64 `json:"exact_accuracy"`
	PositiveExpected  int     `json:"positive_expected"`
	PositiveFound     int     `json:"positive_found"`
	PositiveProduced  int     `json:"positive_produced"`
	PositivePrecision float64 `json:"positive_precision"`
	PositiveRecall    float64 `json:"positive_recall"`
	FalsePositiveRise int     `json:"false_positive_reachable"`
}

// Report is a stable per-language scorecard. Results are sorted by language for diff-friendly CI output.
type Report struct {
	SchemaVersion string          `json:"schema_version"`
	CorpusDigest  string          `json:"corpus_digest"`
	Cases         int             `json:"cases"`
	Languages     []LanguageScore `json:"languages"`
}

// Floors is the monotonic ratchet. A language absent from PositiveRecall is reported but not yet gated,
// allowing a new engine to land its corpus before maintainers calibrate a reviewed floor.
type Floors struct {
	PositiveRecall map[string]float64 `json:"positive_recall"`
}

//go:embed corpus/reachability.json
var defaultCorpusJSON []byte

//go:embed corpus/floors.json
var defaultFloorsJSON []byte

// DefaultCorpus returns the checked-in corpus. It panics only for a repository-authoring error: tests call
// LoadCorpus directly when they need an error instead of a programming-contract failure.
func DefaultCorpus() Corpus {
	c, err := LoadCorpus(bytes.NewReader(defaultCorpusJSON))
	if err != nil {
		panic("reachbench: embedded corpus is invalid: " + err.Error())
	}
	return c
}

// DefaultFloors returns the checked-in recall ratchet.
func DefaultFloors() Floors {
	f, err := LoadFloors(bytes.NewReader(defaultFloorsJSON))
	if err != nil {
		panic("reachbench: embedded floors are invalid: " + err.Error())
	}
	return f
}

// LoadCorpus decodes exactly one strict corpus document and validates its closed vocabulary.
func LoadCorpus(r io.Reader) (Corpus, error) {
	var c Corpus
	if err := decodeStrict(r, &c, "reachability corpus"); err != nil {
		return Corpus{}, err
	}
	if err := validateCorpus(c); err != nil {
		return Corpus{}, err
	}
	sort.Slice(c.Cases, func(i, j int) bool { return c.Cases[i].Name < c.Cases[j].Name })
	return c, nil
}

// DecodeInput decodes exactly one strict fixture-runner input. It validates the nested corpus before any
// observations are scored, so callers that construct JSON rather than using DefaultCorpus get the same
// closed vocabulary and duplicate-case protections.
func DecodeInput(r io.Reader) (Input, error) {
	var input Input
	if err := decodeStrict(r, &input, "reachability input"); err != nil {
		return Input{}, err
	}
	if input.SchemaVersion != InputSchemaVersion {
		return Input{}, fmt.Errorf("unsupported reachability input schema version %q", input.SchemaVersion)
	}
	if err := validateCorpus(input.Corpus); err != nil {
		return Input{}, err
	}
	return input, nil
}

// EvaluateInput reduces a validated fixture-runner hand-off into its scorecard.
func EvaluateInput(input Input) (Report, error) {
	if input.SchemaVersion != InputSchemaVersion {
		return Report{}, fmt.Errorf("unsupported reachability input schema version %q", input.SchemaVersion)
	}
	if err := validateCorpus(input.Corpus); err != nil {
		return Report{}, err
	}
	return Evaluate(input.Corpus, input.Observations)
}

func validateCorpus(c Corpus) error {
	if c.SchemaVersion != CorpusSchemaVersion {
		return fmt.Errorf("unsupported reachability corpus schema version %q", c.SchemaVersion)
	}
	if len(c.Cases) == 0 {
		return fmt.Errorf("reachability corpus has no cases")
	}
	seen := make(map[string]struct{}, len(c.Cases))
	for i, item := range c.Cases {
		if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Language) == "" || strings.TrimSpace(item.Fixture) == "" || strings.TrimSpace(item.Symbol) == "" {
			return fmt.Errorf("reachability corpus case %d requires name, language, fixture, and symbol", i)
		}
		if item.Name != strings.TrimSpace(item.Name) || item.Language != strings.TrimSpace(item.Language) || item.Fixture != strings.TrimSpace(item.Fixture) || item.Symbol != strings.TrimSpace(item.Symbol) {
			return fmt.Errorf("reachability corpus case %q has surrounding whitespace", item.Name)
		}
		if !item.Expected.valid() {
			return fmt.Errorf("reachability corpus case %q has unknown expected label %q", item.Name, item.Expected)
		}
		if err := validateBaselineCase(item.Name, item.Baseline); err != nil {
			return err
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return fmt.Errorf("duplicate reachability corpus case %q", item.Name)
		}
		seen[item.Name] = struct{}{}
	}
	return nil
}

func validateBaselineCase(name string, baseline BaselineCase) error {
	if selector := baseline.OSV; selector != nil {
		if len(selector.AdvisoryIDs) == 0 || strings.TrimSpace(selector.SourceSuffix) == "" {
			return fmt.Errorf("reachability corpus case %q has an incomplete OSV selector", name)
		}
		seen := map[string]bool{}
		for _, id := range selector.AdvisoryIDs {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				return fmt.Errorf("reachability corpus case %q has an invalid OSV advisory id", name)
			}
			seen[id] = true
		}
	}
	if selector := baseline.SemgrepCE; selector != nil && (strings.TrimSpace(selector.RuleID) == "" || strings.TrimSpace(selector.PathSuffix) == "") {
		return fmt.Errorf("reachability corpus case %q has an incomplete Semgrep CE selector", name)
	}
	if selector := baseline.SnykSample; selector != nil && strings.TrimSpace(selector.EvidenceID) == "" {
		return fmt.Errorf("reachability corpus case %q has an empty Snyk sample evidence id", name)
	}
	return nil
}

// LoadFloors decodes the strict ratchet document and refuses values outside the closed rate interval.
func LoadFloors(r io.Reader) (Floors, error) {
	var f Floors
	if err := decodeStrict(r, &f, "reachability floors"); err != nil {
		return Floors{}, err
	}
	for language, value := range f.PositiveRecall {
		if strings.TrimSpace(language) == "" || language != strings.TrimSpace(language) || value < 0 || value > 1 {
			return Floors{}, fmt.Errorf("invalid reachability recall floor for %q", language)
		}
	}
	return f, nil
}

// Evaluate validates a complete observation set and reduces it to per-language accuracy. It is pure: engine
// adapters own fixture execution while this package owns the corpus vocabulary and score semantics.
func Evaluate(c Corpus, observations []Observation) (Report, error) {
	if err := validateCorpus(c); err != nil {
		return Report{}, err
	}
	byCase := make(map[string]Case, len(c.Cases))
	for _, item := range c.Cases {
		byCase[item.Name] = item
	}
	seen := make(map[string]struct{}, len(observations))
	type aggregate struct{ LanguageScore }
	groups := map[string]*aggregate{}
	for i, observation := range observations {
		item, known := byCase[observation.Case]
		if !known {
			return Report{}, fmt.Errorf("observation %d references unknown corpus case %q", i, observation.Case)
		}
		if !observation.Label.valid() {
			return Report{}, fmt.Errorf("observation %q has unknown label %q", observation.Case, observation.Label)
		}
		if _, duplicate := seen[observation.Case]; duplicate {
			return Report{}, fmt.Errorf("duplicate reachability observation %q", observation.Case)
		}
		seen[observation.Case] = struct{}{}
		group := groups[item.Language]
		if group == nil {
			group = &aggregate{LanguageScore: LanguageScore{Language: item.Language}}
			groups[item.Language] = group
		}
		group.Cases++
		if observation.Label == item.Expected {
			group.Exact++
		}
		if positive(item.Expected) {
			group.PositiveExpected++
			if positive(observation.Label) {
				group.PositiveFound++
			}
		}
		if positive(observation.Label) {
			group.PositiveProduced++
			if !positive(item.Expected) {
				group.FalsePositiveRise++
			}
		}
	}
	if len(seen) != len(c.Cases) {
		missing := make([]string, 0, len(c.Cases)-len(seen))
		for _, item := range c.Cases {
			if _, ok := seen[item.Name]; !ok {
				missing = append(missing, item.Name)
			}
		}
		sort.Strings(missing)
		return Report{}, fmt.Errorf("reachability observations omit corpus cases: %s", strings.Join(missing, ", "))
	}
	digest, err := corpusDigest(c)
	if err != nil {
		return Report{}, err
	}
	report := Report{SchemaVersion: ReportSchemaVersion, CorpusDigest: digest, Cases: len(c.Cases), Languages: make([]LanguageScore, 0, len(groups))}
	for _, group := range groups {
		group.ExactAccuracy = float64(group.Exact) / float64(group.Cases)
		if group.PositiveExpected == 0 {
			group.PositiveRecall = 1
		} else {
			group.PositiveRecall = float64(group.PositiveFound) / float64(group.PositiveExpected)
		}
		if group.PositiveProduced == 0 {
			group.PositivePrecision = 1
		} else {
			group.PositivePrecision = float64(group.PositiveFound) / float64(group.PositiveProduced)
		}
		report.Languages = append(report.Languages, group.LanguageScore)
	}
	sort.Slice(report.Languages, func(i, j int) bool { return report.Languages[i].Language < report.Languages[j].Language })
	return report, nil
}

// CheckRatchet reports every recall regression in deterministic order. Floors only rise in review; code must
// never silently lower a threshold when a new fixture exposes a miss.
func CheckRatchet(report Report, floors Floors) []string {
	var breaches []string
	for _, score := range report.Languages {
		if floor, ok := floors.PositiveRecall[score.Language]; ok && score.PositiveRecall < floor {
			breaches = append(breaches, fmt.Sprintf("%s positive reachability recall %.3f is below ratchet floor %.3f", score.Language, score.PositiveRecall, floor))
		}
	}
	sort.Strings(breaches)
	return breaches
}

// CheckBaselineParity reports a candidate engine that falls below a recorded baseline's positive-reachability
// precision or recall for any language. It refuses a comparison against a different corpus. A missing
// candidate language is a breach rather than an omitted comparison, so a removed adapter cannot silently
// improve a scorecard.
func CheckBaselineParity(candidate, baseline Report) []string {
	if candidate.CorpusDigest == "" || baseline.CorpusDigest == "" || candidate.CorpusDigest != baseline.CorpusDigest {
		return []string{"candidate and baseline reports use different or unbound reachability corpora"}
	}
	candidateByLanguage := make(map[string]LanguageScore, len(candidate.Languages))
	for _, score := range candidate.Languages {
		candidateByLanguage[score.Language] = score
	}
	var breaches []string
	for _, base := range baseline.Languages {
		got, ok := candidateByLanguage[base.Language]
		if !ok {
			breaches = append(breaches, fmt.Sprintf("candidate report omits baseline language %s", base.Language))
			continue
		}
		if got.PositiveRecall < base.PositiveRecall {
			breaches = append(breaches, fmt.Sprintf("%s positive reachability recall %.3f is below baseline %.3f", base.Language, got.PositiveRecall, base.PositiveRecall))
		}
		if got.PositivePrecision < base.PositivePrecision {
			breaches = append(breaches, fmt.Sprintf("%s positive reachability precision %.3f is below baseline %.3f", base.Language, got.PositivePrecision, base.PositivePrecision))
		}
	}
	sort.Strings(breaches)
	return breaches
}

// EncodeReport writes one stable, indented report suitable for a checked-in baseline artifact or CI upload.
func EncodeReport(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode reachability report: %w", err)
	}
	return nil
}

// LoadReport decodes a stored candidate or OSS-baseline report without allowing extra fields or concatenated
// JSON. It verifies the report has the schema and corpus binding required for a meaningful parity check;
// detailed metrics remain the adapter's reproducible evidence and are compared by CheckBaselineParity.
func LoadReport(r io.Reader) (Report, error) {
	var report Report
	if err := decodeStrict(r, &report, "reachability report"); err != nil {
		return Report{}, err
	}
	if report.SchemaVersion != ReportSchemaVersion {
		return Report{}, fmt.Errorf("unsupported reachability report schema version %q", report.SchemaVersion)
	}
	if len(report.CorpusDigest) != sha256.Size*2 {
		return Report{}, fmt.Errorf("reachability report has invalid corpus digest")
	}
	if _, err := hex.DecodeString(report.CorpusDigest); err != nil {
		return Report{}, fmt.Errorf("reachability report has invalid corpus digest: %w", err)
	}
	if report.Cases <= 0 || len(report.Languages) == 0 {
		return Report{}, fmt.Errorf("reachability report has no scored cases")
	}
	seen := make(map[string]struct{}, len(report.Languages))
	total := 0
	for _, score := range report.Languages {
		if strings.TrimSpace(score.Language) == "" || score.Language != strings.TrimSpace(score.Language) {
			return Report{}, fmt.Errorf("reachability report has invalid language")
		}
		if _, duplicate := seen[score.Language]; duplicate {
			return Report{}, fmt.Errorf("duplicate reachability report language %q", score.Language)
		}
		seen[score.Language] = struct{}{}
		if score.Cases <= 0 || score.Exact < 0 || score.Exact > score.Cases || score.PositiveExpected < 0 || score.PositiveExpected > score.Cases || score.PositiveFound < 0 || score.PositiveFound > score.PositiveExpected || score.PositiveProduced < 0 || score.PositiveProduced > score.Cases || score.PositiveFound > score.PositiveProduced || score.FalsePositiveRise < 0 || score.FalsePositiveRise > score.Cases || score.ExactAccuracy < 0 || score.ExactAccuracy > 1 || score.PositivePrecision < 0 || score.PositivePrecision > 1 || score.PositiveRecall < 0 || score.PositiveRecall > 1 {
			return Report{}, fmt.Errorf("reachability report has invalid score for %q", score.Language)
		}
		total += score.Cases
	}
	if total != report.Cases {
		return Report{}, fmt.Errorf("reachability report case count %d does not equal language total %d", report.Cases, total)
	}
	sort.Slice(report.Languages, func(i, j int) bool { return report.Languages[i].Language < report.Languages[j].Language })
	return report, nil
}

func decodeStrict(r io.Reader, target any, name string) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: multiple JSON values", name)
		}
		return fmt.Errorf("decode %s trailing data: %w", name, err)
	}
	return nil
}

func positive(label Label) bool {
	return label == Reachable || label == ConditionallyReachable
}

// corpusDigest binds every scorecard and stored baseline to the exact, sorted corpus it measured. Comparing
// a result against a different corpus can make a lower denominator look like higher recall, so it is a
// fail-closed comparison error rather than a best-effort warning.
func corpusDigest(c Corpus) (string, error) {
	canonical := Corpus{SchemaVersion: c.SchemaVersion, Cases: append([]Case(nil), c.Cases...)}
	sort.Slice(canonical.Cases, func(i, j int) bool { return canonical.Cases[i].Name < canonical.Cases[j].Name })
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode reachability corpus digest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
