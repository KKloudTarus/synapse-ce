// Package cqbench defines the deterministic code-quality accuracy corpus contract and its regression
// ratchet, and reduces an engine's detections into a per-language, per-issue-type precision/recall scorecard
// plus a metric-agreement section. It is a pure reducer: the engine's detections and the corpus answer key
// are passed in, so this package holds no infrastructure and is deterministic.
//
// The scorecard is engine-agnostic. Issues are labelled by their SonarQube-compatible Type (bug,
// vulnerability, code_smell, security_hotspot), which the owned rule catalog already emits, so the owned
// engine and an external baseline (SonarQube CE) are scored on the same axis without relabelling either
// tool's rule ids. A detection matches a labelled issue when it lands in the same file, carries the same
// type, and falls within a small line window, which absorbs the line-attribution differences between two
// independent engines on the same source.
package cqbench

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
	CorpusSchemaVersion = "synapse-codequality-corpus-v1"
	InputSchemaVersion  = "synapse-codequality-input-v1"
	ReportSchemaVersion = "synapse-codequality-report-v1"

	// lineTolerance is the half-width of the line window within which a detection matches a labelled issue of
	// the same type in the same file. Curated fixtures place one issue per location; two independent engines
	// (owned vs SonarQube CE) routinely attribute the same defect to lines a step apart (the statement vs the
	// enclosing block), so an exact-line match would understate agreement. Two lines is wide enough to absorb
	// that and narrow enough that two distinct issues in a fixture never collide.
	lineTolerance = 2
)

// IssueType is the closed, SonarQube-compatible issue taxonomy. Both the owned engine (via the rule catalog's
// rule.Type) and the external baseline map their detections onto it, so the head-to-head compares like with
// like.
type IssueType string

const (
	TypeBug             IssueType = "bug"
	TypeVulnerability   IssueType = "vulnerability"
	TypeCodeSmell       IssueType = "code_smell"
	TypeSecurityHotspot IssueType = "security_hotspot"
)

func (t IssueType) valid() bool {
	switch t {
	case TypeBug, TypeVulnerability, TypeCodeSmell, TypeSecurityHotspot:
		return true
	}
	return false
}

// Issue is one labelled or detected issue at a source location. File is the fixture-relative path (forward
// slashes), Line is 1-based.
type Issue struct {
	File string    `json:"file"`
	Line int       `json:"line"`
	Type IssueType `json:"type"`
}

// Case is one labelled fixture: a source tree under Fixture with a known set of true issues. Metrics, when
// present, carries the fixture's ground-truth structural measures for the metric-agreement section; a case
// that does not label metrics is scored on issues only.
type Case struct {
	Name     string   `json:"name"`
	Language string   `json:"language"`
	Fixture  string   `json:"fixture"`
	Issues   []Issue  `json:"issues"`
	Metrics  *Metrics `json:"metrics,omitempty"`
}

// Metrics is the ground-truth (or engine-observed) structural measure of one fixture. Pointers distinguish
// "measured zero" from "not measured": a nil field is unmeasured and excluded from agreement, never scored as
// a zero.
type Metrics struct {
	MaxCyclomatic   *int     `json:"max_cyclomatic,omitempty"`
	DuplicatedLines *int     `json:"duplicated_lines,omitempty"`
	CoveragePercent *float64 `json:"coverage_percent,omitempty"`
}

// Corpus is one versioned, auditable set of code-quality cases.
type Corpus struct {
	SchemaVersion string `json:"schema_version"`
	Cases         []Case `json:"cases"`
}

// CaseObservation is one engine's result for a single corpus case: the issues it detected and, optionally,
// the metrics it measured. Every corpus case must receive exactly one observation; an engine cannot omit a
// hard case to inflate its precision.
type CaseObservation struct {
	Case    string   `json:"case"`
	Issues  []Issue  `json:"issues"`
	Metrics *Metrics `json:"metrics,omitempty"`
}

// Input is the portable hand-off between a fixture runner and this reducer. An adapter for the owned engine
// or the SonarQube CE baseline records its observations against the same corpus, then the reducer scores the
// input without running either tool.
type Input struct {
	SchemaVersion string            `json:"schema_version"`
	Engine        string            `json:"engine"`
	Corpus        Corpus            `json:"corpus"`
	Observations  []CaseObservation `json:"observations"`
}

// TypeScore is the confusion matrix and derived precision/recall for one (language, issue type) cell.
type TypeScore struct {
	Language  string    `json:"language"`
	Type      IssueType `json:"type"`
	Expected  int       `json:"expected"`
	Detected  int       `json:"detected"`
	TP        int       `json:"true_positives"`
	FP        int       `json:"false_positives"`
	FN        int       `json:"false_negatives"`
	Precision float64   `json:"precision"`
	Recall    float64   `json:"recall"`
}

// MetricAgreement reports, per metric, how many fixtures the engine measured in agreement with the corpus
// ground truth (within tolerance) out of the fixtures that label that metric. It is a coarse "does the engine
// measure the same structure" signal, not a per-line comparison.
type MetricAgreement struct {
	Metric     string  `json:"metric"`
	Comparable int     `json:"comparable"`
	Agreed     int     `json:"agreed"`
	Agreement  float64 `json:"agreement"`
}

// Report is a stable scorecard for one engine over one corpus. Cells and metrics are sorted for diff-friendly
// CI output, and CorpusDigest binds the report to the exact corpus it measured so two engines can only be
// compared head to head when they scored the identical corpus.
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	Engine        string            `json:"engine"`
	CorpusDigest  string            `json:"corpus_digest"`
	Cases         int               `json:"cases"`
	Types         []TypeScore       `json:"types"`
	Metrics       []MetricAgreement `json:"metrics"`
}

// Floors is the monotonic ratchet: the minimum recall each "language/type" cell must hold, plus a single
// loose precision tripwire that fires only on an all-flagging degeneracy. Floors only rise in review. A cell
// absent from Recall is reported but not yet gated, so a new corpus can land before maintainers calibrate a
// reviewed floor.
type Floors struct {
	Recall            map[string]float64 `json:"recall"`
	PrecisionTripwire float64            `json:"precision_tripwire"`
}

//go:embed corpus/codequality.json
var defaultCorpusJSON []byte

//go:embed corpus/floors.json
var defaultFloorsJSON []byte

// DefaultCorpus returns the checked-in corpus. It panics only on a repository-authoring error; tests call
// LoadCorpus directly when they want an error instead of a programming-contract failure.
func DefaultCorpus() Corpus {
	c, err := LoadCorpus(bytes.NewReader(defaultCorpusJSON))
	if err != nil {
		panic("cqbench: embedded corpus is invalid: " + err.Error())
	}
	return c
}

// DefaultFloors returns the checked-in recall ratchet.
func DefaultFloors() Floors {
	f, err := LoadFloors(bytes.NewReader(defaultFloorsJSON))
	if err != nil {
		panic("cqbench: embedded floors are invalid: " + err.Error())
	}
	return f
}

// CellKey is the ratchet key for a (language, type) cell, e.g. "go/bug".
func CellKey(language string, t IssueType) string { return language + "/" + string(t) }

// LoadCorpus decodes exactly one strict corpus document and validates its closed vocabulary.
func LoadCorpus(r io.Reader) (Corpus, error) {
	var c Corpus
	if err := decodeStrict(r, &c, "code-quality corpus"); err != nil {
		return Corpus{}, err
	}
	if err := validateCorpus(c); err != nil {
		return Corpus{}, err
	}
	sort.Slice(c.Cases, func(i, j int) bool { return c.Cases[i].Name < c.Cases[j].Name })
	return c, nil
}

// LoadFloors decodes the strict ratchet document and refuses values outside the closed rate interval.
func LoadFloors(r io.Reader) (Floors, error) {
	var f Floors
	if err := decodeStrict(r, &f, "code-quality floors"); err != nil {
		return Floors{}, err
	}
	for cell, value := range f.Recall {
		if strings.TrimSpace(cell) == "" || cell != strings.TrimSpace(cell) || value < 0 || value > 1 {
			return Floors{}, fmt.Errorf("invalid code-quality recall floor for %q", cell)
		}
	}
	if f.PrecisionTripwire < 0 || f.PrecisionTripwire > 1 {
		return Floors{}, fmt.Errorf("invalid code-quality precision tripwire %v", f.PrecisionTripwire)
	}
	return f, nil
}

// DecodeInput decodes exactly one strict fixture-runner input, validating the nested corpus first.
func DecodeInput(r io.Reader) (Input, error) {
	var input Input
	if err := decodeStrict(r, &input, "code-quality input"); err != nil {
		return Input{}, err
	}
	if input.SchemaVersion != InputSchemaVersion {
		return Input{}, fmt.Errorf("unsupported code-quality input schema version %q", input.SchemaVersion)
	}
	if strings.TrimSpace(input.Engine) == "" {
		return Input{}, fmt.Errorf("code-quality input has no engine name")
	}
	if err := validateCorpus(input.Corpus); err != nil {
		return Input{}, err
	}
	return input, nil
}

// EvaluateInput reduces a validated fixture-runner hand-off into its scorecard.
func EvaluateInput(input Input) (Report, error) {
	if input.SchemaVersion != InputSchemaVersion {
		return Report{}, fmt.Errorf("unsupported code-quality input schema version %q", input.SchemaVersion)
	}
	return Evaluate(input.Engine, input.Corpus, input.Observations)
}

func validateCorpus(c Corpus) error {
	if c.SchemaVersion != CorpusSchemaVersion {
		return fmt.Errorf("unsupported code-quality corpus schema version %q", c.SchemaVersion)
	}
	if len(c.Cases) == 0 {
		return fmt.Errorf("code-quality corpus has no cases")
	}
	seen := make(map[string]struct{}, len(c.Cases))
	seenFixture := make(map[string]string, len(c.Cases)) // fixture dir -> first case using it
	for i, item := range c.Cases {
		if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Language) == "" || strings.TrimSpace(item.Fixture) == "" {
			return fmt.Errorf("code-quality corpus case %d requires name, language, and fixture", i)
		}
		if item.Name != strings.TrimSpace(item.Name) || item.Language != strings.TrimSpace(item.Language) || item.Fixture != strings.TrimSpace(item.Fixture) {
			return fmt.Errorf("code-quality corpus case %q has surrounding whitespace", item.Name)
		}
		if err := validateIssues(item.Name, item.Issues); err != nil {
			return err
		}
		if err := validateMetrics(item.Name, item.Metrics); err != nil {
			return err
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return fmt.Errorf("duplicate code-quality corpus case %q", item.Name)
		}
		seen[item.Name] = struct{}{}
		// Two cases sharing a fixture dir would double-count that fixture's findings under both case names in
		// the owned path and be rejected in the SonarQube path (SonarQube components cannot attribute one dir
		// to two cases). Reject it here so both reducers agree.
		if prev, dup := seenFixture[item.Fixture]; dup {
			return fmt.Errorf("code-quality corpus cases %q and %q share fixture %q", prev, item.Name, item.Fixture)
		}
		seenFixture[item.Fixture] = item.Name
	}
	return nil
}

func validateIssues(caseName string, issues []Issue) error {
	for j, iss := range issues {
		if strings.TrimSpace(iss.File) == "" || iss.File != strings.TrimSpace(iss.File) {
			return fmt.Errorf("code-quality case %q issue %d has an empty or padded file", caseName, j)
		}
		if iss.Line < 1 {
			return fmt.Errorf("code-quality case %q issue %d has a non-positive line", caseName, j)
		}
		if !iss.Type.valid() {
			return fmt.Errorf("code-quality case %q issue %d has unknown type %q", caseName, j, iss.Type)
		}
	}
	return nil
}

func validateMetrics(caseName string, m *Metrics) error {
	if m == nil {
		return nil
	}
	if m.MaxCyclomatic != nil && *m.MaxCyclomatic < 0 {
		return fmt.Errorf("code-quality case %q has a negative max_cyclomatic", caseName)
	}
	if m.DuplicatedLines != nil && *m.DuplicatedLines < 0 {
		return fmt.Errorf("code-quality case %q has a negative duplicated_lines", caseName)
	}
	if m.CoveragePercent != nil && (*m.CoveragePercent < 0 || *m.CoveragePercent > 100) {
		return fmt.Errorf("code-quality case %q has a coverage_percent outside [0,100]", caseName)
	}
	return nil
}

// Evaluate validates a complete observation set and reduces it to the per-cell scorecard. It is pure: engine
// adapters own fixture execution while this package owns the corpus vocabulary and score semantics. Every
// corpus case must be observed exactly once.
func Evaluate(engine string, c Corpus, observations []CaseObservation) (Report, error) {
	if strings.TrimSpace(engine) == "" {
		return Report{}, fmt.Errorf("code-quality report requires an engine name")
	}
	if err := validateCorpus(c); err != nil {
		return Report{}, err
	}
	byCase := make(map[string]Case, len(c.Cases))
	for _, item := range c.Cases {
		byCase[item.Name] = item
	}
	seen := make(map[string]struct{}, len(observations))
	cells := map[string]*TypeScore{}
	metricAgg := newMetricAggregator()
	for i, obs := range observations {
		item, known := byCase[obs.Case]
		if !known {
			return Report{}, fmt.Errorf("observation %d references unknown corpus case %q", i, obs.Case)
		}
		if _, duplicate := seen[obs.Case]; duplicate {
			return Report{}, fmt.Errorf("duplicate code-quality observation %q", obs.Case)
		}
		seen[obs.Case] = struct{}{}
		if err := validateIssues(obs.Case, obs.Issues); err != nil {
			return Report{}, err
		}
		if err := validateMetrics(obs.Case, obs.Metrics); err != nil {
			return Report{}, err
		}
		scoreCase(item, obs, cells)
		metricAgg.add(item.Metrics, obs.Metrics)
	}
	if len(seen) != len(c.Cases) {
		missing := make([]string, 0, len(c.Cases)-len(seen))
		for _, item := range c.Cases {
			if _, ok := seen[item.Name]; !ok {
				missing = append(missing, item.Name)
			}
		}
		sort.Strings(missing)
		return Report{}, fmt.Errorf("code-quality observations omit corpus cases: %s", strings.Join(missing, ", "))
	}
	digest, err := corpusDigest(c)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		Engine:        engine,
		CorpusDigest:  digest,
		Cases:         len(c.Cases),
		Types:         finalizeCells(cells),
		Metrics:       metricAgg.finalize(),
	}
	return report, nil
}

// scoreCase matches an observation's issues against a case's labelled issues, greedily one-to-one within each
// (file, type) group by nearest line inside the tolerance window, and folds the confusion counts into cells.
func scoreCase(item Case, obs CaseObservation, cells map[string]*TypeScore) {
	type group struct {
		expected []Issue
		detected []Issue
	}
	groups := map[string]*group{} // key: file + "\x00" + type
	groupKey := func(iss Issue) string { return iss.File + "\x00" + string(iss.Type) }
	touch := func(iss Issue) *group {
		k := groupKey(iss)
		g := groups[k]
		if g == nil {
			g = &group{}
			groups[k] = g
		}
		return g
	}
	for _, e := range item.Issues {
		g := touch(e)
		g.expected = append(g.expected, e)
	}
	for _, d := range obs.Issues {
		g := touch(d)
		g.detected = append(g.detected, d)
	}
	for _, g := range groups {
		tp, fp, fn := matchGroup(g.expected, g.detected)
		// Every issue in a group shares a type + language (the case's language).
		var t IssueType
		switch {
		case len(g.expected) > 0:
			t = g.expected[0].Type
		case len(g.detected) > 0:
			t = g.detected[0].Type
		default:
			continue
		}
		cell := cellFor(cells, item.Language, t)
		cell.Expected += len(g.expected)
		cell.Detected += len(g.detected)
		cell.TP += tp
		cell.FP += fp
		cell.FN += fn
	}
}

// matchGroup one-to-one matches detections to expected issues within a single (file, type) group and returns
// (true positives, false positives, false negatives). Both lists are sorted by line and swept with two
// pointers, which is optimal (maximum-cardinality) for this monotone interval matching: since both lines only
// rise, an expected issue below the current detection's window can never match a later (higher) detection and
// is a miss, and a detection below the current expected issue's window is spurious. A nearest-first greedy
// would undercount a crossed pair (expected [1,3], detected [3,5] with tolerance 2 optimally matches both).
func matchGroup(expected, detected []Issue) (tp, fp, fn int) {
	exp := append([]Issue(nil), expected...)
	det := append([]Issue(nil), detected...)
	sort.Slice(exp, func(i, j int) bool { return exp[i].Line < exp[j].Line })
	sort.Slice(det, func(i, j int) bool { return det[i].Line < det[j].Line })
	i, j := 0, 0
	for i < len(exp) && j < len(det) {
		switch diff := det[j].Line - exp[i].Line; {
		case diff > lineTolerance:
			i++ // exp[i] is below det[j]'s window; det only rises, so exp[i] can never match: a miss
		case diff < -lineTolerance:
			j++ // det[j] is below exp[i]'s window; exp only rises, so det[j] is spurious
		default:
			tp++
			i++
			j++
		}
	}
	return tp, len(det) - tp, len(exp) - tp
}

func cellFor(cells map[string]*TypeScore, language string, t IssueType) *TypeScore {
	k := CellKey(language, t)
	cell := cells[k]
	if cell == nil {
		cell = &TypeScore{Language: language, Type: t}
		cells[k] = cell
	}
	return cell
}

func finalizeCells(cells map[string]*TypeScore) []TypeScore {
	out := make([]TypeScore, 0, len(cells))
	for _, cell := range cells {
		if cell.TP+cell.FP > 0 {
			cell.Precision = float64(cell.TP) / float64(cell.TP+cell.FP)
		}
		if cell.TP+cell.FN > 0 {
			cell.Recall = float64(cell.TP) / float64(cell.TP+cell.FN)
		}
		out = append(out, *cell)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Language != out[j].Language {
			return out[i].Language < out[j].Language
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// CheckRatchet reports every recall regression in deterministic order, plus any all-flagging degeneracy the
// precision tripwire catches. An empty result means the scorecard meets the ratchet. A cell with no floor is
// not gated.
func CheckRatchet(report Report, floors Floors) []string {
	var breaches []string
	for _, cell := range report.Types {
		key := CellKey(cell.Language, cell.Type)
		if floor, ok := floors.Recall[key]; ok && cell.Recall < floor {
			breaches = append(breaches, fmt.Sprintf("%s recall %.3f is below ratchet floor %.3f", key, cell.Recall, floor))
		}
		// The tripwire only applies to cells that carry labelled issues (TP+FN > 0). Precision in a cell with
		// no ground-truth expected issues is not a degeneracy signal (there is nothing to recall), and gating
		// it would contradict the "a cell with no floor is not gated" contract: one stray detection in an
		// unmodelled (language, type) cell would flip the gate red for a reason unrelated to a recall regression.
		if floors.PrecisionTripwire > 0 && cell.TP+cell.FN > 0 && cell.TP+cell.FP > 0 && cell.Precision < floors.PrecisionTripwire {
			breaches = append(breaches, fmt.Sprintf("%s precision %.3f is below the degeneracy tripwire %.3f (near-all-flagging?)", key, cell.Precision, floors.PrecisionTripwire))
		}
	}
	sort.Strings(breaches)
	return breaches
}

// CompareToBaseline reports, per cell, how the owned engine's recall compares to a baseline engine's on the
// SAME corpus. It refuses a comparison across different corpora. Cells present in only one report are listed
// so a removed adapter cannot silently drop a comparison. The result is a human-readable head-to-head, not a
// gate: the acceptance records Synapse vs the baseline, and the owned ratchet is enforced separately.
func CompareToBaseline(owned, baseline Report) ([]string, error) {
	if owned.CorpusDigest == "" || baseline.CorpusDigest == "" || owned.CorpusDigest != baseline.CorpusDigest {
		return nil, fmt.Errorf("owned and baseline reports measured different or unbound corpora")
	}
	baseCells := make(map[string]TypeScore, len(baseline.Types))
	for _, cell := range baseline.Types {
		baseCells[CellKey(cell.Language, cell.Type)] = cell
	}
	ownedCells := make(map[string]TypeScore, len(owned.Types))
	for _, cell := range owned.Types {
		ownedCells[CellKey(cell.Language, cell.Type)] = cell
	}
	keys := map[string]struct{}{}
	for k := range baseCells {
		keys[k] = struct{}{}
	}
	for k := range ownedCells {
		keys[k] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	lines := make([]string, 0, len(ordered))
	for _, k := range ordered {
		o, hasO := ownedCells[k]
		b, hasB := baseCells[k]
		switch {
		case hasO && hasB:
			lines = append(lines, fmt.Sprintf("%s: owned recall %.3f / precision %.3f vs %s recall %.3f / precision %.3f",
				k, o.Recall, o.Precision, baseline.Engine, b.Recall, b.Precision))
		case hasO:
			lines = append(lines, fmt.Sprintf("%s: owned recall %.3f / precision %.3f vs %s (no detections)", k, o.Recall, o.Precision, baseline.Engine))
		default:
			lines = append(lines, fmt.Sprintf("%s: owned (no detections) vs %s recall %.3f / precision %.3f", k, baseline.Engine, b.Recall, b.Precision))
		}
	}
	return lines, nil
}

// EncodeReport writes one stable, indented report suitable for a checked-in baseline artifact or CI upload.
func EncodeReport(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode code-quality report: %w", err)
	}
	return nil
}

// LoadReport decodes a stored engine report without allowing extra fields or concatenated JSON, and checks
// the schema and corpus binding a head-to-head comparison requires.
func LoadReport(r io.Reader) (Report, error) {
	var report Report
	if err := decodeStrict(r, &report, "code-quality report"); err != nil {
		return Report{}, err
	}
	if report.SchemaVersion != ReportSchemaVersion {
		return Report{}, fmt.Errorf("unsupported code-quality report schema version %q", report.SchemaVersion)
	}
	if strings.TrimSpace(report.Engine) == "" {
		return Report{}, fmt.Errorf("code-quality report has no engine name")
	}
	if len(report.CorpusDigest) != sha256.Size*2 {
		return Report{}, fmt.Errorf("code-quality report has an invalid corpus digest")
	}
	if _, err := hex.DecodeString(report.CorpusDigest); err != nil {
		return Report{}, fmt.Errorf("code-quality report has an invalid corpus digest: %w", err)
	}
	if report.Cases <= 0 {
		return Report{}, fmt.Errorf("code-quality report has no scored cases")
	}
	for _, cell := range report.Types {
		if !cell.Type.valid() || strings.TrimSpace(cell.Language) == "" {
			return Report{}, fmt.Errorf("code-quality report has an invalid cell %s/%s", cell.Language, cell.Type)
		}
		if cell.TP < 0 || cell.FP < 0 || cell.FN < 0 || cell.Precision < 0 || cell.Precision > 1 || cell.Recall < 0 || cell.Recall > 1 {
			return Report{}, fmt.Errorf("code-quality report has an invalid score for %s", CellKey(cell.Language, cell.Type))
		}
	}
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

// corpusDigest binds every scorecard to the exact, sorted corpus it measured, so comparing a result against a
// different corpus is a fail-closed error rather than a silently misleading number.
func corpusDigest(c Corpus) (string, error) {
	canonical := Corpus{SchemaVersion: c.SchemaVersion, Cases: append([]Case(nil), c.Cases...)}
	sort.Slice(canonical.Cases, func(i, j int) bool { return canonical.Cases[i].Name < canonical.Cases[j].Name })
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode code-quality corpus digest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
