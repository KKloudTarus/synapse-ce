package sastbench

// corpus.go generalizes the SAST scorecard beyond OWASP BenchmarkJava to any CWE-anchored corpus (Juliet,
// Securibench Micro, OWASP). The OWASP path in score.go is category-string keyed and file-level; this path is
// keyed directly on CWE and location-aware, because Juliet's ground truth is line-anchored (a good and a bad
// function can live in one file) and Securibench's is annotation-anchored. It mirrors the proven cqbench
// contract (versioned corpus/report, corpus digest binding, comparison-only baseline diff, recall ratchet +
// precision tripwire), adding the real/safe axis a SAST corpus needs: a labelled case is a true vulnerability
// or a sanitized-safe trap, so the confusion matrix scores both, where cqbench's code-quality cases are all
// true and score unmatched detections as the only false positives.
//
// Precision here is still PROPOSE-STAGE (the taint engine models few sanitizers and over-flags safe traps),
// so recall is the regression gate; post-triage precision, scored over the verifier-confirmed subset, is a
// separate report produced by feeding this scorer only the confirmed detections.

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

//go:embed securibench-floors.json
var securibenchFloorsJSON []byte

// LoadCWEFloors decodes a per-CWE ratchet floors document.
func LoadCWEFloors(r io.Reader) (CWEFloors, error) {
	var f CWEFloors
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return CWEFloors{}, fmt.Errorf("decode cwe floors: %w", err)
	}
	return f, nil
}

// DefaultSecuribenchFloors returns the checked-in Securibench Micro recall ratchet, calibrated from a real
// run of the owned engine over the pinned corpus.
func DefaultSecuribenchFloors() CWEFloors {
	f, err := LoadCWEFloors(bytes.NewReader(securibenchFloorsJSON))
	if err != nil {
		panic("sastbench: embedded securibench floors are invalid: " + err.Error())
	}
	return f
}

const (
	// CorpusSchemaVersion and ReportSchemaVersion tag the serialized corpus answer key and the scorecard so a
	// checked-in baseline artifact can never be silently compared against an incompatible schema.
	CorpusSchemaVersion = "synapse-sast-corpus-v1"
	ReportSchemaVersion = "synapse-sast-report-v1"

	// DefaultLineWindow is the half-width of the line window within which a detection matches a labelled case
	// of the same CWE in the same file. Two independent tools attribute the same flow to lines a step apart
	// (the sink call vs the enclosing statement), so an exact-line match understates agreement; two lines
	// absorbs that and still separates a good/bad pair that a corpus places on distinct lines. A case or
	// detection with Line <= 0 is unlocated and matches at file level (the OWASP one-vuln-per-file shape).
	DefaultLineWindow = 2
)

// Finding is one detection emitted by an engine: a CWE at a source location. Line is 1-based; 0 means the
// detection is not line-anchored and matches any case for its CWE in the same file.
type Finding struct {
	File string `json:"file"`
	Line int    `json:"line"`
	CWE  string `json:"cwe"`
}

// LabeledCase is one corpus answer-key row: a known true vulnerability (Real) or a sanitized-safe trap
// (!Real) of a given CWE at a location. Name identifies the case for reporting; File/Line locate it (Line <= 0
// means the case is file-level, matched by CWE presence in the file, the OWASP shape).
type LabeledCase struct {
	Name string `json:"name"`
	File string `json:"file"`
	Line int    `json:"line"`
	CWE  string `json:"cwe"`
	Real bool   `json:"real"`
}

// CWEScore is the confusion matrix and derived precision/recall for one CWE across a corpus.
type CWEScore struct {
	CWE       string  `json:"cwe"`
	Total     int     `json:"total"`
	TP        int     `json:"true_positives"`
	FP        int     `json:"false_positives"`
	FN        int     `json:"false_negatives"`
	TN        int     `json:"true_negatives"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

// Report is a serializable scorecard for one engine over one corpus, suitable for a checked-in baseline or a
// CI upload. CorpusDigest binds the report to the exact answer key it was measured against, so a baseline
// comparison across different corpora is refused.
type Report struct {
	Schema       string     `json:"schema"`
	Engine       string     `json:"engine"`
	Corpus       string     `json:"corpus"`
	CorpusDigest string     `json:"corpus_digest"`
	Stage        string     `json:"stage"`                 // "propose" or "post-triage"
	LineWindow   int        `json:"line_window"`           // the match window this report was scored with
	ScoredCWEs   []string   `json:"scored_cwes,omitempty"` // the CWE set this report scored, for a self-describing artifact
	CWEs         []CWEScore `json:"cwes"`
}

// CWEFloors is the checked-in regression ratchet for the generalized path: minimum recall per CWE plus one
// loose global precision tripwire that catches an all-flagging degeneracy. It mirrors sastbench.Floors but is
// keyed on CWE rather than OWASP category string.
type CWEFloors struct {
	Recall            map[string]float64 `json:"recall"`
	PrecisionTripwire float64            `json:"precision_tripwire"`
}

// ScoreByCWE reduces an engine's detections against a CWE-anchored answer key into a per-CWE scorecard. A real
// case is a true positive when some detection of the same CWE lands in the same file within lineWindow (or, if
// either side is unlocated, anywhere in the file), and a false negative otherwise; a safe case is a false
// positive when such a detection exists and a true negative otherwise. Only CWEs in scoredCWEs are scored, so
// the card never reports on a class the engine does not model; pass a lineWindow < 0 to use DefaultLineWindow.
// The result is sorted by CWE for determinism.
func ScoreByCWE(detected []Finding, cases []LabeledCase, scoredCWEs []string, lineWindow int) []CWEScore {
	if lineWindow < 0 {
		lineWindow = DefaultLineWindow
	}
	scored := make(map[string]bool, len(scoredCWEs))
	agg := make(map[string]*CWEScore, len(scoredCWEs))
	for _, cwe := range scoredCWEs {
		scored[cwe] = true
		if agg[cwe] == nil {
			agg[cwe] = &CWEScore{CWE: cwe}
		}
	}
	// Index detections by (file, CWE) so a case is matched against only the detections that could match it.
	byFileCWE := map[string][]int{}
	for _, d := range detected {
		if !scored[d.CWE] {
			continue
		}
		key := d.File + "\x00" + d.CWE
		byFileCWE[key] = append(byFileCWE[key], d.Line)
	}
	for _, c := range cases {
		s := agg[c.CWE]
		if s == nil {
			continue // an unscored CWE
		}
		s.Total++
		flagged := caseMatched(c, byFileCWE[c.File+"\x00"+c.CWE], lineWindow)
		switch {
		case c.Real && flagged:
			s.TP++
		case c.Real && !flagged:
			s.FN++
		case !c.Real && flagged:
			s.FP++
		default:
			s.TN++
		}
	}
	out := make([]CWEScore, 0, len(agg))
	for _, s := range agg {
		if s.TP+s.FP > 0 {
			s.Precision = float64(s.TP) / float64(s.TP+s.FP)
		}
		if s.TP+s.FN > 0 {
			s.Recall = float64(s.TP) / float64(s.TP+s.FN)
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CWE < out[j].CWE })
	return out
}

// caseMatched reports whether any detection line for the case's (file, CWE) matches the case within the line
// window. An unlocated case (Line <= 0) or an unlocated detection (line <= 0) matches at file level. This is a
// per-case boolean model: one detection can satisfy several cases within its window, so recall can overstate
// if a corpus places multiple TRUE cases within the window of each other (Juliet/Securibench separate their
// good/bad locations by more than the window). It never masks a false positive: a detection near a safe case
// always classifies that case as flagged, so a nearby true case can never "consume" the detection.
func caseMatched(c LabeledCase, detectionLines []int, window int) bool {
	for _, dl := range detectionLines {
		if c.Line <= 0 || dl <= 0 {
			return true // file-level match
		}
		if abs(dl-c.Line) <= window {
			return true
		}
	}
	return false
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// CorpusDigest is a stable content hash of an answer key, so a scorecard can be bound to the exact corpus it
// was measured against. It is order-independent (the rows are canonicalized and sorted first), so two runs
// over the same cases in any order produce the same digest. It binds the ANSWER KEY (the cases) only, not the
// scoring configuration (scored CWE set, line window); those are recorded on the Report and the ratchet and
// improvement checks defend coverage independently, breaching on a dropped floored or baseline CWE.
func CorpusDigest(cases []LabeledCase) string {
	rows := make([]string, 0, len(cases))
	for _, c := range cases {
		rows = append(rows, strings.Join([]string{
			c.Name, c.File, strconv.Itoa(c.Line), c.CWE, strconv.FormatBool(c.Real),
		}, "\x00"))
	}
	sort.Strings(rows)
	h := sha256.New()
	for _, r := range rows {
		h.Write([]byte(r))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EncodeReport writes a stable, indented report suitable for a checked-in baseline artifact or a CI upload.
func EncodeReport(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode sast report: %w", err)
	}
	return nil
}

// LoadReport decodes a report, rejecting an unknown schema so an incompatible baseline is never scored.
func LoadReport(r io.Reader) (Report, error) {
	var rep Report
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		return Report{}, fmt.Errorf("decode sast report: %w", err)
	}
	if rep.Schema != ReportSchemaVersion {
		return Report{}, fmt.Errorf("sast report schema %q is not %q", rep.Schema, ReportSchemaVersion)
	}
	return rep, nil
}

// CheckRatchetByCWE reports every CWE whose recall is below its committed floor, plus any all-flagging
// degeneracy the precision tripwire catches. An empty result means the report meets the ratchet. A CWE with no
// floor is not gated (a new CWE starts ungated until a floor is committed), and the tripwire fires only for a
// CWE that carries labelled true cases (TP+FN > 0) and produced detections (TP+FP > 0), so a stray detection
// in an unmodelled CWE never flips the gate for a reason unrelated to a recall regression.
func CheckRatchetByCWE(report Report, floors CWEFloors) []string {
	var breaches []string
	present := make(map[string]bool, len(report.CWEs))
	for _, s := range report.CWEs {
		present[s.CWE] = true
		if floor, ok := floors.Recall[s.CWE]; ok && s.Recall < floor {
			breaches = append(breaches, fmt.Sprintf("%s recall %.3f is below the ratchet floor %.3f", s.CWE, s.Recall, floor))
		}
		if floors.PrecisionTripwire > 0 && s.TP+s.FN > 0 && s.TP+s.FP > 0 && s.Precision < floors.PrecisionTripwire {
			breaches = append(breaches, fmt.Sprintf("%s precision %.3f is below the degeneracy tripwire %.3f (near-all-flagging?)", s.CWE, s.Precision, floors.PrecisionTripwire))
		}
	}
	// A committed floor is a promise to gate that CWE. A report that no longer covers it (its adapter dropped
	// the CWE from the scored set) must breach, not silently pass, or the ratchet could be bypassed by removing
	// coverage instead of regressing it.
	for cwe := range floors.Recall {
		if !present[cwe] {
			breaches = append(breaches, fmt.Sprintf("%s has a committed recall floor but is absent from the report (coverage dropped)", cwe))
		}
	}
	sort.Strings(breaches)
	return breaches
}

// CompareToBaseline reports, per CWE, how the owned engine's recall/precision compares to a baseline engine's
// on the SAME corpus. It refuses a comparison across different or unbound corpora, and lists a CWE present in
// only one report so a dropped adapter cannot silently omit a comparison. The result is a human-readable
// head-to-head, not a gate: the competitor is comparison data, and the owned ratchet is enforced separately.
func CompareToBaseline(owned, baseline Report) ([]string, error) {
	if owned.CorpusDigest == "" || baseline.CorpusDigest == "" || owned.CorpusDigest != baseline.CorpusDigest {
		return nil, fmt.Errorf("owned and baseline reports measured different or unbound corpora")
	}
	ownedCWEs := make(map[string]CWEScore, len(owned.CWEs))
	for _, s := range owned.CWEs {
		ownedCWEs[s.CWE] = s
	}
	baseCWEs := make(map[string]CWEScore, len(baseline.CWEs))
	for _, s := range baseline.CWEs {
		baseCWEs[s.CWE] = s
	}
	keys := map[string]struct{}{}
	for k := range ownedCWEs {
		keys[k] = struct{}{}
	}
	for k := range baseCWEs {
		keys[k] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	lines := make([]string, 0, len(ordered))
	for _, k := range ordered {
		o, hasO := ownedCWEs[k]
		b, hasB := baseCWEs[k]
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

// ImprovedOverBaseline reports whether every CWE's precision and recall in owned are at least the baseline's
// minus eps (no regression) AND at least one CWE strictly improves in precision. It is the post-triage
// acceptance check: the verifier-confirmed report must beat the committed pre-change baseline on precision
// without suppressing true findings to do so. CheckRatchetByCWE still enforces the absolute recall floors.
func ImprovedOverBaseline(owned, baseline Report, eps float64) (improved bool, detail []string, err error) {
	if owned.CorpusDigest == "" || baseline.CorpusDigest == "" || owned.CorpusDigest != baseline.CorpusDigest {
		return false, nil, fmt.Errorf("owned and baseline reports measured different or unbound corpora")
	}
	base := make(map[string]CWEScore, len(baseline.CWEs))
	for _, s := range baseline.CWEs {
		base[s.CWE] = s
	}
	ownedSet := make(map[string]bool, len(owned.CWEs))
	regressed := false
	anyBetter := false
	for _, o := range owned.CWEs {
		ownedSet[o.CWE] = true
		b, ok := base[o.CWE]
		if !ok {
			continue
		}
		switch {
		case o.Precision < b.Precision-eps:
			regressed = true
			detail = append(detail, fmt.Sprintf("%s precision regressed %.3f -> %.3f", o.CWE, b.Precision, o.Precision))
		case o.Precision > b.Precision+eps:
			anyBetter = true
			detail = append(detail, fmt.Sprintf("%s precision improved %.3f -> %.3f", o.CWE, b.Precision, o.Precision))
		}
		if o.Recall < b.Recall-eps {
			regressed = true
			detail = append(detail, fmt.Sprintf("%s recall regressed %.3f -> %.3f", o.CWE, b.Recall, o.Recall))
		}
	}
	// A CWE the baseline covered but owned no longer reports is a coverage loss, not an improvement.
	for _, b := range baseline.CWEs {
		if !ownedSet[b.CWE] {
			regressed = true
			detail = append(detail, fmt.Sprintf("%s dropped from owned (baseline precision %.3f)", b.CWE, b.Precision))
		}
	}
	sort.Strings(detail)
	return !regressed && anyBetter, detail, nil
}
