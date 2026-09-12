// Package sastbench scores the owned SAST/taint engine against a standard external benchmark (OWASP
// BenchmarkJava) and reduces the result to a per-category precision/recall scorecard with a regression
// ratchet. It is a pure reducer: the engine's detections and the benchmark's answer key are passed in, so
// this package holds no infrastructure and is deterministic. The scorecard is scoped to the CWE classes the
// engine MODELS (command injection, SQL injection, path traversal); categories it does not model are
// reported as "not covered" rather than scored, so the numbers never misrepresent the engine on a
// vulnerability class it does not claim.
//
// The precision figure is PROPOSE-STAGE: the taint engine is a propose-stage proposer that deliberately
// models no sanitizers, so it flags the benchmark's sanitized-safe variants (which a downstream verify /
// triage stage filters). Recall is therefore the meaningful regression signal, and the ratchet gates on it.
package sastbench

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// ScoredCategories maps each OWASP BenchmarkJava category the engine models to the CWE the engine emits for
// it. Categories the engine does not model (xss, crypto, hash, ldapi, xpathi, trustbound, weakrand,
// securecookie) are intentionally absent and reported as not-covered.
var ScoredCategories = map[string]string{
	"cmdi":       "CWE-78",
	"sqli":       "CWE-89",
	"pathtraver": "CWE-22",
}

// Case is one benchmark test case from the answer key: its test name, category, and whether it is a real
// (true-positive) vulnerability or a sanitized-safe (false-positive trap) variant.
type Case struct {
	Name     string
	Category string
	Real     bool
}

// CategoryScore is the confusion matrix and derived precision/recall for one scored category.
type CategoryScore struct {
	Category  string  `json:"category"`
	CWE       string  `json:"cwe"`
	Total     int     `json:"total"`
	TP        int     `json:"true_positives"`
	FP        int     `json:"false_positives"`
	FN        int     `json:"false_negatives"`
	TN        int     `json:"true_negatives"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

// Score reduces the engine's detections against the answer key into a per-scored-category scorecard. detected
// maps a test name to the set of CWEs the engine emitted for it; a category's TP/FP is decided by whether the
// engine emitted that category's CWE for the test. Cases in unscored categories are ignored. The result is
// sorted by category for determinism.
func Score(detected map[string]map[string]bool, cases []Case) []CategoryScore {
	agg := map[string]*CategoryScore{}
	for cat, cwe := range ScoredCategories {
		agg[cat] = &CategoryScore{Category: cat, CWE: cwe}
	}
	for _, c := range cases {
		s := agg[c.Category]
		if s == nil {
			continue // an unscored category
		}
		s.Total++
		flagged := detected[c.Name][s.CWE]
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
	out := make([]CategoryScore, 0, len(agg))
	for _, s := range agg {
		if s.TP+s.FP > 0 {
			s.Precision = float64(s.TP) / float64(s.TP+s.FP)
		}
		if s.TP+s.FN > 0 {
			s.Recall = float64(s.TP) / float64(s.TP+s.FN)
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}

// Floors is the checked-in regression ratchet: the minimum recall each scored category must hold. Floors only
// rise (they are raised by hand as the engine improves), so a drop below a floor fails the gate. Recall is the
// primary gate; precision is understated by the no-sanitizer propose-stage design so it is NOT gated at the
// real value. PrecisionTripwire is a single LOOSE global floor, well below the observed precision, that only
// fires on a degeneracy: an engine change that flags nearly everything would drive recall up (passing the
// recall ratchet) while precision collapses, and the tripwire catches exactly that.
type Floors struct {
	Recall            map[string]float64 `json:"recall"`
	PrecisionTripwire float64            `json:"precision_tripwire"`
}

// LoadFloors decodes a ratchet floors document.
func LoadFloors(r io.Reader) (Floors, error) {
	var f Floors
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Floors{}, fmt.Errorf("decode sast benchmark floors: %w", err)
	}
	return f, nil
}

// CheckRatchet reports every scored category whose recall is below its floor (a regression). An empty result
// means the scorecard meets the ratchet. A category with no floor is not gated (a new category starts
// ungated until a floor is committed).
func CheckRatchet(scores []CategoryScore, floors Floors) []string {
	var breaches []string
	for _, s := range scores {
		if floor, ok := floors.Recall[s.Category]; ok && s.Recall < floor {
			breaches = append(breaches, fmt.Sprintf("%s recall %.3f is below the ratchet floor %.3f", s.Category, s.Recall, floor))
		}
		// Degeneracy tripwire: a category that produced findings but whose precision collapsed below the loose
		// global floor signals an all-flagging regression the recall gate would otherwise miss.
		if floors.PrecisionTripwire > 0 && s.TP+s.FP > 0 && s.Precision < floors.PrecisionTripwire {
			breaches = append(breaches, fmt.Sprintf("%s precision %.3f is below the degeneracy tripwire %.3f (near-all-flagging?)", s.Category, s.Precision, floors.PrecisionTripwire))
		}
	}
	sort.Strings(breaches)
	return breaches
}

//go:embed owasp-benchmark-floors.json
var defaultFloorsJSON []byte

// DefaultFloors returns the checked-in regression ratchet floors. The gated OWASP benchmark test and any
// callers share this one committed source of truth.
func DefaultFloors() Floors {
	f, err := LoadFloors(bytes.NewReader(defaultFloorsJSON))
	if err != nil {
		panic("sastbench: embedded floors are invalid: " + err.Error())
	}
	return f
}
