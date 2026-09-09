package benchmark

// Detection-accuracy reduction. This is the counterpart to the throughput/latency
// reduction in benchmark.go, for the SCANNER's own precision and recall: given, per
// evaluation case, the set of ground-truth detections and the set the engine produced,
// it reduces to precision, recall, F1, and false-positive / false-negative rates,
// overall and grouped (e.g. per ecosystem) so a ratchet can gate each group. It is a
// pure reduction: it runs no scan and does no I/O. The caller resolves any alias
// matching into a shared key vocabulary before handing observations here.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	// AccuracyInputSchemaVersion / AccuracyReportSchemaVersion version the accuracy
	// document shapes independently of the throughput benchmark schemas above.
	AccuracyInputSchemaVersion  = "synapse-accuracy-input-v1"
	AccuracyReportSchemaVersion = "synapse-accuracy-report-v1"
)

// AccuracyObservation is one evaluation case: the ground-truth detection keys and the
// keys the engine produced for the same input. Keys are opaque, already-normalized
// strings (the caller decides the vocabulary, e.g. "component|CVE-id"); matching here
// is exact set membership. Group buckets the case (e.g. by ecosystem) for a per-group
// ratchet; an empty Group counts only toward the overall totals.
type AccuracyObservation struct {
	Case     string   `json:"case"`
	Group    string   `json:"group,omitempty"`
	Expected []string `json:"expected"`
	Produced []string `json:"produced"`
}

// AccuracyInput is a set of observations to reduce.
type AccuracyInput struct {
	SchemaVersion string                `json:"schema_version"`
	Observations  []AccuracyObservation `json:"observations"`
}

// Metrics is the reduced confusion-matrix summary. Rates use these conventions so the
// no-data cases never produce a NaN that would make a ratchet undefined:
//   - Precision = TP/(TP+FP); 1.0 when nothing was produced (no false alarms).
//   - Recall    = TP/(TP+FN); 1.0 when nothing was expected (nothing to miss).
//   - F1        = 2PR/(P+R);  0   when P+R == 0.
//   - FalseDiscoveryRate = FP/(TP+FP) = 1 - Precision; 0 when nothing was produced. This is
//     deliberately the false-discovery rate, not the textbook false-positive rate FP/(FP+TN):
//     detection has no bounded universe of true negatives to count, so FPR is not computable.
//   - FalseNegativeRate = FN/(TP+FN) = 1 - Recall (the miss rate); 0 when nothing was expected.
type Metrics struct {
	TruePositives      int64   `json:"true_positives"`
	FalsePositives     int64   `json:"false_positives"`
	FalseNegatives     int64   `json:"false_negatives"`
	Precision          float64 `json:"precision"`
	Recall             float64 `json:"recall"`
	F1                 float64 `json:"f1"`
	FalseDiscoveryRate float64 `json:"false_discovery_rate"`
	FalseNegativeRate  float64 `json:"false_negative_rate"`
}

// GroupAccuracy is the reduction for one group, identified by its label.
type GroupAccuracy struct {
	Group   string  `json:"group"`
	Cases   int64   `json:"cases"`
	Metrics Metrics `json:"metrics"`
}

// AccuracyReport is the deterministic reduction of an AccuracyInput.
type AccuracyReport struct {
	SchemaVersion string          `json:"schema_version"`
	Cases         int64           `json:"cases"`
	Overall       Metrics         `json:"overall"`
	Groups        []GroupAccuracy `json:"groups"`
}

// DecodeAccuracyInput reads exactly one accuracy input document, rejecting unknown fields.
func DecodeAccuracyInput(r io.Reader) (AccuracyInput, error) {
	var input AccuracyInput
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return AccuracyInput{}, fmt.Errorf("decode accuracy input: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return AccuracyInput{}, fmt.Errorf("decode accuracy input: multiple JSON values")
		}
		return AccuracyInput{}, fmt.Errorf("decode accuracy input trailing data: %w", err)
	}
	return input, nil
}

// confusion accumulates true/false positives and false negatives over a set of cases.
type confusion struct {
	tp, fp, fn int64
	cases      int64
}

// add folds one case's expected and produced key sets into the confusion counts.
// Duplicate keys within a set are collapsed first (a set, not a multiset).
func (c *confusion) add(expected, produced []string) {
	exp := toSet(expected)
	prod := toSet(produced)
	c.cases++
	for key := range prod {
		if _, ok := exp[key]; ok {
			c.tp++
		} else {
			c.fp++
		}
	}
	for key := range exp {
		if _, ok := prod[key]; !ok {
			c.fn++
		}
	}
}

func (c confusion) metrics() Metrics {
	m := Metrics{TruePositives: c.tp, FalsePositives: c.fp, FalseNegatives: c.fn}
	if c.tp+c.fp > 0 {
		m.Precision = float64(c.tp) / float64(c.tp+c.fp)
		m.FalseDiscoveryRate = float64(c.fp) / float64(c.tp+c.fp)
	} else {
		m.Precision = 1
	}
	if c.tp+c.fn > 0 {
		m.Recall = float64(c.tp) / float64(c.tp+c.fn)
		m.FalseNegativeRate = float64(c.fn) / float64(c.tp+c.fn)
	} else {
		m.Recall = 1
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	return m
}

// EvaluateAccuracy validates and reduces the observations. It makes no measurements.
func EvaluateAccuracy(input AccuracyInput) (AccuracyReport, error) {
	if input.SchemaVersion != AccuracyInputSchemaVersion {
		return AccuracyReport{}, fmt.Errorf("unsupported accuracy input schema version %q", input.SchemaVersion)
	}
	seen := map[string]bool{}
	var overall confusion
	groups := map[string]*confusion{}
	for i, obs := range input.Observations {
		name := strings.TrimSpace(obs.Case)
		if name == "" {
			return AccuracyReport{}, fmt.Errorf("observation %d: case name is required", i)
		}
		if seen[name] {
			return AccuracyReport{}, fmt.Errorf("duplicate accuracy case %q", name)
		}
		seen[name] = true
		overall.add(obs.Expected, obs.Produced)
		if group := strings.TrimSpace(obs.Group); group != "" {
			c := groups[group]
			if c == nil {
				c = &confusion{}
				groups[group] = c
			}
			c.add(obs.Expected, obs.Produced)
		}
	}
	report := AccuracyReport{
		SchemaVersion: AccuracyReportSchemaVersion,
		Cases:         overall.cases,
		Overall:       overall.metrics(),
		Groups:        make([]GroupAccuracy, 0, len(groups)),
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		report.Groups = append(report.Groups, GroupAccuracy{Group: name, Cases: groups[name].cases, Metrics: groups[name].metrics()})
	}
	return report, nil
}

// EncodeAccuracyReport writes one stable, indented JSON document followed by a newline.
func EncodeAccuracyReport(w io.Writer, report AccuracyReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode accuracy report: %w", err)
	}
	return nil
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			set[v] = struct{}{}
		}
	}
	return set
}
