package shared

import (
	"math"
	"strings"
)

// CVSSv3BaseScore computes the CVSS v3.0/v3.1 base score from a vector string
// (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). Returns (score, true) for
// a well-formed v3 vector, else (0, false). CVSS:4.0 vectors are scored by CVSSv40BaseScore.
func CVSSv3BaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	v31 := strings.HasPrefix(vector, "CVSS:3.1/")
	if !v31 && !strings.HasPrefix(vector, "CVSS:3.0/") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, found := strings.Cut(part, ":"); found {
			m[k] = v
		}
	}
	scopeChanged := m["S"] == "C"

	av, ok1 := metricAV[m["AV"]]
	ac, ok2 := metricAC[m["AC"]]
	ui, ok3 := metricUI[m["UI"]]
	pr, ok4 := privilegesRequired(m["PR"], scopeChanged)
	c, ok5 := metricImpact[m["C"]]
	i, ok6 := metricImpact[m["I"]]
	a, ok7 := metricImpact[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	switch {
	case !scopeChanged:
		impact = 6.42 * iss
	case v31:
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss*0.9731-0.02, 13)
	default: // v3.0, scope changed
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	expl := 8.22 * av * ac * pr * ui
	sum := impact + expl
	if scopeChanged {
		sum *= 1.08
	}
	return roundUpCVSS(math.Min(sum, 10), v31), true
}

// CVSSv2BaseScore computes the CVSS v2 base score from a vector string, with or without the
// "CVSS:2.0/" prefix or the NVD parentheses ("(AV:N/AC:L/Au:N/C:P/I:P/A:P)"). Returns (0, false) for
// anything else. Distro advisories on older CVEs often carry only a v2 vector.
func CVSSv2BaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	vector = strings.TrimPrefix(vector, "CVSS:2.0/")
	vector = strings.TrimSuffix(strings.TrimPrefix(vector, "("), ")")
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, found := strings.Cut(part, ":"); found {
			m[k] = v
		}
	}
	av, ok1 := v2AccessVector[m["AV"]]
	ac, ok2 := v2AccessComplexity[m["AC"]]
	au, ok3 := v2Authentication[m["Au"]]
	c, ok4 := v2Impact[m["C"]]
	i, ok5 := v2Impact[m["I"]]
	a, ok6 := v2Impact[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return 0, false
	}
	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	if impact == 0 {
		return 0, true
	}
	exploitability := 20 * av * ac * au
	base := (0.6*impact + 0.4*exploitability - 1.5) * 1.176
	return math.Round(base*10) / 10, true
}

// CVSSBaseScore scores a v4.0 vector, else a v3.x vector, else a v2 vector. Read paths that only
// display a number use it; paths that require v3 (the finding vector builder) keep calling
// CVSSv3BaseScore. The version prefixes are disjoint, so probe order never changes a result.
func CVSSBaseScore(vector string) (float64, bool) {
	if score, ok := CVSSv40BaseScore(vector); ok {
		return score, true
	}
	if score, ok := CVSSv3BaseScore(vector); ok {
		return score, true
	}
	return CVSSv2BaseScore(vector)
}

// CVSSv40BaseScore computes the CVSS v4.0 score from a vector string per the FIRST.org CVSS v4.0
// specification: the vector is reduced to a six-digit MacroVector (equivalence classes EQ1..EQ6),
// looked up, then interpolated by the severity distance from the highest-severity vector in the same
// MacroVector. Returns (score, true) for a well-formed v4.0 vector, else (0, false). Threat (E) and
// environmental metrics are honored when present; a base-only vector scores with their worst-case
// defaults (E:A, CR/IR/AR:H), matching the reference calculator. The lookup and max-severity tables
// are the published FIRST.org constants.
func CVSSv40BaseScore(vector string) (float64, bool) {
	sel, ok := parseCVSS40(vector)
	if !ok {
		return 0, false
	}
	// No impact on any system is score 0, before any lookup (spec shortcut).
	noImpact := true
	for _, mtr := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if cvss4m(sel, mtr) != "N" {
			noImpact = false
			break
		}
	}
	if noImpact {
		return 0, true
	}

	macro := cvss4MacroVector(sel)
	value, ok := cvss4Lookup[macro]
	if !ok {
		return 0, false
	}

	eq1 := int(macro[0] - '0')
	eq3 := int(macro[2] - '0')
	eq6 := int(macro[5] - '0')

	// Available distance per EQ: value minus the score of the next-lower MacroVector. A missing next-
	// lower MacroVector leaves that EQ out of the mean (the reference treats it as NaN).
	avail1, ok1 := cvss4Diff(value, cvss4Incr(macro, 0))
	avail2, ok2 := cvss4Diff(value, cvss4Incr(macro, 1))
	avail4, ok4 := cvss4Diff(value, cvss4Incr(macro, 3))
	avail5, ok5 := cvss4Diff(value, cvss4Incr(macro, 4))

	// EQ3 and EQ6 are scored jointly. When both are 0 there are two next-lower MacroVectors (increment
	// EQ3, or increment EQ6); the reference takes the higher-scoring one, with NaN semantics.
	var avail36 float64
	var ok36 bool
	if eq3 == 0 && eq6 == 0 {
		left, lok := cvss4Lookup[cvss4Incr(macro, 5)]  // increment EQ6
		right, rok := cvss4Lookup[cvss4Incr(macro, 2)] // increment EQ3
		// Mirror JS `left > right ? left : right` under NaN: a NaN operand makes `>` false, selecting
		// the right operand; only when the left strictly exceeds an existing right is the left chosen.
		var chosen float64
		var cok bool
		switch {
		case lok && rok:
			if left > right {
				chosen, cok = left, true
			} else {
				chosen, cok = right, true
			}
		case !lok && rok:
			chosen, cok = right, true
		default: // right missing: JS selects the (missing) right, so no available distance
			cok = false
		}
		if cok {
			avail36, ok36 = value-chosen, true
		}
	} else {
		if s, e := cvss4Lookup[cvss4IncrEQ3EQ6(macro, eq3, eq6)]; e {
			avail36, ok36 = value-s, true
		}
	}

	// Severity distance of this vector from the nearest dominating maximal vector in its MacroVector.
	maxVec := cvss4MaxVector(sel, macro)
	sd := func(metric string) float64 {
		return cvss4Level(metric, cvss4m(sel, metric)) - cvss4Level(metric, cvss4Extract(metric, maxVec))
	}
	distEQ1 := sd("AV") + sd("PR") + sd("UI")
	distEQ2 := sd("AC") + sd("AT")
	distEQ36 := sd("VC") + sd("VI") + sd("VA") + sd("CR") + sd("IR") + sd("AR")
	distEQ4 := sd("SC") + sd("SI") + sd("SA")

	const step = 0.1
	maxSev1 := float64(cvss4MaxSeverityEQ1[eq1]) * step
	maxSev2 := float64(cvss4MaxSeverityEQ2[int(macro[1]-'0')]) * step
	maxSev36 := float64(cvss4MaxSeverityEQ36[eq3][eq6]) * step
	maxSev4 := float64(cvss4MaxSeverityEQ4[int(macro[3]-'0')]) * step

	var sum float64
	n := 0
	if ok1 {
		sum += avail1 * (distEQ1 / maxSev1)
		n++
	}
	if ok2 {
		sum += avail2 * (distEQ2 / maxSev2)
		n++
	}
	if ok36 {
		sum += avail36 * (distEQ36 / maxSev36)
		n++
	}
	if ok4 {
		sum += avail4 * (distEQ4 / maxSev4)
		n++
	}
	if ok5 {
		// EQ5's proportional distance is always 0 in the reference (step depth 1, distance 0).
		sum += avail5 * 0
		n++
	}

	var mean float64
	if n > 0 {
		mean = sum / float64(n)
	}
	value -= mean
	switch {
	case value < 0:
		value = 0
	case value > 10:
		value = 10
	}
	return math.Round(value*10) / 10, true
}

var (
	v2AccessVector     = map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}
	v2AccessComplexity = map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}
	v2Authentication   = map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}
	v2Impact           = map[string]float64{"N": 0.0, "P": 0.275, "C": 0.660}
)

var (
	metricAV     = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	metricAC     = map[string]float64{"L": 0.77, "H": 0.44}
	metricUI     = map[string]float64{"N": 0.85, "R": 0.62}
	metricImpact = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
)

func privilegesRequired(pr string, scopeChanged bool) (float64, bool) {
	switch pr {
	case "N":
		return 0.85, true
	case "L":
		if scopeChanged {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if scopeChanged {
			return 0.50, true
		}
		return 0.27, true
	default:
		return 0, false
	}
}

// roundUpCVSS rounds up to one decimal place per the CVSS spec (v3.1 uses
// integer arithmetic to avoid float artifacts; v3.0 uses ceil(x*10)/10).
func roundUpCVSS(x float64, v31 bool) float64 {
	if !v31 {
		return math.Ceil(x*10) / 10
	}
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
}

// SeverityFromLabel maps a curated qualitative severity label (GHSA/OSV database_specific.severity,
// NVD/distro labels) to a band. Case-insensitive; MODERATE and MEDIUM both map to medium. An
// unrecognized or empty label returns SeverityUnknown, so a caller can fall back to a score-derived band.
func SeverityFromLabel(label string) Severity {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MODERATE", "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// SeverityFromScore maps a CVSS base score to the qualitative severity band.
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score >= 0.1:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
