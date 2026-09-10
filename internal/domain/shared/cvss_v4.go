package shared

import "strings"

// This file carries the CVSS v4.0 lookup and interpolation data plus the metric helpers used by
// CVSSv40BaseScore (in cvss.go). Everything here is a faithful port of the FIRST.org CVSS v4.0
// reference calculator: the cvss4Lookup table, the maximal-vector composition, and the max-severity
// depths are the published constants; the helpers mirror macroVector(), m(), and cvss_score().

// cvss4ValidValues gives the allowed value set of every v4.0 metric (base, threat, environmental,
// supplemental). A vector carrying an unknown metric key or an out-of-set value is malformed.
var cvss4ValidValues = map[string]map[string]bool{
	// Base (all mandatory).
	"AV": {"N": true, "A": true, "L": true, "P": true},
	"AC": {"L": true, "H": true},
	"AT": {"N": true, "P": true},
	"PR": {"N": true, "L": true, "H": true},
	"UI": {"N": true, "P": true, "A": true},
	"VC": {"H": true, "L": true, "N": true},
	"VI": {"H": true, "L": true, "N": true},
	"VA": {"H": true, "L": true, "N": true},
	"SC": {"H": true, "L": true, "N": true},
	"SI": {"H": true, "L": true, "N": true},
	"SA": {"H": true, "L": true, "N": true},
	// Threat.
	"E": {"X": true, "A": true, "P": true, "U": true},
	// Environmental requirements.
	"CR": {"X": true, "H": true, "M": true, "L": true},
	"IR": {"X": true, "H": true, "M": true, "L": true},
	"AR": {"X": true, "H": true, "M": true, "L": true},
	// Environmental modified base.
	"MAV": {"X": true, "N": true, "A": true, "L": true, "P": true},
	"MAC": {"X": true, "L": true, "H": true},
	"MAT": {"X": true, "N": true, "P": true},
	"MPR": {"X": true, "N": true, "L": true, "H": true},
	"MUI": {"X": true, "N": true, "P": true, "A": true},
	"MVC": {"X": true, "H": true, "L": true, "N": true},
	"MVI": {"X": true, "H": true, "L": true, "N": true},
	"MVA": {"X": true, "H": true, "L": true, "N": true},
	"MSC": {"X": true, "H": true, "L": true, "N": true},
	"MSI": {"X": true, "S": true, "H": true, "L": true, "N": true},
	"MSA": {"X": true, "S": true, "H": true, "L": true, "N": true},
	// Supplemental (no effect on the score, but valid keys).
	"S":  {"X": true, "N": true, "P": true},
	"AU": {"X": true, "N": true, "Y": true},
	"R":  {"X": true, "A": true, "U": true, "I": true},
	"V":  {"X": true, "D": true, "C": true},
	"RE": {"X": true, "L": true, "M": true, "H": true},
	"U":  {"X": true, "Clear": true, "Green": true, "Amber": true, "Red": true},
}

// cvss4Mandatory lists the eleven base metrics that a well-formed v4.0 vector must carry.
var cvss4Mandatory = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}

// parseCVSS40 parses and validates a "CVSS:4.0/..." vector. It returns the metric map and true only
// when the prefix is present, every part is a known metric with an in-set value, no metric repeats,
// and all eleven mandatory base metrics appear. Otherwise it returns (nil, false), so a malformed
// vector is never silently scored.
func parseCVSS40(vector string) (map[string]string, bool) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:4.0/") {
		return nil, false
	}
	parts := strings.Split(vector, "/")[1:]
	if len(parts) == 0 {
		return nil, false
	}
	sel := make(map[string]string, len(parts))
	for _, part := range parts {
		k, v, found := strings.Cut(part, ":")
		if !found {
			return nil, false
		}
		allowed, ok := cvss4ValidValues[k]
		if !ok || !allowed[v] {
			return nil, false
		}
		if _, dup := sel[k]; dup {
			return nil, false
		}
		sel[k] = v
	}
	for _, mtr := range cvss4Mandatory {
		if _, ok := sel[mtr]; !ok {
			return nil, false
		}
	}
	return sel, true
}

// cvss4m resolves a metric's effective value, mirroring the reference m(): E:X defaults to the worst
// case A; CR/IR/AR:X default to H; a present, non-X modified metric M<name> overrides its base; every
// other absent metric resolves to X.
func cvss4m(sel map[string]string, metric string) string {
	v, present := sel[metric]
	switch metric {
	case "E":
		if !present || v == "X" {
			return "A"
		}
	case "CR", "IR", "AR":
		if !present || v == "X" {
			return "H"
		}
	}
	if mv, ok := sel["M"+metric]; ok && mv != "X" {
		return mv
	}
	if !present {
		return "X"
	}
	return v
}

// cvss4MacroVector reduces the resolved metrics to the six-digit MacroVector (EQ1..EQ6).
func cvss4MacroVector(sel map[string]string) string {
	av, pr, ui := cvss4m(sel, "AV"), cvss4m(sel, "PR"), cvss4m(sel, "UI")
	ac, at := cvss4m(sel, "AC"), cvss4m(sel, "AT")
	vc, vi, va := cvss4m(sel, "VC"), cvss4m(sel, "VI"), cvss4m(sel, "VA")
	sc, si, sa := cvss4m(sel, "SC"), cvss4m(sel, "SI"), cvss4m(sel, "SA")
	msi, msa := cvss4m(sel, "MSI"), cvss4m(sel, "MSA")
	cr, ir, ar := cvss4m(sel, "CR"), cvss4m(sel, "IR"), cvss4m(sel, "AR")

	// EQ1
	var eq1 byte
	switch {
	case av == "N" && pr == "N" && ui == "N":
		eq1 = '0'
	case (av == "N" || pr == "N" || ui == "N") && !(av == "N" && pr == "N" && ui == "N") && av != "P":
		eq1 = '1'
	default: // AV:P or not(AV:N or PR:N or UI:N)
		eq1 = '2'
	}
	// EQ2
	eq2 := byte('1')
	if ac == "L" && at == "N" {
		eq2 = '0'
	}
	// EQ3
	var eq3 byte
	switch {
	case vc == "H" && vi == "H":
		eq3 = '0'
	case vc == "H" || vi == "H" || va == "H":
		eq3 = '1'
	default:
		eq3 = '2'
	}
	// EQ4
	var eq4 byte
	switch {
	case msi == "S" || msa == "S":
		eq4 = '0'
	case sc == "H" || si == "H" || sa == "H":
		eq4 = '1'
	default:
		eq4 = '2'
	}
	// EQ5
	var eq5 byte
	switch cvss4m(sel, "E") {
	case "A":
		eq5 = '0'
	case "P":
		eq5 = '1'
	default: // U
		eq5 = '2'
	}
	// EQ6
	eq6 := byte('1')
	if (cr == "H" && vc == "H") || (ir == "H" && vi == "H") || (ar == "H" && va == "H") {
		eq6 = '0'
	}
	return string([]byte{eq1, eq2, eq3, eq4, eq5, eq6})
}

// cvss4Incr returns the MacroVector with the digit at position pos incremented by one (its next-lower
// MacroVector along that equivalence class). The caller looks the result up; a non-existent key means
// there is no lower MacroVector for that EQ.
func cvss4Incr(macro string, pos int) string {
	b := []byte(macro)
	b[pos]++
	return string(b)
}

// cvss4IncrEQ3EQ6 returns the joint next-lower MacroVector for the EQ3/EQ6 pair when they are not both
// zero, mirroring the reference's related-EQ transitions.
func cvss4IncrEQ3EQ6(macro string, eq3, eq6 int) string {
	b := []byte(macro)
	switch {
	case (eq3 == 1 && eq6 == 1), (eq3 == 0 && eq6 == 1):
		b[2]++
	case eq3 == 1 && eq6 == 0:
		b[5]++
	default:
		b[2]++
		b[5]++
	}
	return string(b)
}

// cvss4Diff returns value minus the score of the given MacroVector, and whether that MacroVector
// exists. A missing MacroVector is the reference's NaN available-distance, dropped from the mean.
func cvss4Diff(value float64, macro string) (float64, bool) {
	s, ok := cvss4Lookup[macro]
	if !ok {
		return 0, false
	}
	return value - s, true
}

// cvss4MaxVector composes the maximal-severity vectors of this MacroVector and returns the first one
// that dominates the scored vector on every metric (all severity distances non-negative). When none
// dominates, it returns the last composed vector, matching the reference loop's final assignment.
func cvss4MaxVector(sel map[string]string, macro string) string {
	eq1 := int(macro[0] - '0')
	eq2 := int(macro[1] - '0')
	eq3 := int(macro[2] - '0')
	eq4 := int(macro[3] - '0')
	eq5 := int(macro[4] - '0')
	eq6 := int(macro[5] - '0')
	eq1m := cvss4MaxComposedEQ1[eq1]
	eq2m := cvss4MaxComposedEQ2[eq2]
	eq36m := cvss4MaxComposedEQ36[eq3][eq6]
	eq4m := cvss4MaxComposedEQ4[eq4]
	eq5m := cvss4MaxComposedEQ5[eq5]
	metrics := []string{"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"}
	last := ""
	for _, a := range eq1m {
		for _, b := range eq2m {
			for _, c := range eq36m {
				for _, d := range eq4m {
					for _, e := range eq5m {
						cand := a + b + c + d + e
						last = cand
						dominates := true
						for _, mtr := range metrics {
							if cvss4Level(mtr, cvss4m(sel, mtr))-cvss4Level(mtr, cvss4Extract(mtr, cand)) < 0 {
								dominates = false
								break
							}
						}
						if dominates {
							return cand
						}
					}
				}
			}
		}
	}
	return last
}

// cvss4Extract pulls the value of metric out of a composed maximal-vector string (e.g. "AV" -> "N"
// from ".../AV:N/..."), mirroring extractValueMetric().
func cvss4Extract(metric, s string) string {
	idx := strings.Index(s, metric)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(metric)+1:]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// cvss4Level maps a metric value to its ordered severity level (0 is most severe). Values absent from
// the table (never produced by the resolver or the composed vectors) fall to 0.
func cvss4Level(metric, value string) float64 {
	return cvss4Levels[metric][value]
}

var cvss4Levels = map[string]map[string]float64{
	"AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
	"PR": {"N": 0.0, "L": 0.1, "H": 0.2},
	"UI": {"N": 0.0, "P": 0.1, "A": 0.2},
	"AC": {"L": 0.0, "H": 0.1},
	"AT": {"N": 0.0, "P": 0.1},
	"VC": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VI": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VA": {"H": 0.0, "L": 0.1, "N": 0.2},
	"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"CR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"IR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

// Maximal-severity vector fragments per equivalence class (maxComposed).
var (
	cvss4MaxComposedEQ1 = [][]string{
		{"AV:N/PR:N/UI:N/"},
		{"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
		{"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"},
	}
	cvss4MaxComposedEQ2 = [][]string{
		{"AC:L/AT:N/"},
		{"AC:H/AT:N/", "AC:L/AT:P/"},
	}
	cvss4MaxComposedEQ36 = map[int]map[int][]string{
		0: {
			0: {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"},
			1: {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"},
		},
		1: {
			0: {"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"},
			1: {"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"},
		},
		2: {
			1: {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"},
		},
	}
	cvss4MaxComposedEQ4 = [][]string{
		{"SC:H/SI:S/SA:S/"},
		{"SC:H/SI:H/SA:H/"},
		{"SC:L/SI:L/SA:L/"},
	}
	cvss4MaxComposedEQ5 = [][]string{
		{"E:A/"},
		{"E:P/"},
		{"E:U/"},
	}
)

// Max-severity depths per equivalence class (maxSeverity), used to normalize the severity distance.
var (
	cvss4MaxSeverityEQ1  = []int{1, 4, 5}
	cvss4MaxSeverityEQ2  = []int{1, 2}
	cvss4MaxSeverityEQ4  = []int{6, 5, 4}
	cvss4MaxSeverityEQ36 = map[int]map[int]int{
		0: {0: 7, 1: 6},
		1: {0: 8, 1: 8},
		2: {1: 10},
	}
)

// cvss4Lookup is the published FIRST.org CVSS v4.0 MacroVector score table (270 entries).
var cvss4Lookup = map[string]float64{
	"000000": 10,
	"000001": 9.9,
	"000010": 9.8,
	"000011": 9.5,
	"000020": 9.5,
	"000021": 9.2,
	"000100": 10,
	"000101": 9.6,
	"000110": 9.3,
	"000111": 8.7,
	"000120": 9.1,
	"000121": 8.1,
	"000200": 9.3,
	"000201": 9,
	"000210": 8.9,
	"000211": 8,
	"000220": 8.1,
	"000221": 6.8,
	"001000": 9.8,
	"001001": 9.5,
	"001010": 9.5,
	"001011": 9.2,
	"001020": 9,
	"001021": 8.4,
	"001100": 9.3,
	"001101": 9.2,
	"001110": 8.9,
	"001111": 8.1,
	"001120": 8.1,
	"001121": 6.5,
	"001200": 8.8,
	"001201": 8,
	"001210": 7.8,
	"001211": 7,
	"001220": 6.9,
	"001221": 4.8,
	"002001": 9.2,
	"002011": 8.2,
	"002021": 7.2,
	"002101": 7.9,
	"002111": 6.9,
	"002121": 5,
	"002201": 6.9,
	"002211": 5.5,
	"002221": 2.7,
	"010000": 9.9,
	"010001": 9.7,
	"010010": 9.5,
	"010011": 9.2,
	"010020": 9.2,
	"010021": 8.5,
	"010100": 9.5,
	"010101": 9.1,
	"010110": 9,
	"010111": 8.3,
	"010120": 8.4,
	"010121": 7.1,
	"010200": 9.2,
	"010201": 8.1,
	"010210": 8.2,
	"010211": 7.1,
	"010220": 7.2,
	"010221": 5.3,
	"011000": 9.5,
	"011001": 9.3,
	"011010": 9.2,
	"011011": 8.5,
	"011020": 8.5,
	"011021": 7.3,
	"011100": 9.2,
	"011101": 8.2,
	"011110": 8,
	"011111": 7.2,
	"011120": 7,
	"011121": 5.9,
	"011200": 8.4,
	"011201": 7,
	"011210": 7.1,
	"011211": 5.2,
	"011220": 5,
	"011221": 3,
	"012001": 8.6,
	"012011": 7.5,
	"012021": 5.2,
	"012101": 7.1,
	"012111": 5.2,
	"012121": 2.9,
	"012201": 6.3,
	"012211": 2.9,
	"012221": 1.7,
	"100000": 9.8,
	"100001": 9.5,
	"100010": 9.4,
	"100011": 8.7,
	"100020": 9.1,
	"100021": 8.1,
	"100100": 9.4,
	"100101": 8.9,
	"100110": 8.6,
	"100111": 7.4,
	"100120": 7.7,
	"100121": 6.4,
	"100200": 8.7,
	"100201": 7.5,
	"100210": 7.4,
	"100211": 6.3,
	"100220": 6.3,
	"100221": 4.9,
	"101000": 9.4,
	"101001": 8.9,
	"101010": 8.8,
	"101011": 7.7,
	"101020": 7.6,
	"101021": 6.7,
	"101100": 8.6,
	"101101": 7.6,
	"101110": 7.4,
	"101111": 5.8,
	"101120": 5.9,
	"101121": 5,
	"101200": 7.2,
	"101201": 5.7,
	"101210": 5.7,
	"101211": 5.2,
	"101220": 5.2,
	"101221": 2.5,
	"102001": 8.3,
	"102011": 7,
	"102021": 5.4,
	"102101": 6.5,
	"102111": 5.8,
	"102121": 2.6,
	"102201": 5.3,
	"102211": 2.1,
	"102221": 1.3,
	"110000": 9.5,
	"110001": 9,
	"110010": 8.8,
	"110011": 7.6,
	"110020": 7.6,
	"110021": 7,
	"110100": 9,
	"110101": 7.7,
	"110110": 7.5,
	"110111": 6.2,
	"110120": 6.1,
	"110121": 5.3,
	"110200": 7.7,
	"110201": 6.6,
	"110210": 6.8,
	"110211": 5.9,
	"110220": 5.2,
	"110221": 3,
	"111000": 8.9,
	"111001": 7.8,
	"111010": 7.6,
	"111011": 6.7,
	"111020": 6.2,
	"111021": 5.8,
	"111100": 7.4,
	"111101": 5.9,
	"111110": 5.7,
	"111111": 5.7,
	"111120": 4.7,
	"111121": 2.3,
	"111200": 6.1,
	"111201": 5.2,
	"111210": 5.7,
	"111211": 2.9,
	"111220": 2.4,
	"111221": 1.6,
	"112001": 7.1,
	"112011": 5.9,
	"112021": 3,
	"112101": 5.8,
	"112111": 2.6,
	"112121": 1.5,
	"112201": 2.3,
	"112211": 1.3,
	"112221": 0.6,
	"200000": 9.3,
	"200001": 8.7,
	"200010": 8.6,
	"200011": 7.2,
	"200020": 7.5,
	"200021": 5.8,
	"200100": 8.6,
	"200101": 7.4,
	"200110": 7.4,
	"200111": 6.1,
	"200120": 5.6,
	"200121": 3.4,
	"200200": 7,
	"200201": 5.4,
	"200210": 5.2,
	"200211": 4,
	"200220": 4,
	"200221": 2.2,
	"201000": 8.5,
	"201001": 7.5,
	"201010": 7.4,
	"201011": 5.5,
	"201020": 6.2,
	"201021": 5.1,
	"201100": 7.2,
	"201101": 5.7,
	"201110": 5.5,
	"201111": 4.1,
	"201120": 4.6,
	"201121": 1.9,
	"201200": 5.3,
	"201201": 3.6,
	"201210": 3.4,
	"201211": 1.9,
	"201220": 1.9,
	"201221": 0.8,
	"202001": 6.4,
	"202011": 5.1,
	"202021": 2,
	"202101": 4.7,
	"202111": 2.1,
	"202121": 1.1,
	"202201": 2.4,
	"202211": 0.9,
	"202221": 0.4,
	"210000": 8.8,
	"210001": 7.5,
	"210010": 7.3,
	"210011": 5.3,
	"210020": 6,
	"210021": 5,
	"210100": 7.3,
	"210101": 5.5,
	"210110": 5.9,
	"210111": 4,
	"210120": 4.1,
	"210121": 2,
	"210200": 5.4,
	"210201": 4.3,
	"210210": 4.5,
	"210211": 2.2,
	"210220": 2,
	"210221": 1.1,
	"211000": 7.5,
	"211001": 5.5,
	"211010": 5.8,
	"211011": 4.5,
	"211020": 4,
	"211021": 2.1,
	"211100": 6.1,
	"211101": 5.1,
	"211110": 4.8,
	"211111": 1.8,
	"211120": 2,
	"211121": 0.9,
	"211200": 4.6,
	"211201": 1.8,
	"211210": 1.7,
	"211211": 0.7,
	"211220": 0.8,
	"211221": 0.2,
	"212001": 5.3,
	"212011": 2.4,
	"212021": 1.4,
	"212101": 2.4,
	"212111": 1.2,
	"212121": 0.5,
	"212201": 1,
	"212211": 0.3,
	"212221": 0.1,
}
