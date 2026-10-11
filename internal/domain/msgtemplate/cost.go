package msgtemplate

import (
	"strconv"
	"text/template/parse"
)

// costRunesPerUnit is how many runes a function processes for one cost unit. Measured with
// BenchmarkRenderWorstCase so that MaxEvaluationCost keeps the worst accepted template in the low
// milliseconds.
const costRunesPerUnit = 64

// Static length bounds, in runes, of values whose length does not come from the schema.
const (
	intRunes      = 20 // an int formatted in base 10
	floatRunes    = 32
	boolRunes     = 5
	severityRunes = 8 // the longest severity_label result
)

// runeUnits is the cost of processing n runes once.
func runeUnits(n int) int64 {
	return 1 + int64(n)/costRunesPerUnit
}

// inputRunes is the number of runes a call reads. count reads only the list length; join reads one
// field of every item; every other function reads its scalar arguments.
func (v *validator) inputRunes(name string, args []value) int {
	total := 0
	for _, arg := range args {
		switch {
		case arg.isList() && name == "join":
			total = saturatingAdd(total, v.schema.lists[arg.list].cap*v.schema.maxValueRunes)
		case arg.isList():
		default:
			total = saturatingAdd(total, arg.runes)
		}
	}
	return total
}

// resultRunes bounds the length of a call's result.
func (v *validator) resultRunes(name string, args []value, operands []parse.Node) int {
	switch name {
	case "join":
		list := v.schema.lists[args[2].list]
		return list.cap * (v.schema.maxValueRunes + args[1].runes)
	case "truncate":
		if n, ok := intLiteral(operands[0]); ok {
			return min(max(n, 0), args[1].runes)
		}
		return args[1].runes
	case "severity_label":
		return severityRunes
	case "count":
		return intRunes
	case "eq", "ne", "not":
		return boolRunes
	}
	longest := 0
	for _, arg := range args {
		longest = max(longest, arg.runes)
	}
	return longest
}

func intLiteral(node parse.Node) (int, bool) {
	number, ok := node.(*parse.NumberNode)
	if !ok || !number.IsInt {
		return 0, false
	}
	n, err := strconv.Atoi(number.Text)
	return n, err == nil
}

// saturatingAdd keeps length bounds from overflowing; any bound this large is rejected anyway.
func saturatingAdd(a, b int) int {
	if a > MaxEvaluationCost*costRunesPerUnit-b {
		return MaxEvaluationCost * costRunesPerUnit
	}
	return a + b
}
