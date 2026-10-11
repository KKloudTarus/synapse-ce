package msgtemplate

// Static bounds checked when a template is compiled, and the output ceiling checked at render time.
const (
	// MaxSourceBytes caps the template source.
	MaxSourceBytes = 16 << 10
	// MaxNodes caps the parse tree size.
	MaxNodes = 2000
	// MaxControlNesting caps nested if, with and range blocks.
	MaxControlNesting = 4
	// MaxRangeNesting caps nested range blocks.
	MaxRangeNesting = 2
	// MaxIterationProduct caps the product of the list caps along any chain of nested ranges.
	MaxIterationProduct = 10000
	// MaxEvaluationCost bounds the work of one render in cost units (cost.go). A node evaluation is
	// one unit and a function processes costRunesPerUnit runes per unit; every unit is charged once
	// per iteration of the ranges around it. The same budget is enforced again at render time by the
	// meter (meter.go).
	MaxEvaluationCost = 200000
	// DefaultMaxValueRunes is the value length bound when a SchemaSpec sets none.
	DefaultMaxValueRunes = 1000
	// MaxOutputRunes is the largest per-field output a caller may request (ticket description).
	MaxOutputRunes = 30000
)

// maxNameLength caps the template name used in error messages.
const maxNameLength = 200
