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
	// MaxEvaluationCost bounds the node evaluations of one render: every node counts once per
	// iteration of the ranges around it. It keeps the worst case in the low milliseconds, which the
	// node and iteration bounds alone do not (2,000 nodes inside 10,000 iterations).
	MaxEvaluationCost = 200000
	// MaxOutputRunes is the largest per-field output a caller may request (ticket description).
	MaxOutputRunes = 30000
)

// maxNameLength caps the template name used in error messages.
const maxNameLength = 200
