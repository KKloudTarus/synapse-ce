package msgtemplate

import "errors"

// errBudget is returned by a metered function once a render has spent MaxEvaluationCost.
var errBudget = errors.New("msgtemplate: render budget exceeded")

// meter charges the work each function call actually does during one render. The static cost
// model already guarantees the budget holds; the meter is the second line of defence if that model
// is ever wrong, since text/template offers no way to interrupt an execution from outside.
type meter struct {
	used int64
}

// charge records work on n runes and reports errBudget once the budget is spent.
func (m *meter) charge(n int) error {
	m.used += runeUnits(n)
	if m.used > MaxEvaluationCost {
		return errBudget
	}
	return nil
}
