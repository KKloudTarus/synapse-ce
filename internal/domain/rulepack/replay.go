package rulepack

import "sort"

// ReplayResult is the deterministic expected-vs-actual outcome for one replay fixture.
type ReplayResult struct {
	FixtureID string   `json:"fixture_id"`
	Expected  []string `json:"expected"`
	Actual    []string `json:"actual"`
	Pass      bool     `json:"pass"`
}

// Replay evaluates all positive fixtures first and then negative fixtures, each group sorted by fixture
// ID so reports are stable regardless of manifest ordering.
func Replay(p RulePack) ([]ReplayResult, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	positive := append([]Fixture(nil), p.PositiveFixtures...)
	negative := append([]Fixture(nil), p.NegativeFixtures...)
	sort.Slice(positive, func(i, j int) bool { return positive[i].ID < positive[j].ID })
	sort.Slice(negative, func(i, j int) bool { return negative[i].ID < negative[j].ID })
	fixtures := append(positive, negative...)
	out := make([]ReplayResult, 0, len(fixtures))
	for _, f := range fixtures {
		actual := make([]string, 0)
		for _, r := range p.Rules {
			if r.Match(f.Event) {
				actual = append(actual, r.ID)
			}
		}
		sort.Strings(actual)
		expected := append([]string(nil), f.ExpectedRuleIDs...)
		sort.Strings(expected)
		out = append(out, ReplayResult{FixtureID: f.ID, Expected: expected, Actual: actual, Pass: stringSlicesEqual(expected, actual)})
	}
	return out, nil
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
