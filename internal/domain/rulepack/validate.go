package rulepack

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var attackTechniquePattern = regexp.MustCompile(`^T[0-9]{4}(?:\.[0-9]{3})?$`)

func validatePredicateBounds(r detection.Rule) error {
	if strings.TrimSpace(r.ID) != r.ID || len(r.ID) > MaxIdentifierBytes {
		return fmt.Errorf("%w: rule id must be trimmed and at most %d bytes", shared.ErrValidation, MaxIdentifierBytes)
	}
	for i, p := range r.Matcher.All {
		if len(p.Value) > MaxPredicateStringBytes {
			return fmt.Errorf("%w: rule %s predicate %d value exceeds %d bytes", shared.ErrValidation, r.ID, i, MaxPredicateStringBytes)
		}
		if len(p.Values) > MaxValuesPerPredicate {
			return fmt.Errorf("%w: rule %s predicate %d has more than %d values", shared.ErrValidation, r.ID, i, MaxValuesPerPredicate)
		}
		if p.Op == detection.OpIn {
			if p.Value != "" {
				return fmt.Errorf("%w: rule %s predicate %d op in must not carry the unused value field", shared.ErrValidation, r.ID, i)
			}
		} else if len(p.Values) != 0 {
			return fmt.Errorf("%w: rule %s predicate %d op %s must not carry the unused values field", shared.ErrValidation, r.ID, i, p.Op)
		}
		if p.Field.Numeric() {
			n, err := strconv.Atoi(p.Value)
			if err != nil || strconv.Itoa(n) != p.Value {
				return fmt.Errorf("%w: rule %s predicate %d numeric value %q is not canonical decimal", shared.ErrValidation, r.ID, i, p.Value)
			}
		}
		seen := map[string]struct{}{}
		for _, value := range p.Values {
			if len(value) > MaxPredicateStringBytes {
				return fmt.Errorf("%w: rule %s predicate %d value exceeds %d bytes", shared.ErrValidation, r.ID, i, MaxPredicateStringBytes)
			}
			if _, dup := seen[value]; dup {
				return fmt.Errorf("%w: rule %s predicate %d repeats value %q", shared.ErrValidation, r.ID, i, value)
			}
			seen[value] = struct{}{}
		}
	}
	return nil
}

func validatePredicatesUnique(r detection.Rule) error {
	seen := map[string]struct{}{}
	for _, p := range r.Matcher.All {
		key := predicateKey(p)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: rule %s contains duplicate predicate %s", shared.ErrValidation, r.ID, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateUniquePositiveInts(name string, values []int) error {
	seen := map[int]struct{}{}
	for _, v := range values {
		if v < 1 {
			return fmt.Errorf("%w: %s must be >= 1", shared.ErrValidation, name)
		}
		if _, dup := seen[v]; dup {
			return fmt.Errorf("%w: duplicate %s %d", shared.ErrValidation, name, v)
		}
		seen[v] = struct{}{}
	}
	return nil
}

func validateSensors(sensors []SensorRequirement) error {
	seen := map[string]struct{}{}
	for _, s := range sensors {
		if strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.MinVersion) == "" || strings.TrimSpace(s.ID) != s.ID || strings.TrimSpace(s.MinVersion) != s.MinVersion || len(s.ID) > MaxIdentifierBytes {
			return fmt.Errorf("%w: sensor compatibility needs id and min version", shared.ErrValidation)
		}
		if _, ok := fleetversion.Parse(s.MinVersion); !ok {
			return fmt.Errorf("%w: sensor %s has unparseable version %q", shared.ErrValidation, s.ID, s.MinVersion)
		}
		if _, dup := seen[s.ID]; dup {
			return fmt.Errorf("%w: duplicate sensor requirement %q", shared.ErrValidation, s.ID)
		}
		seen[s.ID] = struct{}{}
	}
	return nil
}

func validateRequiredFields(fields []detection.Field, matcherFields map[detection.Field]struct{}) error {
	if len(fields) == 0 {
		return fmt.Errorf("%w: rulepack names no required fields", shared.ErrValidation)
	}
	seen := map[detection.Field]struct{}{}
	for _, f := range fields {
		if !f.Valid() {
			return fmt.Errorf("%w: unknown required field %q", shared.ErrValidation, f)
		}
		if _, dup := seen[f]; dup {
			return fmt.Errorf("%w: duplicate required field %q", shared.ErrValidation, f)
		}
		seen[f] = struct{}{}
	}
	for f := range matcherFields {
		if _, ok := seen[f]; !ok {
			return fmt.Errorf("%w: matcher field %q is absent from required_fields", shared.ErrValidation, f)
		}
	}
	return nil
}

func validateATTACKMappings(mappings []ATTACKMapping, rules map[string]detection.Rule) error {
	seen := map[string]struct{}{}
	for _, m := range mappings {
		if _, ok := rules[m.RuleID]; !ok {
			return fmt.Errorf("%w: ATT&CK mapping names unknown rule %q", shared.ErrValidation, m.RuleID)
		}
		canonicalTechnique := strings.ToUpper(strings.TrimSpace(m.TechniqueID))
		if m.TechniqueID != canonicalTechnique || !attackTechniquePattern.MatchString(canonicalTechnique) {
			return fmt.Errorf("%w: rule %s has invalid ATT&CK technique %q", shared.ErrValidation, m.RuleID, m.TechniqueID)
		}
		key := m.RuleID + "\x1f" + canonicalTechnique
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate ATT&CK mapping for %s", shared.ErrValidation, m.RuleID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateFixtures(fixtures []Fixture, positive bool, rules map[string]detection.Rule) error {
	if len(fixtures) > MaxFixturesPerKind {
		return fmt.Errorf("%w: fixture set exceeds %d entries", shared.ErrValidation, MaxFixturesPerKind)
	}
	if len(fixtures) == 0 {
		kind := "negative"
		if positive {
			kind = "positive"
		}
		return fmt.Errorf("%w: rulepack needs at least one %s fixture", shared.ErrValidation, kind)
	}
	seen := map[string]struct{}{}
	coveredRules := map[string]struct{}{}
	for _, f := range fixtures {
		if strings.TrimSpace(f.ID) == "" || strings.TrimSpace(f.ID) != f.ID || len(f.ID) > MaxIdentifierBytes {
			return fmt.Errorf("%w: fixture id must be trimmed, non-empty, and at most %d bytes", shared.ErrValidation, MaxIdentifierBytes)
		}
		if _, dup := seen[f.ID]; dup {
			return fmt.Errorf("%w: duplicate fixture id %q", shared.ErrValidation, f.ID)
		}
		seen[f.ID] = struct{}{}
		if err := f.Event.Validate(); err != nil {
			return fmt.Errorf("fixture %s: %w", f.ID, err)
		}
		eventBytes, err := json.Marshal(f.Event)
		if err != nil {
			return fmt.Errorf("fixture %s encode: %w", f.ID, err)
		}
		if len(eventBytes) > MaxFixtureEventBytes {
			return fmt.Errorf("%w: fixture %s event exceeds %d bytes", shared.ErrValidation, f.ID, MaxFixtureEventBytes)
		}
		if positive && len(f.ExpectedRuleIDs) == 0 {
			return fmt.Errorf("%w: positive fixture %s names no expected rule", shared.ErrValidation, f.ID)
		}
		if !positive && len(f.ExpectedRuleIDs) != 0 {
			return fmt.Errorf("%w: negative fixture %s must not name expected rules", shared.ErrValidation, f.ID)
		}
		expected := map[string]struct{}{}
		for _, id := range f.ExpectedRuleIDs {
			if _, ok := rules[id]; !ok {
				return fmt.Errorf("%w: fixture %s expects unknown rule %q", shared.ErrValidation, f.ID, id)
			}
			if _, dup := expected[id]; dup {
				return fmt.Errorf("%w: fixture %s repeats expected rule %q", shared.ErrValidation, f.ID, id)
			}
			expected[id] = struct{}{}
			coveredRules[id] = struct{}{}
		}
	}
	if positive {
		for ruleID := range rules {
			if _, ok := coveredRules[ruleID]; !ok {
				return fmt.Errorf("%w: rule %s has no positive replay fixture", shared.ErrValidation, ruleID)
			}
		}
	}
	return nil
}

func validateFixtureIDsUnique(positive, negative []Fixture) error {
	seen := make(map[string]struct{}, len(positive)+len(negative))
	for _, fixtures := range [][]Fixture{positive, negative} {
		for _, f := range fixtures {
			if _, dup := seen[f.ID]; dup {
				return fmt.Errorf("%w: fixture id %q is reused across positive/negative corpora", shared.ErrValidation, f.ID)
			}
			seen[f.ID] = struct{}{}
		}
	}
	return nil
}

func validateCostBudgets(costs []RuleCostBudget, rules map[string]detection.Rule) error {
	if len(costs) != len(rules) {
		return fmt.Errorf("%w: expected_cost must contain exactly one budget per rule", shared.ErrValidation)
	}
	seen := map[string]struct{}{}
	for _, c := range costs {
		if _, ok := rules[c.RuleID]; !ok {
			return fmt.Errorf("%w: cost budget names unknown rule %q", shared.ErrValidation, c.RuleID)
		}
		if _, dup := seen[c.RuleID]; dup {
			return fmt.Errorf("%w: duplicate cost budget for rule %q", shared.ErrValidation, c.RuleID)
		}
		if c.MaxLatencyMicros <= 0 || c.MaxCPUMicrosPerHostDay <= 0 {
			return fmt.Errorf("%w: rule %s cost limits must be positive", shared.ErrValidation, c.RuleID)
		}
		seen[c.RuleID] = struct{}{}
	}
	return nil
}

func validateCohorts(cohorts []string) error {
	if len(cohorts) == 0 {
		return fmt.Errorf("%w: rulepack has no rollout cohort", shared.ErrValidation)
	}
	seen := map[string]struct{}{}
	for _, c := range cohorts {
		if strings.TrimSpace(c) == "" || strings.TrimSpace(c) != c || len(c) > MaxIdentifierBytes {
			return fmt.Errorf("%w: rollout cohort must be trimmed, non-empty, and at most %d bytes", shared.ErrValidation, MaxIdentifierBytes)
		}
		if _, dup := seen[c]; dup {
			return fmt.Errorf("%w: duplicate rollout cohort %q", shared.ErrValidation, c)
		}
		seen[c] = struct{}{}
	}
	return nil
}
