package notification

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EventFilters are event-specific selectors stored with a rule. They are kept
// in one value so persistence can evolve without widening the rule table.
type EventFilters struct {
	Kinds         []string `json:"kinds,omitempty"`
	FindingKinds  []string `json:"finding_kinds,omitempty"`
	FromStatuses  []string `json:"from_statuses,omitempty"`
	ToStatuses    []string `json:"to_statuses,omitempty"`
	RetestResults []string `json:"retest_results,omitempty"`
	ScanKinds     []string `json:"scan_kinds,omitempty"`
	Outcomes      []string `json:"outcomes,omitempty"`
	Providers     []string `json:"providers,omitempty"`
}

const maxEventFilterValues = 50

func (r *Rule) normalizeEventFilters(spec EventSpec) error {
	sets := []struct {
		values *[]string
		filter Filter
		name   string
		valid  func(string) bool
	}{
		{&r.Kinds, FilterKinds, "kinds", validApprovalKind},
		{&r.FindingKinds, FilterFindingKinds, "finding kinds", validFindingKind},
		{&r.FromStatuses, FilterFromStatuses, "from statuses", validFindingStatus},
		{&r.ToStatuses, FilterToStatuses, "to statuses", validFindingStatus},
		{&r.RetestResults, FilterRetestResults, "retest results", validRetestResult},
		{&r.ScanKinds, FilterScanKinds, "scan kinds", validRunToken},
		{&r.Outcomes, FilterOutcomes, "outcomes", func(value string) bool { return validEventOutcome(r.EventType, value) }},
		{&r.Providers, FilterProviders, "providers", validRunToken},
	}
	for _, set := range sets {
		values := uniqueStrings(*set.values)
		if len(values) > maxEventFilterValues {
			return fmt.Errorf("%w: too many notification %s", shared.ErrValidation, set.name)
		}
		if len(values) > 0 && !spec.Allows(set.filter) {
			return unsupportedFilter(r.EventType, set.name)
		}
		for _, value := range values {
			if !set.valid(value) {
				return fmt.Errorf("%w: invalid notification %s", shared.ErrValidation, set.name)
			}
		}
		*set.values = values
	}
	return nil
}

func (r Rule) matchesEventFilters(e Event) bool {
	if len(r.Kinds) == 0 && len(r.FindingKinds) == 0 && len(r.FromStatuses) == 0 && len(r.ToStatuses) == 0 && len(r.RetestResults) == 0 && len(r.ScanKinds) == 0 && len(r.Outcomes) == 0 && len(r.Providers) == 0 {
		return true
	}
	var data struct {
		Kind        string   `json:"kind"`
		FindingKind string   `json:"finding_kind"`
		FromStatus  string   `json:"from_status"`
		ToStatus    string   `json:"to_status"`
		Result      string   `json:"result"`
		ScanKind    string   `json:"scan_kind"`
		Outcome     string   `json:"outcome"`
		Provider    string   `json:"provider"`
		Providers   []string `json:"providers"`
	}
	if json.Unmarshal(e.Data, &data) != nil {
		return false
	}
	return (len(r.Kinds) == 0 || contains(r.Kinds, data.Kind)) &&
		(len(r.FindingKinds) == 0 || contains(r.FindingKinds, data.FindingKind)) &&
		(len(r.FromStatuses) == 0 || contains(r.FromStatuses, data.FromStatus)) &&
		(len(r.ToStatuses) == 0 || contains(r.ToStatuses, data.ToStatus)) &&
		(len(r.RetestResults) == 0 || contains(r.RetestResults, data.Result)) &&
		(len(r.ScanKinds) == 0 || contains(r.ScanKinds, data.ScanKind)) &&
		(len(r.Outcomes) == 0 || contains(r.Outcomes, data.Outcome)) &&
		(len(r.Providers) == 0 || containsAny(r.Providers, data.Providers, data.Provider))
}

// containsAny matches any immutable provider captured by a run producer. The
// singular provider is retained as the compatibility fallback for events that
// predate the providers array.
func containsAny(want, actual []string, fallback string) bool {
	for _, value := range actual {
		if contains(want, value) {
			return true
		}
	}
	return contains(want, fallback)
}

func validFindingKind(value string) bool   { return finding.Kind(value).Valid() }
func validFindingStatus(value string) bool { return finding.Status(value).Valid() }
func validRetestResult(value string) bool  { return finding.RetestOutcome(value).Valid() }

func validOutcome(value string) bool {
	switch value {
	case "succeeded", "failed", "partial", "cancelled", "unknown":
		return true
	}
	return false
}

// Run identifiers are producer-owned but must stay bounded and token-shaped so
// a rule cannot become an arbitrary text matcher.
func validRunToken(value string) bool {
	if len(value) == 0 || len(value) > 80 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return strings.TrimSpace(value) == value
}

func validApprovalKind(value string) bool { return value == "agent" || value == "response" }

func validEventOutcome(event EventType, value string) bool {
	if event == EventResponseFinished {
		switch value {
		case "applied", "verified", "failed", "reverted", "halted":
			return true
		}
		return false
	}
	return validOutcome(value)
}
