package notification

import (
	"sort"
	"testing"
)

func TestCatalogIsConsistent(t *testing.T) {
	specs := EventCatalog()
	if len(specs) != len(catalog) {
		t.Fatalf("EventCatalog returned %d specs, catalog has %d", len(specs), len(catalog))
	}
	if !sort.SliceIsSorted(specs, func(i, j int) bool { return specs[i].Type < specs[j].Type }) {
		t.Fatal("EventCatalog is not ordered by type")
	}
	for _, spec := range specs {
		if !spec.Type.Valid() || spec.SchemaVersion < 1 || spec.SubjectKind == "" || spec.MaxDataClass.Rank() == 0 {
			t.Fatalf("incomplete spec %+v", spec)
		}
		// A filter is only declared when the producer fills the field it reads.
		requires := map[Filter]bool{
			FilterEngagements: spec.HasEngagement,
			FilterMinSeverity: spec.HasSeverity,
			FilterTeams:       spec.HasTeam,
			FilterLeadTime:    spec.HasLeadTime,
			FilterActionTypes: spec.Type == EventVulnerabilityAction,
		}
		for _, filter := range spec.Filters {
			if !requires[filter] {
				t.Fatalf("%s declares filter %s without the matching event field", spec.Type, filter)
			}
		}
		if spec.OperatorOnly && len(spec.Filters) > 0 {
			t.Fatalf("operator-only %s declares rule filters", spec.Type)
		}
	}
	if EventType("finding.unknown").Valid() {
		t.Fatal("undeclared event type is valid")
	}
}

func TestCatalogReturnsCopies(t *testing.T) {
	spec, _ := LookupEvent(EventVulnerabilityAction)
	spec.Filters[0] = FilterTeams
	again, _ := LookupEvent(EventVulnerabilityAction)
	if again.Filters[0] == FilterTeams {
		t.Fatal("LookupEvent exposes the shared catalog")
	}
}
