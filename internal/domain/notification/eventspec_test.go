package notification

import "testing"

func TestDataClassRank(t *testing.T) {
	if !(DataClassSignal.Rank() < DataClassSummary.Rank() && DataClassSummary.Rank() < DataClassDetail.Rank()) {
		t.Fatal("data classes are not ordered signal < summary < detail")
	}
	if DataClass("secret").Rank() != 0 {
		t.Fatal("unknown data class has a rank")
	}
}

func TestEventSpecAllows(t *testing.T) {
	spec := EventSpec{Filters: []Filter{FilterEngagements, FilterLeadTime}}
	for filter, want := range map[Filter]bool{
		FilterEngagements: true,
		FilterLeadTime:    true,
		FilterMinSeverity: false,
		FilterTeams:       false,
	} {
		if got := spec.Allows(filter); got != want {
			t.Fatalf("Allows(%s) = %v, want %v", filter, got, want)
		}
	}
	if (EventSpec{}).Allows(FilterEngagements) {
		t.Fatal("a spec without filters allows one")
	}
}

func TestEventSpecCloneIsIndependent(t *testing.T) {
	original := EventSpec{Filters: []Filter{FilterEngagements}, Variables: []Variable{{Name: "title"}}}
	copied := original.clone()
	copied.Filters[0] = FilterTeams
	copied.Variables[0].Name = "changed"
	if original.Filters[0] != FilterEngagements || original.Variables[0].Name != "title" {
		t.Fatal("clone shares slices with the original")
	}
}
