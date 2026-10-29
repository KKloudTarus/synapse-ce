package notification

import (
	"encoding/json"
	"testing"
)

func TestPagerLifecycleValidatesSubjectAndStaysPrivate(t *testing.T) {
	for _, tc := range []struct {
		p        PagerLifecycle
		typ      EventType
		kind, id string
		valid    bool
	}{
		{PagerLifecycle{}, EventIncidentCreated, "", "", true},
		{PagerLifecycle{Episode: 1, Revision: 2, Terminal: true}, EventFindingStatusChanged, "finding", "f", true},
		{PagerLifecycle{Episode: 1, Revision: 2}, EventIncidentUpdated, "finding", "f", false},
		{PagerLifecycle{Episode: 1}, EventIncidentUpdated, "incident", "i", false},
		{PagerLifecycle{Terminal: true}, EventIncidentUpdated, "incident", "i", false},
		{PagerLifecycle{Episode: 1, Revision: 1}, EventIncidentCreated, "incident", "", false},
	} {
		if got := tc.p.validate(tc.typ, tc.kind, tc.id) == nil; got != tc.valid {
			t.Fatalf("%+v: got valid %v", tc, got)
		}
	}
	raw, err := json.Marshal(Event{PagerLifecycle: PagerLifecycle{Episode: 2, Revision: 3, Terminal: true}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, exists := decoded["PagerLifecycle"]; exists {
		t.Fatalf("lifecycle leaked in %s", raw)
	}
}
