package threatmodel

import "testing"

func TestDiffAddedRemoved(t *testing.T) {
	prior := Model{
		Components: []Component{{ID: "a"}, {ID: "b"}},
		Flows:      []DataFlow{{ID: "f1", From: "a", To: "b"}},
	}
	next := Model{
		Components: []Component{{ID: "b"}, {ID: "c"}},          // a removed, c added
		Flows:      []DataFlow{{ID: "f2", From: "b", To: "c"}}, // f1 removed, f2 added
	}
	d := Diff(prior, next)
	if len(d.AddedComponents) != 1 || d.AddedComponents[0].ID != "c" {
		t.Errorf("added components: %+v", d.AddedComponents)
	}
	if len(d.RemovedComponents) != 1 || d.RemovedComponents[0].ID != "a" {
		t.Errorf("removed components: %+v", d.RemovedComponents)
	}
	if len(d.AddedFlows) != 1 || d.AddedFlows[0].ID != "f2" {
		t.Errorf("added flows: %+v", d.AddedFlows)
	}
	if len(d.RemovedFlows) != 1 || d.RemovedFlows[0].ID != "f1" {
		t.Errorf("removed flows: %+v", d.RemovedFlows)
	}
	if d.Empty() {
		t.Error("a model with added/removed elements is not an empty delta")
	}
}

func TestDiffNewCrossingFromMovedComponent(t *testing.T) {
	// f1 (a→b) does NOT cross in prior (both in zone1); in next, b moves to zone2 → f1 NOW crosses a boundary,
	// even though f1 itself is unchanged. This is the shift-left signal: new attack surface without a new flow.
	bounds := []TrustBoundary{{ID: "zone1"}, {ID: "zone2"}}
	prior := Model{
		Boundaries: bounds,
		Components: []Component{{ID: "a", Boundary: "zone1"}, {ID: "b", Boundary: "zone1"}},
		Flows:      []DataFlow{{ID: "f1", From: "a", To: "b"}},
	}
	next := Model{
		Boundaries: bounds,
		Components: []Component{{ID: "a", Boundary: "zone1"}, {ID: "b", Boundary: "zone2"}}, // b moved
		Flows:      []DataFlow{{ID: "f1", From: "a", To: "b"}},
	}
	d := Diff(prior, next)
	if len(d.AddedFlows) != 0 || len(d.RemovedFlows) != 0 {
		t.Errorf("f1 is unchanged – must not be added/removed: %+v", d)
	}
	if len(d.NewCrossings) != 1 || d.NewCrossings[0].ID != "f1" {
		t.Errorf("f1 newly crosses zone1→zone2 → one new crossing: %+v", d.NewCrossings)
	}
	if len(d.ClosedCrossings) != 0 {
		t.Errorf("nothing stopped crossing: %+v", d.ClosedCrossings)
	}
	if d.Empty() {
		t.Error("a new crossing is a non-empty delta")
	}
}

func TestDiffClosedCrossing(t *testing.T) {
	// the reverse of the above: b moves back into a's zone → f1 stops crossing.
	bounds := []TrustBoundary{{ID: "zone1"}, {ID: "zone2"}}
	prior := Model{
		Boundaries: bounds,
		Components: []Component{{ID: "a", Boundary: "zone1"}, {ID: "b", Boundary: "zone2"}},
		Flows:      []DataFlow{{ID: "f1", From: "a", To: "b"}},
	}
	next := Model{
		Boundaries: bounds,
		Components: []Component{{ID: "a", Boundary: "zone1"}, {ID: "b", Boundary: "zone1"}},
		Flows:      []DataFlow{{ID: "f1", From: "a", To: "b"}},
	}
	d := Diff(prior, next)
	if len(d.NewCrossings) != 0 {
		t.Errorf("no new crossing: %+v", d.NewCrossings)
	}
	if len(d.ClosedCrossings) != 1 || d.ClosedCrossings[0].ID != "f1" {
		t.Errorf("f1 stopped crossing → one closed crossing: %+v", d.ClosedCrossings)
	}
}

func TestDiffEmptyAndFirstIngest(t *testing.T) {
	m := Model{Components: []Component{{ID: "a"}}, Flows: []DataFlow{{ID: "f1", From: "a", To: "a"}}}
	if d := Diff(m, m); !d.Empty() {
		t.Errorf("identical models → empty delta, got %+v", d)
	}
	d := Diff(Model{}, m) // first ingest: prior is the zero Model → everything added
	if len(d.AddedComponents) != 1 || len(d.AddedFlows) != 1 {
		t.Errorf("first ingest must report everything as added: %+v", d)
	}
	if d.Empty() {
		t.Error("a first ingest is not an empty delta")
	}
}
