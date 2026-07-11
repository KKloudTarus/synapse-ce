package threatmodel

import "sort"

// ModelDelta is the deterministic change between two versions of an architecture model (the
// shift-left "re-run on architecture change, surface deltas" hook): which components and flows were
// added/removed, and – most actionable – which data flows newly CROSS a trust boundary (new attack surface)
// or no longer do (closed surface). Pure data, NO LLM: it is computed from the two stored models and
// recorded in the append-only audit trail, so an architecture change is attributable and its security
// impact (new crossings) is visible without re-running the agent.
type ModelDelta struct {
	AddedComponents   []Component `json:"added_components,omitempty"`
	RemovedComponents []Component `json:"removed_components,omitempty"`
	AddedFlows        []DataFlow  `json:"added_flows,omitempty"`
	RemovedFlows      []DataFlow  `json:"removed_flows,omitempty"`
	NewCrossings      []DataFlow  `json:"new_boundary_crossings,omitempty"`    // flows that now cross a trust boundary
	ClosedCrossings   []DataFlow  `json:"closed_boundary_crossings,omitempty"` // flows that no longer cross one
}

// Empty reports whether the two models are structurally identical (no added/removed components or flows, and
// no change in the boundary-crossing set) – i.e. the architecture change introduced no DFD delta.
func (d ModelDelta) Empty() bool {
	return len(d.AddedComponents) == 0 && len(d.RemovedComponents) == 0 &&
		len(d.AddedFlows) == 0 && len(d.RemovedFlows) == 0 &&
		len(d.NewCrossings) == 0 && len(d.ClosedCrossings) == 0
}

// Diff computes the change from prior to next. Elements are keyed by ID: present in next but not prior ⇒
// Added; present in prior but not next ⇒ Removed. NewCrossings/ClosedCrossings diff the two models'
// BoundaryCrossings sets – a flow that newly crosses a boundary (a re-homed component, a new cross-boundary
// flow) is NEW attack surface even if the flow itself already existed, which is exactly the shift-left
// signal. Deterministic (sorted by id); pure (the inputs are not mutated). A first ingest (prior is the zero
// Model) yields everything as Added.
func Diff(prior, next Model) ModelDelta {
	componentID := func(c Component) string { return c.ID }
	flowID := func(f DataFlow) string { return f.ID }
	var d ModelDelta
	d.AddedComponents, d.RemovedComponents = diffByID(prior.Components, next.Components, componentID)
	d.AddedFlows, d.RemovedFlows = diffByID(prior.Flows, next.Flows, flowID)
	d.NewCrossings, d.ClosedCrossings = diffByID(prior.BoundaryCrossings(), next.BoundaryCrossings(), flowID)
	return d
}

// diffByID returns (added, removed) = (in next not prior, in prior not next), keyed by id, each sorted by id
// for a deterministic result. Pure.
func diffByID[T any](prior, next []T, id func(T) string) (added, removed []T) {
	priorIDs := make(map[string]bool, len(prior))
	for _, e := range prior {
		priorIDs[id(e)] = true
	}
	nextIDs := make(map[string]bool, len(next))
	for _, e := range next {
		nextIDs[id(e)] = true
	}
	for _, e := range next {
		if !priorIDs[id(e)] {
			added = append(added, e)
		}
	}
	for _, e := range prior {
		if !nextIDs[id(e)] {
			removed = append(removed, e)
		}
	}
	sort.SliceStable(added, func(i, j int) bool { return id(added[i]) < id(added[j]) })
	sort.SliceStable(removed, func(i, j int) bool { return id(removed[i]) < id(removed[j]) })
	return added, removed
}
