// Package threatmodel is the architecture-input model that threat modeling reasons over:
// a data-flow diagram – components (processes, data stores, external entities), directed data flows between
// them, trust boundaries that partition them by trust level, and the assets at stake. It is PURE domain (no
// I/O, no LLM): the analysis layer proposes STRIDE threats as gated Judgments over THIS model, while the model itself only
// validates the DFD (fail-closed on dangling references) and answers the structural query STRIDE turns on –
// which data flows CROSS a trust boundary (the attack surface). Mirrors the callgraph/taint seams: a small
// pure value type an ingest adapter populates and the analysis layer queries, deterministic + table-testable.
package threatmodel

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ElementKind is a DFD element type; STRIDE applicability differs per kind, so it is part of the
// input and is fail-closed to a known set.
type ElementKind string

const (
	KindExternalEntity ElementKind = "external_entity" // an actor/system at the edge (user, third-party API)
	KindProcess        ElementKind = "process"         // code acting on data (a service, a handler)
	KindDataStore      ElementKind = "data_store"      // data at rest (database, bucket, file)
)

// Valid reports whether k is a known DFD element kind.
func (k ElementKind) Valid() bool {
	switch k {
	case KindExternalEntity, KindProcess, KindDataStore:
		return true
	}
	return false
}

// Component is one DFD node. Boundary is the TrustBoundary.ID it sits inside ("" = ungrouped / outermost);
// Assets are the Asset.IDs it holds or handles.
type Component struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Kind     ElementKind `json:"kind"`
	Boundary string      `json:"boundary,omitempty"`
	Assets   []string    `json:"assets,omitempty"`
}

// DataFlow is a directed edge: data moves From → To. A flow whose endpoints sit in different trust
// boundaries CROSSES one – where spoofing / tampering / information-disclosure threats concentrate.
type DataFlow struct {
	ID        string `json:"id"`
	From      string `json:"from"`                 // source Component.ID
	To        string `json:"to"`                   // destination Component.ID
	Data      string `json:"data,omitempty"`       // a human label for what flows (opaque free text – not a reference)
	DataAsset string `json:"data_asset,omitempty"` // optional Asset.ID this flow carries; validated when set, so the analysis layer can flag information-disclosure of a classified asset that crosses a boundary
}

// TrustBoundary partitions components by trust level (e.g. "internet", "vpc", "db-subnet").
type TrustBoundary struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Asset is a thing of value the model protects, with a classification label (e.g. "pii", "secret").
type Asset struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	Classification string `json:"classification,omitempty"`
}

// Model is the architecture-input DFD: the deterministic structure threat modeling reasons over.
type Model struct {
	Components []Component     `json:"components"`
	Flows      []DataFlow      `json:"flows"`
	Boundaries []TrustBoundary `json:"boundaries"`
	Assets     []Asset         `json:"assets"`
}

// Validate fail-closes a malformed model: ids must be non-empty + unique within their kind; every component
// kind must be known; a component's Boundary (when set) and Assets must reference declared entries; and every
// flow endpoint must reference a declared component. A dangling reference is rejected, not silently dropped –
// an ingested model with a typo'd boundary would otherwise hide the very crossing STRIDE looks for.
func (m Model) Validate() error {
	comps := make(map[string]bool, len(m.Components))
	for _, c := range m.Components {
		if c.ID == "" {
			return fmt.Errorf("%w: component with empty id", shared.ErrValidation)
		}
		if comps[c.ID] {
			return fmt.Errorf("%w: duplicate component id %q", shared.ErrValidation, c.ID)
		}
		comps[c.ID] = true
		if !c.Kind.Valid() {
			return fmt.Errorf("%w: component %q has unknown kind %q", shared.ErrValidation, c.ID, c.Kind)
		}
	}
	bounds := make(map[string]bool, len(m.Boundaries))
	for _, b := range m.Boundaries {
		if b.ID == "" {
			return fmt.Errorf("%w: trust boundary with empty id", shared.ErrValidation)
		}
		if bounds[b.ID] {
			return fmt.Errorf("%w: duplicate trust boundary id %q", shared.ErrValidation, b.ID)
		}
		bounds[b.ID] = true
	}
	assets := make(map[string]bool, len(m.Assets))
	for _, a := range m.Assets {
		if a.ID == "" {
			return fmt.Errorf("%w: asset with empty id", shared.ErrValidation)
		}
		if assets[a.ID] {
			return fmt.Errorf("%w: duplicate asset id %q", shared.ErrValidation, a.ID)
		}
		assets[a.ID] = true
	}
	// Referential integrity, checked after every declaration is known.
	for _, c := range m.Components {
		if c.Boundary != "" && !bounds[c.Boundary] {
			return fmt.Errorf("%w: component %q references unknown trust boundary %q", shared.ErrValidation, c.ID, c.Boundary)
		}
		for _, aid := range c.Assets {
			if !assets[aid] {
				return fmt.Errorf("%w: component %q references unknown asset %q", shared.ErrValidation, c.ID, aid)
			}
		}
	}
	flows := make(map[string]bool, len(m.Flows))
	for _, f := range m.Flows {
		if f.ID == "" {
			return fmt.Errorf("%w: data flow with empty id", shared.ErrValidation)
		}
		if flows[f.ID] {
			return fmt.Errorf("%w: duplicate data flow id %q", shared.ErrValidation, f.ID)
		}
		flows[f.ID] = true
		if !comps[f.From] {
			return fmt.Errorf("%w: data flow %q references unknown source component %q", shared.ErrValidation, f.ID, f.From)
		}
		if !comps[f.To] {
			return fmt.Errorf("%w: data flow %q references unknown destination component %q", shared.ErrValidation, f.ID, f.To)
		}
		if f.DataAsset != "" && !assets[f.DataAsset] {
			return fmt.Errorf("%w: data flow %q references unknown data asset %q", shared.ErrValidation, f.ID, f.DataAsset)
		}
	}
	return nil
}

// boundaryByComponent maps Component.ID → its Boundary (built once for the crossing query).
func (m Model) boundaryByComponent() map[string]string {
	out := make(map[string]string, len(m.Components))
	for _, c := range m.Components {
		out[c.ID] = c.Boundary
	}
	return out
}

// BoundaryCrossings returns the data flows whose endpoints sit in DIFFERENT trust boundaries – the attack
// surface threat modeling focuses on: a flow staying within one boundary is lower-risk, while one crossing a
// boundary is where an attacker on the lower-trust side can spoof/tamper/eavesdrop. Deterministic order (by
// flow id). A flow referencing an unknown component is skipped defensively (call Validate first to reject it).
func (m Model) BoundaryCrossings() []DataFlow {
	bc := m.boundaryByComponent()
	var out []DataFlow
	for _, f := range m.Flows {
		from, okF := bc[f.From]
		to, okT := bc[f.To]
		if !okF || !okT {
			continue
		}
		if from != to {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID }) // stable: deterministic even on an unvalidated model with duplicate flow ids
	return out
}
