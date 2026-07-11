package threatmodel

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// sampleModel: internet (external entity) → api (process, in vpc) → db (data store, in vpc), holding a PII
// asset. The internet→api flow crosses the internet→vpc boundary; api→db stays within vpc.
func sampleModel() Model {
	return Model{
		Boundaries: []TrustBoundary{{ID: "internet", Name: "Internet"}, {ID: "vpc", Name: "VPC"}},
		Assets:     []Asset{{ID: "pii", Name: "user records", Classification: "pii"}},
		Components: []Component{
			{ID: "user", Name: "End user", Kind: KindExternalEntity, Boundary: "internet"},
			{ID: "api", Name: "API service", Kind: KindProcess, Boundary: "vpc"},
			{ID: "db", Name: "Postgres", Kind: KindDataStore, Boundary: "vpc", Assets: []string{"pii"}},
		},
		Flows: []DataFlow{
			{ID: "f1", From: "user", To: "api", Data: "http request"},                 // crosses internet → vpc
			{ID: "f2", From: "api", To: "db", Data: "user records", DataAsset: "pii"}, // stays within vpc; carries the pii asset
		},
	}
}

func TestValidateHappyPath(t *testing.T) {
	if err := sampleModel().Validate(); err != nil {
		t.Fatalf("valid model rejected: %v", err)
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Model)
	}{
		{"empty component id", func(m *Model) { m.Components[0].ID = "" }},
		{"duplicate component id", func(m *Model) { m.Components[1].ID = "user" }},
		{"unknown component kind", func(m *Model) { m.Components[0].Kind = "gateway" }},
		{"dangling boundary ref", func(m *Model) { m.Components[1].Boundary = "nope" }},
		{"dangling asset ref", func(m *Model) { m.Components[2].Assets = []string{"ghost"} }},
		{"empty flow id", func(m *Model) { m.Flows[0].ID = "" }},
		{"duplicate flow id", func(m *Model) { m.Flows[1].ID = "f1" }},
		{"dangling flow source", func(m *Model) { m.Flows[0].From = "ghost" }},
		{"dangling flow dest", func(m *Model) { m.Flows[0].To = "ghost" }},
		{"dangling data asset ref", func(m *Model) { m.Flows[0].DataAsset = "ghost" }},
		{"empty boundary id", func(m *Model) { m.Boundaries[0].ID = "" }},
		{"duplicate boundary id", func(m *Model) { m.Boundaries[1].ID = "internet" }},
		{"empty asset id", func(m *Model) { m.Assets[0].ID = "" }},
		{"duplicate asset id", func(m *Model) { m.Assets = append(m.Assets, Asset{ID: "pii"}) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := sampleModel()
			c.mutate(&m)
			err := m.Validate()
			if err == nil {
				t.Fatalf("%s: want validation error, got nil", c.name)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("%s: want ErrValidation, got %v", c.name, err)
			}
		})
	}
}

func TestBoundaryCrossings(t *testing.T) {
	got := sampleModel().BoundaryCrossings()
	if len(got) != 1 || got[0].ID != "f1" {
		t.Fatalf("want only f1 (internet→vpc) crossing, got %+v", got)
	}
}

// TestBoundaryCrossingsUngroupedVsNamed: a flow between an ungrouped component ("") and a boundaried one
// counts as crossing (different boundary), and results are deterministically ordered by flow id.
func TestBoundaryCrossingsUngroupedVsNamed(t *testing.T) {
	m := Model{
		Boundaries: []TrustBoundary{{ID: "vpc"}},
		Components: []Component{
			{ID: "ext", Kind: KindExternalEntity}, // ungrouped ("")
			{ID: "svc", Kind: KindProcess, Boundary: "vpc"},
			{ID: "svc2", Kind: KindProcess, Boundary: "vpc"},
		},
		Flows: []DataFlow{
			{ID: "z", From: "ext", To: "svc"},  // "" → vpc: crosses
			{ID: "a", From: "ext", To: "svc2"}, // "" → vpc: crosses
			{ID: "m", From: "svc", To: "svc2"}, // vpc → vpc: no cross
		},
	}
	got := m.BoundaryCrossings()
	if len(got) != 2 {
		t.Fatalf("want 2 crossings, got %+v", got)
	}
	if got[0].ID != "a" || got[1].ID != "z" { // sorted by id
		t.Errorf("crossings must be sorted by flow id, got %s,%s", got[0].ID, got[1].ID)
	}
}

// TestBoundaryCrossingsNoBoundaries: with no trust boundaries declared, every component is "" – no flow
// crosses, so there is no attack surface to model (the empty/degenerate case).
func TestBoundaryCrossingsNoBoundaries(t *testing.T) {
	m := Model{
		Components: []Component{{ID: "a", Kind: KindProcess}, {ID: "b", Kind: KindProcess}},
		Flows:      []DataFlow{{ID: "f", From: "a", To: "b"}},
	}
	if got := m.BoundaryCrossings(); len(got) != 0 {
		t.Fatalf("no boundaries → no crossings, got %+v", got)
	}
}
