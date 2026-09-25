package reachbench

import (
	"testing"

	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestVersionedGoBinaryProfileEnumeratesMeasuredWorkerCells(t *testing.T) {
	input, err := measurement.GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFrozenTemplateStaticContract(input); err != nil {
		t.Fatalf("resolve registered successor profile: %v", err)
	}
	profile, err := measurement.ResolveReachabilityProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Authoritative {
		t.Fatal("pending successor profile acquired authoritative status")
	}
	if err := requireProfileAuthority(profile, true); err == nil {
		t.Fatal("pending successor profile entered an authoritative route")
	}
	if err := requireProfileAuthority(profile, false); err != nil {
		t.Fatalf("pending successor profile cannot run a local diagnostic: %v", err)
	}
	cells, err := enumerateCells(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 100 {
		t.Fatalf("successor cells = %d, want 100", len(cells))
	}
	workerCells := 0
	for _, cell := range cells {
		if cell.CohortID != "go" || cell.ModeID != "binary" || cell.BindingID != "worker" {
			continue
		}
		workerCells++
		registered, err := profile.ResolveFixtureSpecification(cell.Fixture)
		if err != nil {
			t.Fatalf("resolve %s fixture in selected profile: %v", cell.CaseID, err)
		}
		if _, _, err := frozenFixtureSpecification(registered); err != nil {
			t.Fatalf("materializer rejected selected %s fixture: %v", cell.CaseID, err)
		}
	}
	if workerCells != 5 {
		t.Fatalf("Go binary worker cells = %d, want 5", workerCells)
	}
}

func TestVersionedGoBinaryProfileRejectsMixedStaticContract(t *testing.T) {
	input, err := measurement.GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := measurement.DefaultBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	input.Inventory = legacy.Inventory
	if err := validateFrozenTemplateStaticContract(input); err == nil {
		t.Fatal("mixed successor and legacy static components resolved")
	}
	if _, err := enumerateCells(input); err == nil {
		t.Fatal("mixed successor and legacy components produced a capture plan")
	}
}

func TestVersionedGoBinaryProfileRejectsLegacyCheckpoint(t *testing.T) {
	legacy := newFixture(t).candidate
	successor, err := measurement.GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	legacy.Inventory = successor.Inventory
	legacy.Corpus = successor.Corpus
	legacy.Oracle = successor.Oracle
	legacy.Policy = successor.Policy
	legacy.Exceptions = successor.Exceptions
	legacy.ActiveSnapshot = successor.ActiveSnapshot
	if legacy.Checkpoint == nil {
		t.Fatal("legacy candidate has no procedural checkpoint")
	}
	if err := legacy.Validate(); err == nil {
		t.Fatal("legacy checkpoint and ratchet validated against successor inventory")
	}
}
