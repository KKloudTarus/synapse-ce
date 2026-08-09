package dastcheck

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestValidateParity(t *testing.T) {
	catalog := []CatalogEntry{{ID: "header-leak", CWE: "CWE-200", Class: ClassMisconfiguration, Title: "Header leak", Description: "A response reveals a server header.", Remediation: "Remove the header."}}
	checks := []Check{{ID: "header-leak", CWE: "CWE-200", Class: ClassMisconfiguration, BlastRadius: RadiusReadOnly, ProductionSafe: true, ProofClass: "response_header"}}
	if err := ValidateParity(catalog, checks); err != nil {
		t.Fatalf("ValidateParity: %v", err)
	}
	checks[0].Class = ClassInjection
	if err := ValidateParity(catalog, checks); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("drift = %v, want ErrValidation", err)
	}
}

func TestCheckRejectsUnsafeProductionMetadata(t *testing.T) {
	check := Check{ID: "state-change", CWE: "CWE-89", Class: ClassInjection, BlastRadius: RadiusStateChanging, ProductionSafe: true, ProofClass: "response_delta"}
	if err := check.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Validate() = %v, want ErrValidation", err)
	}
}
