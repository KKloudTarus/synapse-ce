package judgment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CompletenessObligation names a required class of completeness evidence.
type CompletenessObligation string

const (
	ObligationEnumeration   CompletenessObligation = "enumeration"
	ObligationEntrypoints   CompletenessObligation = "entrypoints"
	ObligationOpaqueSurface CompletenessObligation = "opaque_surface"
	ObligationRuntimeInputs CompletenessObligation = "runtime_inputs"
	ObligationDeployInputs  CompletenessObligation = "deployment_inputs"
)

// CompletenessContractDefinition is the mutable construction input for one
// immutable completeness contract. Slice ordering is part of the contract digest.
type CompletenessContractDefinition struct {
	ID               string
	ReviewerRole     string
	Enumeration      []string
	Entrypoints      []string
	OpaqueSurface    []string
	RuntimeInputs    []string
	DeploymentInputs []string
}

// CompletenessContract is an immutable, procedurally defined completeness contract.
// Its digest detects definition drift; it is not proof of an external artifact origin.
type CompletenessContract struct {
	id               string
	digest           string
	reviewerRole     string
	enumeration      []string
	entrypoints      []string
	opaqueSurface    []string
	runtimeInputs    []string
	deploymentInputs []string
}

// completenessContractDigestMaterial has a fixed field order and only ordered
// slices, so its standard-library JSON encoding is canonical for a validated contract.
type completenessContractDigestMaterial struct {
	Version          string   `json:"version"`
	ID               string   `json:"id"`
	ReviewerRole     string   `json:"reviewer_role"`
	Enumeration      []string `json:"enumeration"`
	Entrypoints      []string `json:"entrypoints"`
	OpaqueSurface    []string `json:"opaque_surface"`
	RuntimeInputs    []string `json:"runtime_inputs"`
	DeploymentInputs []string `json:"deployment_inputs"`
}

// NewCompletenessContract validates and freezes a contract definition. Every
// obligation class must contain at least one explicit, canonical obligation.
func NewCompletenessContract(definition CompletenessContractDefinition) (CompletenessContract, error) {
	if !validStableIdentity(definition.ID) {
		return CompletenessContract{}, fmt.Errorf("%w: completeness contract requires a stable id", shared.ErrValidation)
	}
	if !validStableIdentity(definition.ReviewerRole) {
		return CompletenessContract{}, fmt.Errorf("%w: completeness contract requires a stable reviewer role", shared.ErrValidation)
	}

	enumeration, err := cloneValidatedObligations("enumeration", definition.Enumeration)
	if err != nil {
		return CompletenessContract{}, err
	}
	entrypoints, err := cloneValidatedObligations("entrypoints", definition.Entrypoints)
	if err != nil {
		return CompletenessContract{}, err
	}
	opaqueSurface, err := cloneValidatedObligations("opaque surface", definition.OpaqueSurface)
	if err != nil {
		return CompletenessContract{}, err
	}
	runtimeInputs, err := cloneValidatedObligations("runtime inputs", definition.RuntimeInputs)
	if err != nil {
		return CompletenessContract{}, err
	}
	deploymentInputs, err := cloneValidatedObligations("deployment inputs", definition.DeploymentInputs)
	if err != nil {
		return CompletenessContract{}, err
	}

	contract := CompletenessContract{
		id:               definition.ID,
		reviewerRole:     definition.ReviewerRole,
		enumeration:      enumeration,
		entrypoints:      entrypoints,
		opaqueSurface:    opaqueSurface,
		runtimeInputs:    runtimeInputs,
		deploymentInputs: deploymentInputs,
	}
	digest, err := canonicalCompletenessContractDigest(contract)
	if err != nil {
		return CompletenessContract{}, err
	}
	contract.digest = digest
	return contract, nil
}

// ID returns the contract's stable identity.
func (c CompletenessContract) ID() string { return c.id }

// Digest returns the canonical SHA-256 digest of the complete contract definition.
func (c CompletenessContract) Digest() string { return c.digest }

// ReviewerRole returns the stable reviewer-role identity required by this contract.
func (c CompletenessContract) ReviewerRole() string { return c.reviewerRole }

// Obligations returns a copy of the ordered obligations for one obligation class.
func (c CompletenessContract) Obligations(kind CompletenessObligation) []string {
	return cloneStrings(c.obligations(kind))
}

// Matches reports whether a supplied stable ID and digest name this unchanged contract.
func (c CompletenessContract) Matches(id, digest string) bool {
	return c.Valid() && c.id == id && c.digest == digest
}

// Valid reports whether the contract remains complete and its canonical digest
// still matches its immutable definition.
func (c CompletenessContract) Valid() bool {
	if !validStableIdentity(c.id) || !validStableIdentity(c.reviewerRole) || !validSHA256Digest(c.digest) {
		return false
	}
	for _, obligations := range [][]string{
		c.enumeration,
		c.entrypoints,
		c.opaqueSurface,
		c.runtimeInputs,
		c.deploymentInputs,
	} {
		if !validObligations(obligations) {
			return false
		}
	}
	digest, err := canonicalCompletenessContractDigest(c)
	return err == nil && c.digest == digest
}

// ValidateFor reports whether a complete, unchanged contract represents every
// required obligation class for the cohort that wants suppression authority.
func (c CompletenessContract) ValidateFor(required []CompletenessObligation) error {
	if !c.Valid() {
		return fmt.Errorf("%w: invalid or stale completeness contract", shared.ErrValidation)
	}
	for index, obligation := range required {
		if !obligation.Valid() {
			return fmt.Errorf("%w: unknown required completeness obligation at index %d", shared.ErrValidation, index)
		}
		if !validObligations(c.obligations(obligation)) {
			return fmt.Errorf("%w: completeness contract is missing %s obligations", shared.ErrValidation, obligation)
		}
		for prior := 0; prior < index; prior++ {
			if required[prior] == obligation {
				return fmt.Errorf("%w: duplicate required completeness obligation %q", shared.ErrValidation, obligation)
			}
		}
	}
	return nil
}

// Valid reports whether the obligation class is known.
func (o CompletenessObligation) Valid() bool {
	switch o {
	case ObligationEnumeration, ObligationEntrypoints, ObligationOpaqueSurface, ObligationRuntimeInputs, ObligationDeployInputs:
		return true
	}
	return false
}

func (c CompletenessContract) obligations(kind CompletenessObligation) []string {
	switch kind {
	case ObligationEnumeration:
		return c.enumeration
	case ObligationEntrypoints:
		return c.entrypoints
	case ObligationOpaqueSurface:
		return c.opaqueSurface
	case ObligationRuntimeInputs:
		return c.runtimeInputs
	case ObligationDeployInputs:
		return c.deploymentInputs
	default:
		return nil
	}
}

func cloneValidatedObligations(name string, obligations []string) ([]string, error) {
	if !validObligations(obligations) {
		return nil, fmt.Errorf("%w: completeness contract requires canonical %s obligations", shared.ErrValidation, name)
	}
	return cloneStrings(obligations), nil
}

func validObligations(obligations []string) bool {
	if len(obligations) == 0 {
		return false
	}
	for index, obligation := range obligations {
		if obligation == "" || obligation != strings.TrimSpace(obligation) || len(obligation) > 256 {
			return false
		}
		for prior := 0; prior < index; prior++ {
			if obligations[prior] == obligation {
				return false
			}
		}
	}
	return true
}

func canonicalCompletenessContractDigest(contract CompletenessContract) (string, error) {
	material, err := json.Marshal(completenessContractDigestMaterial{
		Version:          "reachability-completeness-contract-v1",
		ID:               contract.id,
		ReviewerRole:     contract.reviewerRole,
		Enumeration:      contract.enumeration,
		Entrypoints:      contract.entrypoints,
		OpaqueSurface:    contract.opaqueSurface,
		RuntimeInputs:    contract.runtimeInputs,
		DeploymentInputs: contract.deploymentInputs,
	})
	if err != nil {
		return "", fmt.Errorf("marshal completeness contract digest material: %w", err)
	}
	sum := sha256.Sum256(material)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func cloneCompletenessContract(contract CompletenessContract) CompletenessContract {
	return CompletenessContract{
		id:               contract.id,
		digest:           contract.digest,
		reviewerRole:     contract.reviewerRole,
		enumeration:      cloneStrings(contract.enumeration),
		entrypoints:      cloneStrings(contract.entrypoints),
		opaqueSurface:    cloneStrings(contract.opaqueSurface),
		runtimeInputs:    cloneStrings(contract.runtimeInputs),
		deploymentInputs: cloneStrings(contract.deploymentInputs),
	}
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}
