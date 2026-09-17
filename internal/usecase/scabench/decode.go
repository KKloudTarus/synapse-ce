package scabench

import (
	"fmt"
	"io"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// MaxJSONBytes remains the SCA compatibility name for the neutral document bound.
const MaxJSONBytes int64 = benchmark.MaxJSONBytes

// DecodeCatalog strictly decodes and validates one versioned catalog JSON value.
func DecodeCatalog(reader io.Reader) (Catalog, error) {
	var catalog Catalog
	if err := strictDecode(reader, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode catalog: %w", err)
	}
	if err := catalog.Validate(); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

// DecodeOracle strictly decodes and validates an oracle's self-contained invariants.
// Use Validate with its Catalog before reducing observations to verify target/component cross-references.
func DecodeOracle(reader io.Reader) (Oracle, error) {
	var oracle Oracle
	if err := strictDecode(reader, &oracle); err != nil {
		return Oracle{}, fmt.Errorf("decode oracle: %w", err)
	}
	if err := oracle.Validate(); err != nil {
		return Oracle{}, err
	}
	return oracle, nil
}

// DecodeObservationSet strictly decodes one versioned observation envelope.
func DecodeObservationSet(reader io.Reader) (ObservationSet, error) {
	var set ObservationSet
	if err := strictDecode(reader, &set); err != nil {
		return ObservationSet{}, fmt.Errorf("decode observation set: %w", err)
	}
	if err := set.Validate(); err != nil {
		return ObservationSet{}, err
	}
	return set, nil
}

// DecodeRatchet strictly decodes a ratchet shape; it does not evaluate thresholds.
func DecodeRatchet(reader io.Reader) (Ratchet, error) {
	var ratchet Ratchet
	if err := strictDecode(reader, &ratchet); err != nil {
		return Ratchet{}, fmt.Errorf("decode ratchet: %w", err)
	}
	if err := ratchet.Validate(); err != nil {
		return Ratchet{}, err
	}
	return ratchet, nil
}

// DecodeResult strictly decodes a result document and rejects unsupported versions.
func DecodeResult(reader io.Reader) (Result, error) {
	var result Result
	if err := strictDecode(reader, &result); err != nil {
		return Result{}, fmt.Errorf("decode result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// ValidateJSONDocument preserves SCA's bounded strict-document contract through the neutral helper.
func ValidateJSONDocument(reader io.Reader) error {
	return benchmark.ValidateJSONDocument(reader)
}

// Validate validates an observation envelope's self-contained invariants.
func (set ObservationSet) Validate() error {
	if set.SchemaVersion != ObservationSchemaVersion {
		return fmt.Errorf("unsupported observation set schema %q", set.SchemaVersion)
	}
	if strings.TrimSpace(set.CatalogRevision) == "" || !validSHA256Digest(set.CatalogDigest) {
		return fmt.Errorf("observation set catalog revision and digest are required")
	}
	seen := make(map[observationKey]struct{}, len(set.Observations))
	for i, observation := range set.Observations {
		if err := validateObservationEnvelope(observation, set.CatalogRevision, set.CatalogDigest); err != nil {
			return fmt.Errorf("observation %d: %w", i, err)
		}
		key := observationKey{Engine: observation.Engine, TargetID: observation.TargetID}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("observation for engine %q and target %q is duplicated", observation.Engine, observation.TargetID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func strictDecode(reader io.Reader, destination any) error {
	return benchmark.StrictDecode(reader, destination)
}
