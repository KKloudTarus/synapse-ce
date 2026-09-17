package reachbench

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

//go:embed inventory/production.json
var defaultProductionInventoryJSON []byte

// DefaultProductionInventory returns the checked-in full production inventory. Its not_assessed state is honest:
// current v1 fixtures do not exercise each production binding/case required by this v2 contract.
func DefaultProductionInventory() ProductionInventory {
	inventory, err := LoadProductionInventory(bytes.NewReader(defaultProductionInventoryJSON))
	if err != nil {
		panic("reachbench: embedded production inventory is invalid: " + err.Error())
	}
	return inventory
}

// LoadProductionInventory strictly decodes and validates the production inventory manifest.
func LoadProductionInventory(reader io.Reader) (ProductionInventory, error) {
	var inventory ProductionInventory
	if err := benchmark.StrictDecode(reader, &inventory); err != nil {
		return ProductionInventory{}, fmt.Errorf("decode production inventory: %w", err)
	}
	if err := inventory.Validate(); err != nil {
		return ProductionInventory{}, err
	}
	return canonicalInventory(inventory), nil
}

// DecodeMeasurementInput strictly decodes one v2 measurement envelope.
func DecodeMeasurementInput(reader io.Reader) (MeasurementInput, error) {
	var input MeasurementInput
	if err := benchmark.StrictDecode(reader, &input); err != nil {
		return MeasurementInput{}, fmt.Errorf("decode reachability measurement input: %w", err)
	}
	if err := input.Validate(); err != nil {
		return MeasurementInput{}, err
	}
	return input, nil
}

// EncodeMeasurementReport writes a canonical v2 report and verifies its self digest before publication.
func EncodeMeasurementReport(writer io.Writer, report MeasurementReport) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validate reachability measurement report: %w", err)
	}
	encoded, err := benchmark.CanonicalJSON(canonicalReport(report))
	if err != nil {
		return fmt.Errorf("encode reachability measurement report: %w", err)
	}
	if err := benchmark.WriteCanonicalJSON(writer, encoded); err != nil {
		return fmt.Errorf("write reachability measurement report: %w", err)
	}
	return nil
}

// DecodeMeasurementReport strictly decodes and verifies a canonical report's digest binding.
func DecodeMeasurementReport(reader io.Reader) (MeasurementReport, error) {
	var report MeasurementReport
	if err := benchmark.StrictDecode(reader, &report); err != nil {
		return MeasurementReport{}, fmt.Errorf("decode reachability measurement report: %w", err)
	}
	if err := report.Validate(); err != nil {
		return MeasurementReport{}, err
	}
	return canonicalReport(report), nil
}

// ConvertV1Input is the only supported v1 conversion direction. It preserves raw bytes, the original digest,
// and labels while explicitly recording unavailable v2 evidence. The result cannot be accepted by EvaluateMeasurement.
func ConvertV1Input(raw []byte) (LegacyV1Evidence, error) {
	input, err := DecodeInput(bytes.NewReader(raw))
	if err != nil {
		return LegacyV1Evidence{}, fmt.Errorf("decode v1 reachability input: %w", err)
	}
	labels := make([]LegacyLabel, len(input.Observations))
	for i, observation := range input.Observations {
		labels[i] = LegacyLabel{CaseID: observation.Case, Label: observation.Label}
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].CaseID < labels[j].CaseID })
	return LegacyV1Evidence{
		OriginalBytes:         append([]byte(nil), raw...),
		OriginalDigest:        benchmark.SHA256Digest(raw),
		Labels:                labels,
		Coverage:              LegacyUnavailable,
		SuppressionCapture:    LegacyUnavailable,
		AnalyzerIdentity:      LegacyUnavailable,
		ConfigurationIdentity: LegacyUnavailable,
		SnapshotIdentity:      LegacyUnavailable,
		Authority:             LegacyUnavailable,
	}, nil
}

// MigrateV1Corpus preserves all existing v1 labels in a structurally v2 corpus. LegacyOrigin deliberately
// prevents its fixture identities from being presented as immutable v2 production evidence.
func MigrateV1Corpus(corpus Corpus) (ContractCorpus, ReachabilityOracle, error) {
	if err := validateCorpus(corpus); err != nil {
		return ContractCorpus{}, ReachabilityOracle{}, err
	}
	legacyDigest, err := corpusDigest(corpus)
	if err != nil {
		return ContractCorpus{}, ReachabilityOracle{}, err
	}
	cases := make([]ContractCase, len(corpus.Cases))
	oracleCases := make([]OracleCase, len(corpus.Cases))
	for i, item := range corpus.Cases {
		cohort, mode := legacyCohort(item.Language)
		cases[i] = ContractCase{
			ID:        item.Name,
			SubjectID: "legacy-subject/" + item.Name,
			CohortID:  cohort,
			ModeID:    mode,
			LegacyOrigin: &LegacyCaseReference{
				OriginalCorpusDigest: legacyDigest,
				OriginalCaseID:       item.Name,
			},
		}
		oracleCases[i] = OracleCase{
			CaseID:              item.Name,
			Expected:            Outcome(item.Expected),
			Category:            OracleNoCoverage,
			CoverageExpectation: CoverageUnavailable,
		}
	}
	migrated := ContractCorpus{SchemaVersion: ContractCorpusSchemaVersion, ID: "migrated-v1-corpus", Cases: cases}
	oracle := ReachabilityOracle{SchemaVersion: OracleSchemaVersionV2, ID: "migrated-v1-oracle", Cases: oracleCases}
	if err := migrated.Validate(); err != nil {
		return ContractCorpus{}, ReachabilityOracle{}, err
	}
	if err := oracle.ValidateAgainst(migrated); err != nil {
		return ContractCorpus{}, ReachabilityOracle{}, err
	}
	return canonicalCorpus(migrated), canonicalOracleV2(oracle), nil
}

func legacyCohort(_ string) (string, string) {
	// v1 labels have no immutable fixture, boundary, category, or coverage authority. They are
	// intentionally kept outside every modern production cohort rather than being relabeled as proof.
	return "legacy", "v1"
}
