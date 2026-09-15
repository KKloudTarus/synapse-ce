package scabench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// SHA256Digest returns a lower-case, immutable sha256 digest with its algorithm prefix.
func SHA256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalJSON encodes a value with the deterministic guarantees of encoding/json for structs and maps.
// Callers with order-insensitive slices should use the type-specific digest helpers below.
func CanonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// DigestCatalog produces a stable digest regardless of target, component, or pin input order.
func DigestCatalog(catalog Catalog) (string, error) {
	canonical := canonicalCatalog(catalog)
	encoded, err := CanonicalJSON(canonical)
	if err != nil {
		return "", err
	}
	return SHA256Digest(encoded), nil
}

// DigestOracle produces a stable digest regardless of case, alias, reviewer, or citation input order.
func DigestOracle(oracle Oracle) (string, error) {
	canonical := canonicalOracle(oracle)
	encoded, err := CanonicalJSON(canonical)
	if err != nil {
		return "", err
	}
	return SHA256Digest(encoded), nil
}

// DigestObservations produces a stable digest regardless of observation and finding input order.
func DigestObservations(observations []Observation) (string, error) {
	canonical := canonicalObservations(observations)
	encoded, err := CanonicalJSON(canonical)
	if err != nil {
		return "", err
	}
	return SHA256Digest(encoded), nil
}

// scoringObservation is the explicit score-bearing projection of Observation.
// RawOutputDigest is provenance-only and deliberately excluded.
type scoringObservation struct {
	SchemaVersion      string           `json:"schema_version"`
	CatalogRevision    string           `json:"catalog_revision"`
	CatalogDigest      string           `json:"catalog_digest"`
	Engine             Engine           `json:"engine"`
	EngineVersion      string           `json:"engine_version"`
	EngineBinaryDigest string           `json:"engine_binary_digest"`
	DatabaseBuild      string           `json:"database_build"`
	DatabaseDigest     string           `json:"database_digest"`
	EnvironmentID      string           `json:"environment_id"`
	EnvironmentDigest  string           `json:"environment_digest"`
	TargetID           string           `json:"target_id"`
	TargetDigest       string           `json:"target_digest"`
	SBOMDigest         string           `json:"sbom_digest"`
	State              ObservationState `json:"state"`
	ConfigDigest       string           `json:"config_digest"`
	CapabilityKind     CapabilityKind   `json:"capability_kind,omitempty"`
	CapabilityDigest   string           `json:"capability_digest,omitempty"`
	Findings           []Finding        `json:"findings,omitempty"`
}

// DigestScoringObservations produces a stable digest of every score-bearing observation field.
func DigestScoringObservations(observations []Observation) (string, error) {
	canonical := canonicalScoringObservations(observations)
	encoded, err := CanonicalJSON(canonical)
	if err != nil {
		return "", err
	}
	return SHA256Digest(encoded), nil
}

func canonicalScoringObservations(observations []Observation) []scoringObservation {
	out := make([]scoringObservation, len(observations))
	for i, observation := range observations {
		out[i] = scoringObservationFromObservation(observation)
		out[i].Findings = canonicalFindings(out[i].Findings)
	}
	sort.Slice(out, func(i, j int) bool {
		return observationLess(out[i].asObservation(), out[j].asObservation())
	})
	return out
}

func scoringObservationFromObservation(observation Observation) scoringObservation {
	return scoringObservation{
		SchemaVersion:      observation.SchemaVersion,
		CatalogRevision:    observation.CatalogRevision,
		CatalogDigest:      observation.CatalogDigest,
		Engine:             observation.Engine,
		EngineVersion:      observation.EngineVersion,
		EngineBinaryDigest: observation.EngineBinaryDigest,
		DatabaseBuild:      observation.DatabaseBuild,
		DatabaseDigest:     observation.DatabaseDigest,
		EnvironmentID:      observation.EnvironmentID,
		EnvironmentDigest:  observation.EnvironmentDigest,
		TargetID:           observation.TargetID,
		TargetDigest:       observation.TargetDigest,
		SBOMDigest:         observation.SBOMDigest,
		State:              observation.State,
		ConfigDigest:       observation.ConfigDigest,
		CapabilityKind:     observation.CapabilityKind,
		CapabilityDigest:   observation.CapabilityDigest,
		Findings:           observation.Findings,
	}
}

func (observation scoringObservation) asObservation() Observation {
	return Observation{
		SchemaVersion:      observation.SchemaVersion,
		CatalogRevision:    observation.CatalogRevision,
		CatalogDigest:      observation.CatalogDigest,
		Engine:             observation.Engine,
		EngineVersion:      observation.EngineVersion,
		EngineBinaryDigest: observation.EngineBinaryDigest,
		DatabaseBuild:      observation.DatabaseBuild,
		DatabaseDigest:     observation.DatabaseDigest,
		EnvironmentID:      observation.EnvironmentID,
		EnvironmentDigest:  observation.EnvironmentDigest,
		TargetID:           observation.TargetID,
		TargetDigest:       observation.TargetDigest,
		SBOMDigest:         observation.SBOMDigest,
		State:              observation.State,
		ConfigDigest:       observation.ConfigDigest,
		CapabilityKind:     observation.CapabilityKind,
		CapabilityDigest:   observation.CapabilityDigest,
		Findings:           observation.Findings,
	}
}

// EncodeObservationSet validates and writes a canonical observation envelope.
func EncodeObservationSet(writer io.Writer, set ObservationSet) error {
	set.Observations = canonicalObservations(set.Observations)
	if err := set.Validate(); err != nil {
		return fmt.Errorf("validate observation set: %w", err)
	}
	encoded, err := CanonicalJSON(set)
	if err != nil {
		return fmt.Errorf("encode observation set: %w", err)
	}
	if err := writeCanonicalJSON(writer, encoded); err != nil {
		return fmt.Errorf("write observation set: %w", err)
	}
	return nil
}

// DigestRatchet produces a stable digest regardless of supplied floor order.
func DigestRatchet(ratchet Ratchet) (string, error) {
	canonical := canonicalRatchet(ratchet)
	encoded, err := CanonicalJSON(canonical)
	if err != nil {
		return "", err
	}
	return SHA256Digest(encoded), nil
}

// DigestResult produces a stable result digest. The ID field is excluded to avoid self-reference.
func DigestResult(result Result) (string, error) {
	canonical := canonicalResult(result)
	canonical.ID = ""
	encoded, err := CanonicalJSON(canonical)
	if err != nil {
		return "", err
	}
	return SHA256Digest(encoded), nil
}

// EncodeResult writes one deterministic JSON result followed by a newline.
func EncodeResult(writer io.Writer, result Result) error {
	canonical := canonicalResult(result)
	if canonical.SchemaVersion != ResultSchemaVersion {
		return fmt.Errorf("unsupported result schema %q", canonical.SchemaVersion)
	}
	id, err := DigestResult(canonical)
	if err != nil {
		return fmt.Errorf("digest result: %w", err)
	}
	canonical.ID = id
	if err := canonical.Validate(); err != nil {
		return fmt.Errorf("validate result: %w", err)
	}
	encoded, err := CanonicalJSON(canonical)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	if err := writeCanonicalJSON(writer, encoded); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func writeCanonicalJSON(writer io.Writer, encoded []byte) error {
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > MaxJSONBytes {
		return fmt.Errorf("JSON output exceeds %d byte limit", MaxJSONBytes)
	}
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return nil
}

func canonicalCatalog(catalog Catalog) Catalog {
	out := catalog
	out.Targets = append([]Target(nil), catalog.Targets...)
	for i := range out.Targets {
		out.Targets[i].Components = append([]Component(nil), out.Targets[i].Components...)
		sort.Slice(out.Targets[i].Components, func(left, right int) bool {
			leftKey, leftErr := componentIdentityKey(out.Targets[i].Components[left])
			rightKey, rightErr := componentIdentityKey(out.Targets[i].Components[right])
			if leftErr == nil && rightErr == nil && leftKey != rightKey {
				return componentKeyText(leftKey) < componentKeyText(rightKey)
			}
			if out.Targets[i].Components[left].PURL != out.Targets[i].Components[right].PURL {
				return out.Targets[i].Components[left].PURL < out.Targets[i].Components[right].PURL
			}
			return out.Targets[i].Components[left].Version < out.Targets[i].Components[right].Version
		})
	}
	sort.Slice(out.Targets, func(i, j int) bool { return out.Targets[i].ID < out.Targets[j].ID })
	out.Pins = append([]ArtifactPin(nil), catalog.Pins...)
	sort.Slice(out.Pins, func(i, j int) bool {
		if out.Pins[i].Reference != out.Pins[j].Reference {
			return out.Pins[i].Reference < out.Pins[j].Reference
		}
		return out.Pins[i].Digest < out.Pins[j].Digest
	})
	return out
}

func canonicalOracle(oracle Oracle) Oracle {
	out := oracle
	out.Cases = append([]OracleCase(nil), oracle.Cases...)
	for i := range out.Cases {
		out.Cases[i].Aliases = sortedStrings(out.Cases[i].Aliases)
		out.Cases[i].LabelerIDs = sortedStrings(out.Cases[i].LabelerIDs)
		out.Cases[i].ReviewerIDs = sortedStrings(out.Cases[i].ReviewerIDs)
		out.Cases[i].Citations = append([]Citation(nil), out.Cases[i].Citations...)
		sort.Slice(out.Cases[i].Citations, func(left, right int) bool {
			if out.Cases[i].Citations[left].Reference != out.Cases[i].Citations[right].Reference {
				return out.Cases[i].Citations[left].Reference < out.Cases[i].Citations[right].Reference
			}
			return out.Cases[i].Citations[left].Digest < out.Cases[i].Citations[right].Digest
		})
	}
	sort.Slice(out.Cases, func(i, j int) bool { return out.Cases[i].ID < out.Cases[j].ID })
	return out
}

func canonicalObservations(observations []Observation) []Observation {
	out := append([]Observation(nil), observations...)
	for i := range out {
		out[i].Findings = canonicalFindings(out[i].Findings)
	}
	sort.Slice(out, func(i, j int) bool {
		return observationLess(out[i], out[j])
	})
	return out
}

func canonicalFindings(findings []Finding) []Finding {
	out := append([]Finding(nil), findings...)
	sort.Slice(out, func(left, right int) bool {
		leftKey, rightKey := canonicalFindingKey(out[left]), canonicalFindingKey(out[right])
		if leftKey != rightKey {
			return leftKey < rightKey
		}
		return tupleKey(
			out[left].AdvisoryID,
			out[left].Component.PURL,
			out[left].Component.Version,
		) < tupleKey(
			out[right].AdvisoryID,
			out[right].Component.PURL,
			out[right].Component.Version,
		)
	})
	return out
}

func observationLess(left, right Observation) bool {
	for _, pair := range [][2]string{
		{string(left.Engine), string(right.Engine)},
		{left.TargetID, right.TargetID},
		{left.CatalogRevision, right.CatalogRevision},
		{left.CatalogDigest, right.CatalogDigest},
		{left.TargetDigest, right.TargetDigest},
		{left.SBOMDigest, right.SBOMDigest},
		{left.EngineVersion, right.EngineVersion},
		{left.EngineBinaryDigest, right.EngineBinaryDigest},
		{left.DatabaseBuild, right.DatabaseBuild},
		{left.DatabaseDigest, right.DatabaseDigest},
		{left.EnvironmentID, right.EnvironmentID},
		{left.EnvironmentDigest, right.EnvironmentDigest},
		{string(left.State), string(right.State)},
		{left.RawOutputDigest, right.RawOutputDigest},
		{left.ConfigDigest, right.ConfigDigest},
		{string(left.CapabilityKind), string(right.CapabilityKind)},
		{left.CapabilityDigest, right.CapabilityDigest},
		{left.SchemaVersion, right.SchemaVersion},
	} {
		if pair[0] != pair[1] {
			return pair[0] < pair[1]
		}
	}
	for i := 0; i < len(left.Findings) && i < len(right.Findings); i++ {
		for _, pair := range [][2]string{
			{left.Findings[i].AdvisoryID, right.Findings[i].AdvisoryID},
			{left.Findings[i].Component.PURL, right.Findings[i].Component.PURL},
			{left.Findings[i].Component.Version, right.Findings[i].Component.Version},
		} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
	}
	return len(left.Findings) < len(right.Findings)
}

func runIdentityLess(left, right RunIdentity) bool {
	return runIdentityKey(left) < runIdentityKey(right)
}

func canonicalResult(result Result) Result {
	out := result
	out.Targets = append([]TargetIdentity(nil), result.Targets...)
	sort.Slice(out.Targets, func(i, j int) bool { return out.Targets[i].ID < out.Targets[j].ID })
	out.Runs = append([]RunIdentity(nil), result.Runs...)
	sort.Slice(out.Runs, func(i, j int) bool { return runIdentityLess(out.Runs[i], out.Runs[j]) })
	out.RunMetrics = append([]RunMetric(nil), result.RunMetrics...)
	sort.Slice(out.RunMetrics, func(i, j int) bool { return runIdentityLess(out.RunMetrics[i].Run, out.RunMetrics[j].Run) })
	out.Engines = append([]EngineResult(nil), result.Engines...)
	sortedEngines(out.Engines)
	out.Diagnostics = append([]Diagnostic(nil), result.Diagnostics...)
	sortDiagnostics(out.Diagnostics)
	out.Diagnostics = deduplicateDiagnostics(out.Diagnostics)
	if result.Gate != nil {
		gate := *result.Gate
		gate.Ratchet = canonicalRatchet(result.Gate.Ratchet)
		gate.Checks = append([]GateCheck(nil), result.Gate.Checks...)
		for i := range gate.Checks {
			gate.Checks[i].Mode = gate.Checks[i].Mode.canonical()
			if gate.Checks[i].Actual != nil {
				actual := *gate.Checks[i].Actual
				gate.Checks[i].Actual = &actual
			}
			gate.Checks[i].ReasonCodes = append([]GateReasonCode(nil), gate.Checks[i].ReasonCodes...)
			sort.Slice(gate.Checks[i].ReasonCodes, func(left, right int) bool {
				return gate.Checks[i].ReasonCodes[left] < gate.Checks[i].ReasonCodes[right]
			})
		}
		sort.Slice(gate.Checks, func(i, j int) bool {
			return expectedRunIdentityLess(gate.Checks[i].Expected, gate.Checks[j].Expected)
		})
		out.Gate = &gate
	}
	return out
}

func canonicalRatchet(ratchet Ratchet) Ratchet {
	out := ratchet
	out.Floors = make([]RatchetFloor, len(ratchet.Floors))
	for i, floor := range ratchet.Floors {
		out.Floors[i] = cloneRatchetFloor(floor)
		out.Floors[i].Mode = out.Floors[i].Mode.canonical()
	}
	sort.Slice(out.Floors, func(i, j int) bool {
		return expectedRunIdentityLess(out.Floors[i].Expected, out.Floors[j].Expected)
	})
	return out
}

func cloneRatchetFloor(floor RatchetFloor) RatchetFloor {
	out := floor
	out.MinimumCovered = cloneIntPointer(floor.MinimumCovered)
	out.MinimumAffectedRelations = cloneIntPointer(floor.MinimumAffectedRelations)
	out.MinimumNegativeRelations = cloneIntPointer(floor.MinimumNegativeRelations)
	out.MinimumPrecision = cloneFloatPointer(floor.MinimumPrecision)
	out.MinimumRecall = cloneFloatPointer(floor.MinimumRecall)
	out.MaximumFalsePositives = cloneIntPointer(floor.MaximumFalsePositives)
	out.MaximumFalseNegatives = cloneIntPointer(floor.MaximumFalseNegatives)
	out.MaximumUnknown = cloneIntPointer(floor.MaximumUnknown)
	out.MaximumIncomplete = cloneIntPointer(floor.MaximumIncomplete)
	out.MaximumUnsupported = cloneIntPointer(floor.MaximumUnsupported)
	return out
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneFloatPointer(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func componentKeyText(key ComponentBenchmarkKey) string {
	return tupleKey(key.Ecosystem, key.Package, key.Version)
}

func benchmarkKeyText(key ComponentBenchmarkKey) string {
	return tupleKey(key.Ecosystem, key.Package, key.Version, key.Advisory)
}

func canonicalFindingKey(finding Finding) string {
	key, err := BenchmarkKey(finding.Component, finding.AdvisoryID)
	if err == nil {
		return "valid:" + benchmarkKeyText(key)
	}
	return "invalid:" + tupleKey(finding.AdvisoryID, finding.Component.PURL, finding.Component.Version)
}

func tupleKey(values ...string) string {
	var key strings.Builder
	for _, value := range values {
		fmt.Fprintf(&key, "%d:%s", len(value), value)
	}
	return key.String()
}
