package scabench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const semanticBundleComparisonSchema = "synapse-sca-benchmark-semantic-comparison-v2"

type BundleFileIdentity struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// BundleIdentity binds every retained raw artifact. It is provenance, not a repeat claim.
type BundleIdentity struct {
	TargetID                    string               `json:"target_id"`
	Engine                      bench.Engine         `json:"engine"`
	ManifestDigest              string               `json:"manifest_digest"`
	RootDigest                  string               `json:"root_digest"`
	Files                       []BundleFileIdentity `json:"files"`
	NormalizedObservationDigest string               `json:"normalized_observation_digest"`
	RawOutputDigest             string               `json:"raw_output_digest"`
	RawStdoutDigest             string               `json:"raw_stdout_digest,omitempty"`
	RawStderrDigest             string               `json:"raw_stderr_digest,omitempty"`
	ProcessEvidenceDigest       string               `json:"process_evidence_digest"`
	EnvironmentDigest           string               `json:"environment_digest"`
	SBOMDigest                  string               `json:"sbom_digest"`
}

type ProcessOutcome struct {
	ExitKnown           bool   `json:"exit_known"`
	ExitCode            int    `json:"exit_code"`
	RunnerError         bool   `json:"runner_error"`
	Cancelled           bool   `json:"cancelled"`
	TimedOut            bool   `json:"timed_out"`
	Truncated           bool   `json:"truncated"`
	ConnectEventCount   int    `json:"connect_event_count"`
	Redacted            bool   `json:"redacted"`
	ParsedEngineVersion string `json:"parsed_engine_version"`
}

// BundleClaim is the stable, claim-bearing subset of a validated bundle. Raw streams,
// timing, addresses, timestamps, and formatting remain in BundleIdentity only.
type BundleClaim struct {
	Observation    bench.Observation      `json:"observation"`
	ExpectedState  bench.ObservationState `json:"expected_state"`
	ParserStatus   ParserStatus           `json:"parser_status"`
	InputIntegrity InputIntegrityStatus   `json:"input_integrity"`
	FailureCode    FailureCode            `json:"failure_code"`
	VersionProbe   *ProcessOutcome        `json:"version_probe,omitempty"`
	Scan           *ProcessOutcome        `json:"scan,omitempty"`
}

type SemanticBundleComparison struct {
	SchemaVersion           string                 `json:"schema_version"`
	TargetID                string                 `json:"target_id"`
	Engine                  bench.Engine           `json:"engine"`
	ExpectedState           bench.ObservationState `json:"expected_state"`
	Left                    BundleIdentity         `json:"left"`
	Right                   BundleIdentity         `json:"right"`
	LeftClaim               BundleClaim            `json:"left_claim"`
	RightClaim              BundleClaim            `json:"right_claim"`
	SemanticEqual           bool                   `json:"semantic_equal"`
	UnclassifiedDifferences []string               `json:"unclassified_differences,omitempty"`
}

// CompareBundlesForCell validates and replays both bundles before projecting their
// benchmark claims. Comparisons are always bound to a target and engine.
func CompareBundlesForCell(leftPath, rightPath, targetID string, engine bench.Engine, expectedState bench.ObservationState) (SemanticBundleComparison, error) {
	left, leftObservation, leftEvidence, err := inspectBundleIdentity(leftPath)
	if err != nil {
		return SemanticBundleComparison{}, fmt.Errorf("validate left bundle: %w", err)
	}
	right, rightObservation, rightEvidence, err := inspectBundleIdentity(rightPath)
	if err != nil {
		return SemanticBundleComparison{}, fmt.Errorf("validate right bundle: %w", err)
	}
	report := SemanticBundleComparison{
		SchemaVersion: semanticBundleComparisonSchema, TargetID: targetID, Engine: engine,
		ExpectedState: expectedState, Left: left, Right: right,
		LeftClaim:  bundleClaim(leftObservation, leftEvidence, expectedState),
		RightClaim: bundleClaim(rightObservation, rightEvidence, expectedState),
	}
	for _, observation := range []bench.Observation{leftObservation, rightObservation} {
		if observation.TargetID != targetID || observation.Engine != engine {
			report.UnclassifiedDifferences = append(report.UnclassifiedDifferences, "bundle does not match the selected target and engine")
		}
		if observation.State != expectedState {
			report.UnclassifiedDifferences = append(report.UnclassifiedDifferences, "bundle state does not match the planned state")
		}
	}
	leftClaim, err := bench.CanonicalJSON(report.LeftClaim)
	if err != nil {
		return SemanticBundleComparison{}, fmt.Errorf("encode left claim: %w", err)
	}
	rightClaim, err := bench.CanonicalJSON(report.RightClaim)
	if err != nil {
		return SemanticBundleComparison{}, fmt.Errorf("encode right claim: %w", err)
	}
	if !bytes.Equal(leftClaim, rightClaim) {
		report.UnclassifiedDifferences = append(report.UnclassifiedDifferences, "claim-bearing bundle projection differs")
	}
	sort.Strings(report.UnclassifiedDifferences)
	report.UnclassifiedDifferences = deduplicateStrings(report.UnclassifiedDifferences)
	report.SemanticEqual = len(report.UnclassifiedDifferences) == 0
	if !report.SemanticEqual {
		return report, fmt.Errorf("semantic bundle comparison rejected: %s", report.UnclassifiedDifferences[0])
	}
	return report, nil
}

func BundleIdentityFromPath(path string) (BundleIdentity, error) {
	identity, _, _, err := inspectBundleIdentity(path)
	return identity, err
}

func bundleClaim(observation bench.Observation, evidence Evidence, expectedState bench.ObservationState) BundleClaim {
	observation.RawOutputDigest = ""
	return BundleClaim{
		Observation: observation, ExpectedState: expectedState, ParserStatus: evidence.ParserStatus,
		InputIntegrity: evidence.InputIntegrity, FailureCode: evidence.FailureCode,
		VersionProbe: processOutcome(evidence.VersionProbe), Scan: processOutcome(evidence.Scan),
	}
}

func processOutcome(evidence *ProcessEvidence) *ProcessOutcome {
	if evidence == nil {
		return nil
	}
	return &ProcessOutcome{
		ExitKnown: evidence.ExitKnown, ExitCode: evidence.ExitCode, RunnerError: evidence.RunnerError,
		Cancelled: evidence.Cancelled, TimedOut: evidence.TimedOut, Truncated: evidence.Truncated,
		ConnectEventCount: evidence.ConnectEventCount, Redacted: evidence.Redacted,
		ParsedEngineVersion: evidence.ParsedEngineVersion,
	}
}

func inspectBundleIdentity(path string) (BundleIdentity, bench.Observation, Evidence, error) {
	if err := ValidateBundle(path); err != nil {
		return BundleIdentity{}, bench.Observation{}, Evidence{}, err
	}
	files, err := bundleFileMap(path)
	if err != nil {
		return BundleIdentity{}, bench.Observation{}, Evidence{}, err
	}
	observationSet, err := bench.DecodeObservationSet(bytes.NewReader(files["observation.json"]))
	if err != nil || len(observationSet.Observations) != 1 {
		return BundleIdentity{}, bench.Observation{}, Evidence{}, fmt.Errorf("decode validated observation bundle")
	}
	var evidence Evidence
	if err := json.Unmarshal(files["evidence.json"], &evidence); err != nil {
		return BundleIdentity{}, bench.Observation{}, Evidence{}, fmt.Errorf("decode validated evidence bundle: %w", err)
	}
	manifest := make([]BundleFileIdentity, 0, len(files))
	for name, data := range files {
		manifest = append(manifest, BundleFileIdentity{Name: name, Digest: bench.SHA256Digest(data), Size: int64(len(data))})
	}
	sort.Slice(manifest, func(left, right int) bool { return manifest[left].Name < manifest[right].Name })
	manifestJSON, err := bench.CanonicalJSON(manifest)
	if err != nil {
		return BundleIdentity{}, bench.Observation{}, Evidence{}, err
	}
	rootMaterial := make([]byte, 0, len(manifest)*80)
	for _, item := range manifest {
		rootMaterial = append(rootMaterial, item.Name...)
		rootMaterial = append(rootMaterial, 0)
		rootMaterial = append(rootMaterial, item.Digest...)
		rootMaterial = append(rootMaterial, 0)
	}
	observation := observationSet.Observations[0]
	processEvidence, err := bench.CanonicalJSON(evidence)
	if err != nil {
		return BundleIdentity{}, bench.Observation{}, Evidence{}, err
	}
	identity := BundleIdentity{
		TargetID: observation.TargetID, Engine: observation.Engine,
		ManifestDigest: bench.SHA256Digest(manifestJSON), RootDigest: bench.SHA256Digest(rootMaterial),
		Files: manifest, NormalizedObservationDigest: bench.SHA256Digest(files["observation.json"]),
		RawOutputDigest: observation.RawOutputDigest, ProcessEvidenceDigest: bench.SHA256Digest(processEvidence),
		EnvironmentDigest: observation.EnvironmentDigest, SBOMDigest: observation.SBOMDigest,
	}
	if evidence.Scan != nil {
		identity.RawStdoutDigest = bench.SHA256Digest(evidence.Scan.Stdout)
		identity.RawStderrDigest = bench.SHA256Digest(evidence.Scan.Stderr)
	}
	return identity, observation, evidence, nil
}

func bundleFileMap(path string) (map[string][]byte, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle directory: %w", err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("bundle contains a non-regular artifact")
		}
		data, readErr := os.ReadFile(filepath.Join(path, entry.Name()))
		if readErr != nil {
			return nil, fmt.Errorf("read bundle artifact: %w", readErr)
		}
		files[entry.Name()] = data
	}
	return files, nil
}

func deduplicateStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
