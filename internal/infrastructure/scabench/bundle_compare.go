package scabench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const semanticBundleComparisonSchema = "synapse-sca-benchmark-full-bundle-comparison-v1"

type BundleFileIdentity struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// BundleIdentity is derived from an existing validated bundle; no additional
// artifact is written into the raw capture directory.
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

type AllowedBundleDifference struct {
	Artifact    string `json:"artifact"`
	Path        string `json:"path"`
	LeftDigest  string `json:"left_digest"`
	RightDigest string `json:"right_digest"`
}

// SemanticBundleComparison retains the two raw roots regardless of whether
// semantic comparison passes. Any unclassified difference makes comparison
// fail; callers can retain this report with the protected raw bundles.
type SemanticBundleComparison struct {
	SchemaVersion           string                    `json:"schema_version"`
	Engine                  bench.Engine              `json:"engine"`
	Policy                  string                    `json:"policy"`
	Left                    BundleIdentity            `json:"left"`
	Right                   BundleIdentity            `json:"right"`
	AllowedDifferences      []AllowedBundleDifference `json:"allowed_differences"`
	UnclassifiedDifferences []string                  `json:"unclassified_differences,omitempty"`
	SemanticEqual           bool                      `json:"semantic_equal"`
}

type semanticBundlePolicy struct {
	engine bench.Engine
	name   string
}

func policyForEngine(engine bench.Engine) (semanticBundlePolicy, error) {
	switch engine {
	case bench.EngineOwned:
		return semanticBundlePolicy{engine: engine, name: "owned-exact-v1"}, nil
	case bench.EngineGrype:
		return semanticBundlePolicy{engine: engine, name: "grype-descriptor-timestamp-v1"}, nil
	case bench.EngineTrivy:
		return semanticBundlePolicy{engine: engine, name: "trivy-top-level-and-direct-fingerprint-v1"}, nil
	case bench.EngineOSVScanner:
		return semanticBundlePolicy{engine: engine, name: "osv-pointer-and-terminal-timing-v1"}, nil
	default:
		return semanticBundlePolicy{}, fmt.Errorf("unsupported semantic bundle engine %q", engine)
	}
}

// CompareBundles validates each full bundle before comparing it. Its policy is
// explicitly selected per engine, preserves both raw roots, and fails closed on
// every difference outside that narrow policy.
func CompareBundles(leftPath, rightPath string, engine bench.Engine) (SemanticBundleComparison, error) {
	policy, err := policyForEngine(engine)
	if err != nil {
		return SemanticBundleComparison{}, err
	}
	left, leftObservation, leftEvidence, err := inspectBundleIdentity(leftPath)
	if err != nil {
		return SemanticBundleComparison{}, fmt.Errorf("validate left bundle: %w", err)
	}
	right, rightObservation, rightEvidence, err := inspectBundleIdentity(rightPath)
	if err != nil {
		return SemanticBundleComparison{}, fmt.Errorf("validate right bundle: %w", err)
	}
	report := SemanticBundleComparison{
		SchemaVersion: semanticBundleComparisonSchema,
		Engine:        engine,
		Policy:        policy.name,
		Left:          left,
		Right:         right,
	}
	if leftObservation.Engine != engine || rightObservation.Engine != engine {
		report.UnclassifiedDifferences = append(report.UnclassifiedDifferences, "bundle observation engine does not match selected policy")
		return report, fmt.Errorf("semantic bundle comparison: %s", report.UnclassifiedDifferences[0])
	}
	if difference := compareNormalizedObservation(leftObservation, rightObservation); difference != "" {
		report.UnclassifiedDifferences = append(report.UnclassifiedDifferences, difference)
	}
	allowed, differences := compareEvidenceForPolicy(policy, leftEvidence, rightEvidence)
	report.AllowedDifferences = append(report.AllowedDifferences, allowed...)
	report.UnclassifiedDifferences = append(report.UnclassifiedDifferences, differences...)
	leftFiles, err := bundleFileMap(leftPath)
	if err != nil {
		return report, err
	}
	rightFiles, err := bundleFileMap(rightPath)
	if err != nil {
		return report, err
	}
	for _, name := range sortedBundleFileNames(leftFiles) {
		if name == "observation.json" || name == "evidence.json" {
			continue
		}
		if !bytes.Equal(leftFiles[name], rightFiles[name]) {
			report.UnclassifiedDifferences = append(report.UnclassifiedDifferences, "unexpected raw bundle artifact difference: "+name)
		}
	}
	sort.Slice(report.AllowedDifferences, func(left, right int) bool {
		if report.AllowedDifferences[left].Artifact != report.AllowedDifferences[right].Artifact {
			return report.AllowedDifferences[left].Artifact < report.AllowedDifferences[right].Artifact
		}
		return report.AllowedDifferences[left].Path < report.AllowedDifferences[right].Path
	})
	sort.Strings(report.UnclassifiedDifferences)
	report.SemanticEqual = len(report.UnclassifiedDifferences) == 0
	if !report.SemanticEqual {
		return report, fmt.Errorf("semantic bundle comparison rejected unclassified differences: %s", strings.Join(report.UnclassifiedDifferences, "; "))
	}
	return report, nil
}

// BundleIdentityFromPath exposes full raw evidence identities for the cycle
// ledger and publication manifest after validating the existing capture bundle.
func BundleIdentityFromPath(path string) (BundleIdentity, error) {
	identity, _, _, err := inspectBundleIdentity(path)
	return identity, err
}

// CycleEvidenceIdentityFromBundle extends a derived existing-bundle identity
// with the digest of its target-native comparison record for ledger and
// publication use. It does not modify the retained capture bundle.
func CycleEvidenceIdentityFromBundle(identity BundleIdentity, native bench.NativeTargetEvidence) (bench.BundleEvidenceIdentity, error) {
	if identity.TargetID == "" || identity.Engine == "" || identity.ManifestDigest == "" || identity.RootDigest == "" || identity.NormalizedObservationDigest == "" || identity.RawOutputDigest == "" || identity.ProcessEvidenceDigest == "" || identity.EnvironmentDigest == "" || identity.SBOMDigest == "" {
		return bench.BundleEvidenceIdentity{}, fmt.Errorf("derived bundle identity is incomplete")
	}
	if err := native.Validate(); err != nil {
		return bench.BundleEvidenceIdentity{}, err
	}
	if native.TargetID != identity.TargetID {
		return bench.BundleEvidenceIdentity{}, fmt.Errorf("native target evidence does not match bundle identity")
	}
	nativeDigest, err := bench.DigestNativeTargetEvidence(native)
	if err != nil {
		return bench.BundleEvidenceIdentity{}, err
	}
	result := bench.BundleEvidenceIdentity{
		TargetID:                    identity.TargetID,
		Engine:                      identity.Engine,
		BundleManifestDigest:        identity.ManifestDigest,
		BundleRootDigest:            identity.RootDigest,
		RawStdoutDigest:             identity.RawStdoutDigest,
		RawStderrDigest:             identity.RawStderrDigest,
		RawOutputDigest:             identity.RawOutputDigest,
		NormalizedObservationDigest: identity.NormalizedObservationDigest,
		SBOMDigest:                  identity.SBOMDigest,
		NativeComparisonDigest:      nativeDigest,
		ProcessEvidenceDigest:       identity.ProcessEvidenceDigest,
		EnvironmentDigest:           identity.EnvironmentDigest,
	}
	if err := result.Validate(); err != nil {
		return bench.BundleEvidenceIdentity{}, err
	}
	return result, nil
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
		TargetID:                    observation.TargetID,
		Engine:                      observation.Engine,
		ManifestDigest:              bench.SHA256Digest(manifestJSON),
		RootDigest:                  bench.SHA256Digest(rootMaterial),
		Files:                       manifest,
		NormalizedObservationDigest: bench.SHA256Digest(files["observation.json"]),
		RawOutputDigest:             observation.RawOutputDigest,
		ProcessEvidenceDigest:       bench.SHA256Digest(processEvidence),
		EnvironmentDigest:           observation.EnvironmentDigest,
		SBOMDigest:                  observation.SBOMDigest,
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
		data, err := readBundleArtifact(path, entry.Name())
		if err != nil {
			return nil, err
		}
		files[entry.Name()] = data
	}
	return files, nil
}

func sortedBundleFileNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func compareNormalizedObservation(left, right bench.Observation) string {
	left.RawOutputDigest = "<raw-output-varies>"
	right.RawOutputDigest = "<raw-output-varies>"
	if reflect.DeepEqual(left, right) {
		return ""
	}
	return "observation differs outside raw_output_digest"
}

func compareEvidenceForPolicy(policy semanticBundlePolicy, left, right Evidence) ([]AllowedBundleDifference, []string) {
	leftStable := cloneEvidence(left)
	rightStable := cloneEvidence(right)
	var leftStdout, leftStderr, rightStdout, rightStderr []byte
	if leftStable.Scan != nil {
		leftStdout, leftStderr = append([]byte(nil), leftStable.Scan.Stdout...), append([]byte(nil), leftStable.Scan.Stderr...)
		leftStable.Scan.Stdout = nil
		leftStable.Scan.Stderr = nil
	}
	if rightStable.Scan != nil {
		rightStdout, rightStderr = append([]byte(nil), rightStable.Scan.Stdout...), append([]byte(nil), rightStable.Scan.Stderr...)
		rightStable.Scan.Stdout = nil
		rightStable.Scan.Stderr = nil
	}
	if !reflect.DeepEqual(leftStable, rightStable) {
		return nil, []string{"evidence differs outside scan raw output"}
	}
	if left.Scan == nil || right.Scan == nil {
		if bytes.Equal(leftStdout, rightStdout) && bytes.Equal(leftStderr, rightStderr) {
			return nil, nil
		}
		return nil, []string{"scan raw output differs without a process record"}
	}
	switch policy.engine {
	case bench.EngineOwned:
		return compareExactRaw(leftStdout, rightStdout, leftStderr, rightStderr)
	case bench.EngineGrype:
		allowed, differences := compareGrypeRaw(leftStdout, rightStdout)
		if !bytes.Equal(leftStderr, rightStderr) {
			differences = append(differences, "grype scan stderr differs")
		}
		return allowed, differences
	case bench.EngineTrivy:
		allowed, differences := compareTrivyRaw(leftStdout, rightStdout)
		if !bytes.Equal(leftStderr, rightStderr) {
			differences = append(differences, "trivy scan stderr differs")
		}
		return allowed, differences
	case bench.EngineOSVScanner:
		allowed, differences := compareOSVRaw(leftStderr, rightStderr)
		if !bytes.Equal(leftStdout, rightStdout) {
			differences = append(differences, "OSV scan stdout differs")
		}
		return allowed, differences
	default:
		return nil, []string{"unknown semantic bundle policy"}
	}
}

func compareExactRaw(leftStdout, rightStdout, leftStderr, rightStderr []byte) ([]AllowedBundleDifference, []string) {
	var differences []string
	if !bytes.Equal(leftStdout, rightStdout) {
		differences = append(differences, "scan stdout differs")
	}
	if !bytes.Equal(leftStderr, rightStderr) {
		differences = append(differences, "scan stderr differs")
	}
	return nil, differences
}

func compareGrypeRaw(left, right []byte) ([]AllowedBundleDifference, []string) {
	if bytes.Equal(left, right) {
		return nil, nil
	}
	leftValue, err := strictJSONValue(left)
	if err != nil {
		return nil, []string{"grype left stdout is not strict JSON"}
	}
	rightValue, err := strictJSONValue(right)
	if err != nil {
		return nil, []string{"grype right stdout is not strict JSON"}
	}
	leftTimestamp, err := replaceOnlyGrypeTimestamp(leftValue)
	if err != nil {
		return nil, []string{"grype left stdout does not have a valid descriptor timestamp"}
	}
	rightTimestamp, err := replaceOnlyGrypeTimestamp(rightValue)
	if err != nil {
		return nil, []string{"grype right stdout does not have a valid descriptor timestamp"}
	}
	if !semanticJSONEqual(leftValue, rightValue) {
		return nil, []string{"grype stdout differs outside descriptor timestamp"}
	}
	if bytes.Equal(leftTimestamp, rightTimestamp) {
		return nil, []string{"grype raw stdout differs without a descriptor timestamp difference"}
	}
	return []AllowedBundleDifference{newAllowedDifference("evidence.json", "$.scan.stdout.$.descriptor.timestamp", leftTimestamp, rightTimestamp)}, nil
}

func replaceOnlyGrypeTimestamp(value any) ([]byte, error) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("root is not an object")
	}
	descriptor, ok := root["descriptor"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("descriptor is missing")
	}
	timestamp, ok := descriptor["timestamp"].(string)
	if !ok || timestamp == "" {
		return nil, fmt.Errorf("timestamp is missing")
	}
	descriptor["timestamp"] = "<volatile-descriptor-timestamp>"
	return []byte(timestamp), nil
}

func compareTrivyRaw(left, right []byte) ([]AllowedBundleDifference, []string) {
	if bytes.Equal(left, right) {
		return nil, nil
	}
	leftValue, err := strictJSONValue(left)
	if err != nil {
		return nil, []string{"trivy left stdout is not strict JSON"}
	}
	rightValue, err := strictJSONValue(right)
	if err != nil {
		return nil, []string{"trivy right stdout is not strict JSON"}
	}
	leftChanges, err := replaceOnlyTrivyVolatileValues(leftValue)
	if err != nil {
		return nil, []string{"trivy left stdout violates the narrow policy"}
	}
	rightChanges, err := replaceOnlyTrivyVolatileValues(rightValue)
	if err != nil {
		return nil, []string{"trivy right stdout violates the narrow policy"}
	}
	if !semanticJSONEqual(leftValue, rightValue) {
		return nil, []string{"trivy stdout differs outside top-level values and direct fingerprints"}
	}
	return compareNamedAllowedChanges("evidence.json", "$.scan.stdout", leftChanges, rightChanges)
}

type rawJSONChange struct {
	path  string
	value []byte
}

func replaceOnlyTrivyVolatileValues(value any) ([]rawJSONChange, error) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("root is not an object")
	}
	changes := make([]rawJSONChange, 0)
	for _, key := range []string{"CreatedAt", "ReportID"} {
		raw, ok := root[key].(string)
		if !ok || raw == "" {
			return nil, fmt.Errorf("top-level %s is missing", key)
		}
		changes = append(changes, rawJSONChange{path: "$." + key, value: []byte(raw)})
		root[key] = "<volatile-" + key + ">"
	}
	results, ok := root["Results"].([]any)
	if !ok {
		return nil, fmt.Errorf("top-level Results is missing")
	}
	for resultIndex, resultValue := range results {
		result, ok := resultValue.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("result is not an object")
		}
		vulnerabilities, ok := result["Vulnerabilities"].([]any)
		if !ok {
			return nil, fmt.Errorf("result Vulnerabilities is missing")
		}
		for vulnerabilityIndex, vulnerabilityValue := range vulnerabilities {
			vulnerability, ok := vulnerabilityValue.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("vulnerability is not an object")
			}
			fingerprint, ok := vulnerability["Fingerprint"].(string)
			if !ok || fingerprint == "" {
				return nil, fmt.Errorf("direct fingerprint is missing or malformed")
			}
			path := fmt.Sprintf("$.Results[%d].Vulnerabilities[%d].Fingerprint", resultIndex, vulnerabilityIndex)
			changes = append(changes, rawJSONChange{path: path, value: []byte(fingerprint)})
			vulnerability["Fingerprint"] = "<volatile-direct-fingerprint>"
		}
	}
	return changes, nil
}

var osvTimingLine = regexp.MustCompile(`^End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, ([1-9][0-9]*(?:\.[0-9]+)?)ms elapsed, ([1-9][0-9]*(?:\.[0-9]+)?)ms wall time$`)

func compareOSVRaw(left, right []byte) ([]AllowedBundleDifference, []string) {
	if bytes.Equal(left, right) {
		return nil, nil
	}
	leftLines, leftChanges, err := normalizeOSVStderr(left)
	if err != nil {
		return nil, []string{"OSV left stderr violates the narrow policy"}
	}
	rightLines, rightChanges, err := normalizeOSVStderr(right)
	if err != nil {
		return nil, []string{"OSV right stderr violates the narrow policy"}
	}
	if !reflect.DeepEqual(leftLines, rightLines) {
		return nil, []string{"OSV stderr differs outside pointer metadata and terminal timing"}
	}
	return compareNamedAllowedChanges("evidence.json", "$.scan.stderr", leftChanges, rightChanges)
}

func normalizeOSVStderr(raw []byte) ([]string, []rawJSONChange, error) {
	lines := strings.Split(string(raw), "\n")
	trailingNewline := len(lines) > 1 && lines[len(lines)-1] == ""
	last := len(lines) - 1
	if trailingNewline {
		last--
	}
	changes := make([]rawJSONChange, 0)
	for index, line := range lines {
		if index == last && osvTimingLine.MatchString(line) {
			changes = append(changes, rawJSONChange{path: fmt.Sprintf("lines[%d].timing", index), value: []byte(line)})
			lines[index] = "<terminal-timing>"
			continue
		}
		if strings.HasPrefix(line, "Neither CPE nor PURL found for package: {") {
			value, err := strictJSONValue([]byte(strings.TrimPrefix(line, "Neither CPE nor PURL found for package: ")))
			if err != nil {
				return nil, nil, err
			}
			object, ok := value.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("OSV pointer diagnostic is not an object")
			}
			for _, key := range []string{"ExternalReferences", "Hashes", "Properties", "SWID"} {
				if value, exists := object[key]; exists {
					if value == nil {
						return nil, nil, fmt.Errorf("OSV pointer diagnostic %s is nil", key)
					}
					encoded, err := json.Marshal(value)
					if err != nil {
						return nil, nil, err
					}
					changes = append(changes, rawJSONChange{path: fmt.Sprintf("lines[%d].%s", index, key), value: encoded})
					object[key] = "<volatile-pointer-field>"
				}
			}
			encoded, err := json.Marshal(object)
			if err != nil {
				return nil, nil, err
			}
			lines[index] = "Neither CPE nor PURL found for package: " + string(encoded)
		}
	}
	return lines, changes, nil
}

func compareNamedAllowedChanges(artifact, prefix string, left, right []rawJSONChange) ([]AllowedBundleDifference, []string) {
	leftByPath := make(map[string][]byte, len(left))
	rightByPath := make(map[string][]byte, len(right))
	for _, change := range left {
		leftByPath[change.path] = change.value
	}
	for _, change := range right {
		rightByPath[change.path] = change.value
	}
	if len(leftByPath) != len(rightByPath) {
		return nil, []string{"allowed volatile field set changed"}
	}
	var allowed []AllowedBundleDifference
	for path, leftValue := range leftByPath {
		rightValue, exists := rightByPath[path]
		if !exists {
			return nil, []string{"allowed volatile field set changed"}
		}
		if !bytes.Equal(leftValue, rightValue) {
			allowed = append(allowed, newAllowedDifference(artifact, prefix+"."+path, leftValue, rightValue))
		}
	}
	if len(allowed) == 0 {
		return nil, []string{"raw output differs without an allowed volatile value change"}
	}
	return allowed, nil
}

func newAllowedDifference(artifact, path string, left, right []byte) AllowedBundleDifference {
	return AllowedBundleDifference{Artifact: artifact, Path: path, LeftDigest: bench.SHA256Digest(left), RightDigest: bench.SHA256Digest(right)}
}

func semanticJSONEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func strictJSONValue(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := consumeStrictJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func consumeStrictJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("JSON object key is not a string")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate JSON key %q", key)
				}
				value, err := consumeStrictJSONValue(decoder)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("JSON object is not closed")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				value, err := consumeStrictJSONValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("JSON array is not closed")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", token)
		}
	default:
		return token, nil
	}
}
