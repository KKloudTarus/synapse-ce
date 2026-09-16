package scabench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// MaxJSONBytes bounds each untrusted benchmark JSON document before decoding.
const MaxJSONBytes int64 = 8 << 20

const maxJSONDepth = 256

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

// DecodeSourceFreeze strictly decodes a fresh-cycle source freeze.
func DecodeSourceFreeze(reader io.Reader) (SourceFreeze, error) {
	var freeze SourceFreeze
	if err := strictDecode(reader, &freeze); err != nil {
		return SourceFreeze{}, fmt.Errorf("decode source freeze: %w", err)
	}
	if err := freeze.Validate(); err != nil {
		return SourceFreeze{}, err
	}
	return freeze, nil
}

// DecodeOracleCandidate strictly decodes scanner-free proposed oracle truth.
func DecodeOracleCandidate(reader io.Reader) (OracleCandidate, error) {
	var candidate OracleCandidate
	if err := strictDecode(reader, &candidate); err != nil {
		return OracleCandidate{}, fmt.Errorf("decode oracle candidate: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return OracleCandidate{}, err
	}
	return candidate, nil
}

// DecodeAutomatedCrossCheck strictly decodes an automated scanner-blinded cross-check.
func DecodeAutomatedCrossCheck(reader io.Reader) (AutomatedCrossCheck, error) {
	var check AutomatedCrossCheck
	if err := strictDecode(reader, &check); err != nil {
		return AutomatedCrossCheck{}, fmt.Errorf("decode automated cross-check: %w", err)
	}
	if err := check.Validate(); err != nil {
		return AutomatedCrossCheck{}, err
	}
	return check, nil
}

// DecodeAdjudicationRecord strictly decodes a scanner-free adjudication record.
func DecodeAdjudicationRecord(reader io.Reader) (AdjudicationRecord, error) {
	var record AdjudicationRecord
	if err := strictDecode(reader, &record); err != nil {
		return AdjudicationRecord{}, fmt.Errorf("decode adjudication record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return AdjudicationRecord{}, err
	}
	return record, nil
}

// DecodeAccountableReview strictly decodes the distinct publication decision.
func DecodeAccountableReview(reader io.Reader) (AccountableReview, error) {
	var review AccountableReview
	if err := strictDecode(reader, &review); err != nil {
		return AccountableReview{}, fmt.Errorf("decode accountable review: %w", err)
	}
	if err := review.Validate(); err != nil {
		return AccountableReview{}, err
	}
	return review, nil
}

// DecodeGitHubReviewCapture strictly decodes the sanitized GitHub-review form.
func DecodeGitHubReviewCapture(reader io.Reader) (GitHubReviewCapture, error) {
	var capture GitHubReviewCapture
	if err := strictDecode(reader, &capture); err != nil {
		return GitHubReviewCapture{}, fmt.Errorf("decode github review capture: %w", err)
	}
	if err := capture.Validate(); err != nil {
		return GitHubReviewCapture{}, err
	}
	return capture, nil
}

// DecodeGitHubReviewDispositionCapture strictly decodes the sanitized,
// immutable maintainer disposition comment.
func DecodeGitHubReviewDispositionCapture(reader io.Reader) (GitHubReviewDispositionCapture, error) {
	var capture GitHubReviewDispositionCapture
	if err := strictDecode(reader, &capture); err != nil {
		return GitHubReviewDispositionCapture{}, fmt.Errorf("decode github review disposition capture: %w", err)
	}
	if err := capture.Validate(); err != nil {
		return GitHubReviewDispositionCapture{}, err
	}
	return capture, nil
}

func DecodeFinalOracleFreeze(reader io.Reader) (FinalOracleFreeze, error) {
	var freeze FinalOracleFreeze
	if err := strictDecode(reader, &freeze); err != nil {
		return FinalOracleFreeze{}, fmt.Errorf("decode final oracle freeze: %w", err)
	}
	if err := freeze.Validate(); err != nil {
		return FinalOracleFreeze{}, err
	}
	return freeze, nil
}

func DecodeSourceCaseEvidence(reader io.Reader) (SourceCaseEvidenceSet, error) {
	var source SourceCaseEvidenceSet
	if err := strictDecode(reader, &source); err != nil {
		return SourceCaseEvidenceSet{}, fmt.Errorf("decode source case evidence: %w", err)
	}
	if err := source.Validate(); err != nil {
		return SourceCaseEvidenceSet{}, err
	}
	return source, nil
}

// DecodeSourceEvidencePlan decodes a strict, benchmark-only source selection plan.
func DecodeSourceEvidencePlan(reader io.Reader) (SourceEvidencePlan, error) {
	var plan SourceEvidencePlan
	if err := strictDecode(reader, &plan); err != nil {
		return SourceEvidencePlan{}, fmt.Errorf("decode source evidence plan: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return SourceEvidencePlan{}, err
	}
	return plan, nil
}

// DecodeNativeEvidenceSet decodes generated, target-native version evidence.
func DecodeNativeEvidenceSet(reader io.Reader) (NativeEvidenceSet, error) {
	var evidence NativeEvidenceSet
	if err := strictDecode(reader, &evidence); err != nil {
		return NativeEvidenceSet{}, fmt.Errorf("decode native evidence: %w", err)
	}
	if err := evidence.Validate(); err != nil {
		return NativeEvidenceSet{}, err
	}
	return evidence, nil
}

// DecodeCyclePlan strictly decodes a cycle plan before any capture can use it.
func DecodeCyclePlan(reader io.Reader) (CyclePlan, error) {
	var plan CyclePlan
	if err := strictDecode(reader, &plan); err != nil {
		return CyclePlan{}, fmt.Errorf("decode cycle plan: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return CyclePlan{}, err
	}
	return plan, nil
}

// DecodeCycleLedger strictly decodes retained capture attempt records.
func DecodeCycleLedger(reader io.Reader) (CycleLedger, error) {
	var ledger CycleLedger
	if err := strictDecode(reader, &ledger); err != nil {
		return CycleLedger{}, fmt.Errorf("decode cycle ledger: %w", err)
	}
	if err := ledger.validateBasic(); err != nil {
		return CycleLedger{}, err
	}
	return ledger, nil
}

// DecodeNativeComparisonRecord strictly decodes a target-native comparison record.
func DecodeNativeComparisonRecord(reader io.Reader) (NativeComparisonRecord, error) {
	var record NativeComparisonRecord
	if err := strictDecode(reader, &record); err != nil {
		return NativeComparisonRecord{}, fmt.Errorf("decode native comparison record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return NativeComparisonRecord{}, err
	}
	return record, nil
}

// DecodePublicationManifest strictly decodes the single publication manifest.
func DecodePublicationManifest(reader io.Reader) (PublicationManifest, error) {
	var manifest PublicationManifest
	if err := strictDecode(reader, &manifest); err != nil {
		return PublicationManifest{}, fmt.Errorf("decode publication manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return PublicationManifest{}, err
	}
	return manifest, nil
}

// DecodePublicationControl strictly decodes immutable pre-reduction artifact commitments.
func DecodePublicationControl(reader io.Reader) (PublicationControl, error) {
	var control PublicationControl
	if err := strictDecode(reader, &control); err != nil {
		return PublicationControl{}, fmt.Errorf("decode publication control: %w", err)
	}
	if err := control.Validate(); err != nil {
		return PublicationControl{}, err
	}
	return control, nil
}

// DecodeFalsifierSpec strictly decodes an executable falsifier specification.
func DecodeFalsifierSpec(reader io.Reader) (FalsifierSpec, error) {
	var spec FalsifierSpec
	if err := strictDecode(reader, &spec); err != nil {
		return FalsifierSpec{}, fmt.Errorf("decode falsifier spec: %w", err)
	}
	if err := spec.Validate(); err != nil {
		return FalsifierSpec{}, err
	}
	return spec, nil
}

// Validate validates an observation envelope's self-contained invariants.
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
	raw, err := readBounded(reader)
	if err != nil {
		return err
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON input is not valid UTF-8")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := rejectUnknownFields(value, reflect.TypeOf(destination)); err != nil {
		return err
	}

	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON shape: %w", err)
	}
	return nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxJSONBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JSON: %w", err)
	}
	if int64(len(raw)) > MaxJSONBytes {
		return nil, fmt.Errorf("JSON input exceeds %d byte limit", MaxJSONBytes)
	}
	return raw, nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON input must contain exactly one top-level value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
	return nil
}

func rejectUnknownFields(value any, destination reflect.Type) error {
	if destination.Kind() != reflect.Pointer {
		return fmt.Errorf("strict decoder destination must be a pointer")
	}
	return validateJSONShape(value, destination.Elem())
}

func validateJSONShape(value any, expected reflect.Type) error {
	for expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	switch expected.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil // json.Unmarshal supplies the more useful type error.
		}
		fields := jsonFields(expected)
		for key, nested := range object {
			field, exists := fields[key]
			if !exists {
				return fmt.Errorf("unknown JSON field %q", key)
			}
			if err := validateJSONShape(nested, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		values, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, nested := range values {
			if err := validateJSONShape(nested, expected.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for _, nested := range object {
			if err := validateJSONShape(nested, expected.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func jsonFields(expected reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, expected.NumField())
	for i := 0; i < expected.NumField(); i++ {
		field := expected.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}
