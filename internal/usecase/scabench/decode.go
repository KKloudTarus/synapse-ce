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

// ValidateJSONDocument applies the shared bounded, UTF-8, depth, duplicate-key,
// and single-value checks to a JSON document before a boundary-specific decode.
func ValidateJSONDocument(reader io.Reader) error {
	raw, err := readBounded(reader)
	if err != nil {
		return err
	}
	return validateJSONDocument(raw)
}

func validateJSONDocument(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON input is not valid UTF-8")
	}
	return rejectDuplicateKeys(raw)
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
	if err := validateJSONDocument(raw); err != nil {
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
