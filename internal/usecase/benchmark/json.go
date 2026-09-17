package benchmark

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// MaxJSONBytes bounds one untrusted benchmark JSON document before decoding or publication.
const MaxJSONBytes int64 = 8 << 20

const maxJSONDepth = 256

// SHA256Digest returns a lower-case immutable SHA-256 digest with its algorithm prefix.
func SHA256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalJSON encodes a value with encoding/json's deterministic struct and map ordering.
// Callers must canonicalize order-insensitive slices before calling it.
func CanonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// ValidateJSONDocument applies bounded, UTF-8, depth, duplicate-key, and single-value checks.
func ValidateJSONDocument(reader io.Reader) error {
	raw, err := readBounded(reader)
	if err != nil {
		return err
	}
	return validateJSONDocument(raw)
}

// StrictDecode validates one bounded JSON document, recursively rejects unknown object fields, and decodes it.
func StrictDecode(reader io.Reader, destination any) error {
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

// WriteCanonicalJSON writes one canonical JSON value followed by a newline within the document limit.
func WriteCanonicalJSON(writer io.Writer, encoded []byte) error {
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > MaxJSONBytes {
		return fmt.Errorf("JSON output exceeds %d byte limit", MaxJSONBytes)
	}
	if _, err := writer.Write(encoded); err != nil {
		return err
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

func validateJSONDocument(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON input is not valid UTF-8")
	}
	return rejectDuplicateKeys(raw)
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
