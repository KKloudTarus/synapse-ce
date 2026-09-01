package findinglineage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	CanonicalizationVersionV1 = 1
	maxCanonicalDepth         = 8
	maxCanonicalEntries       = 256
	maxCanonicalKeyBytes      = 128
	maxCanonicalTextBytes     = 2048
	maxCanonicalBytes         = 32 * 1024
)

var (
	ErrIncompleteIdentity = errors.New("incomplete finding identity")
	ErrSensitiveInput     = errors.New("sensitive finding identity input")
)

type canonicalKind uint8

const (
	canonicalText canonicalKind = iota + 1
	canonicalInteger
	canonicalBoolean
	canonicalObject
	canonicalArray
	canonicalStringSet
)

type CanonicalValue struct {
	kind    canonicalKind
	text    string
	integer int64
	boolean bool
	object  map[string]CanonicalValue
	array   []CanonicalValue
	set     []string
}

func Text(value string) CanonicalValue {
	return CanonicalValue{kind: canonicalText, text: value}
}

func Integer(value int64) CanonicalValue {
	return CanonicalValue{kind: canonicalInteger, integer: value}
}

func Boolean(value bool) CanonicalValue {
	return CanonicalValue{kind: canonicalBoolean, boolean: value}
}

func Object(value map[string]CanonicalValue) CanonicalValue {
	return CanonicalValue{kind: canonicalObject, object: cloneCanonicalObject(value)}
}

func OrderedArray(value ...CanonicalValue) CanonicalValue {
	return CanonicalValue{kind: canonicalArray, array: append([]CanonicalValue(nil), value...)}
}

func StringSet(value ...string) CanonicalValue {
	return CanonicalValue{kind: canonicalStringSet, set: append([]string(nil), value...)}
}

type FingerprintCanonicalInputV1 struct {
	CanonicalizationVersion     int
	ProducerKind                string
	TargetIdentitySchemaVersion int
	TargetIdentityCanonical     string
	IdentityFields              map[string]CanonicalValue
}

type CanonicalFingerprint struct {
	Bytes          []byte
	IdentityFields []byte
	Fingerprint    string
}

func CanonicalizeFingerprintV1(input FingerprintCanonicalInputV1) (CanonicalFingerprint, error) {
	if input.CanonicalizationVersion != CanonicalizationVersionV1 {
		return CanonicalFingerprint{}, fmt.Errorf("%w: canonicalization version must be %d", ErrIncompleteIdentity, CanonicalizationVersionV1)
	}
	producer, err := canonicalRequiredText("producer_kind", input.ProducerKind, 128)
	if err != nil {
		return CanonicalFingerprint{}, err
	}
	if input.TargetIdentitySchemaVersion <= 0 {
		return CanonicalFingerprint{}, fmt.Errorf("%w: target identity schema version is required", ErrIncompleteIdentity)
	}
	target, err := canonicalRequiredText("target_identity_canonical", input.TargetIdentityCanonical, maxCanonicalTextBytes)
	if err != nil {
		return CanonicalFingerprint{}, err
	}
	if len(input.IdentityFields) == 0 {
		return CanonicalFingerprint{}, fmt.Errorf("%w: identity fields are required", ErrIncompleteIdentity)
	}

	fields := Object(input.IdentityFields)
	fieldsBytes, err := serializeCanonical(fields)
	if err != nil {
		return CanonicalFingerprint{}, err
	}
	payload := Object(map[string]CanonicalValue{
		"canonicalization_version":       Integer(CanonicalizationVersionV1),
		"identity_fields":                fields,
		"producer_kind":                  Text(producer),
		"target_identity_canonical":      Text(target),
		"target_identity_schema_version": Integer(int64(input.TargetIdentitySchemaVersion)),
	})
	canonical, err := serializeCanonical(payload)
	if err != nil {
		return CanonicalFingerprint{}, err
	}
	if len(canonical) > maxCanonicalBytes {
		return CanonicalFingerprint{}, fmt.Errorf("%w: canonical identity exceeds %d bytes", ErrIncompleteIdentity, maxCanonicalBytes)
	}
	digest := sha256.Sum256(append([]byte("synapse:finding-lineage:v1\x00"), canonical...))
	return CanonicalFingerprint{
		Bytes:          append([]byte(nil), canonical...),
		IdentityFields: append([]byte(nil), fieldsBytes...),
		Fingerprint:    hex.EncodeToString(digest[:]),
	}, nil
}

func HashAlias(producerKind, findingKind, targetCanonical string, schemaVersion int, value string) (string, error) {
	producer, err := canonicalRequiredText("producer_kind", producerKind, 128)
	if err != nil {
		return "", err
	}
	kind, err := canonicalRequiredText("finding_kind", findingKind, 128)
	if err != nil {
		return "", err
	}
	target, err := canonicalRequiredText("target_identity_canonical", targetCanonical, maxCanonicalTextBytes)
	if err != nil {
		return "", err
	}
	alias, err := canonicalRequiredText("alias", value, maxCanonicalTextBytes)
	if err != nil {
		return "", err
	}
	if schemaVersion <= 0 {
		return "", fmt.Errorf("%w: alias schema version is required", ErrIncompleteIdentity)
	}
	payload, err := serializeCanonical(Object(map[string]CanonicalValue{
		"alias":            Text(alias),
		"finding_kind":     Text(kind),
		"producer_kind":    Text(producer),
		"schema_version":   Integer(int64(schemaVersion)),
		"target_canonical": Text(target),
	}))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("synapse:finding-alias:v1\x00"), payload...))
	return hex.EncodeToString(digest[:]), nil
}

func serializeCanonical(value CanonicalValue) ([]byte, error) {
	var buffer bytes.Buffer
	if err := appendCanonical(&buffer, value, 0); err != nil {
		return nil, err
	}
	if buffer.Len() > maxCanonicalBytes {
		return nil, fmt.Errorf("%w: canonical value exceeds %d bytes", ErrIncompleteIdentity, maxCanonicalBytes)
	}
	return buffer.Bytes(), nil
}

func validateCanonicalIdentityFields(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maxCanonicalBytes {
		return fmt.Errorf("%w: canonical identity fields must contain 1-%d bytes", ErrIncompleteIdentity, maxCanonicalBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("%w: canonical identity fields are invalid JSON", ErrIncompleteIdentity)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: canonical identity fields contain trailing data", ErrIncompleteIdentity)
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: canonical identity fields must be an object", ErrIncompleteIdentity)
	}
	return validateCanonicalJSONValue(object, 0)
}

func validateCanonicalJSONValue(value any, depth int) error {
	if depth > maxCanonicalDepth {
		return fmt.Errorf("%w: canonical value exceeds maximum depth", ErrIncompleteIdentity)
	}
	switch typed := value.(type) {
	case string:
		_, err := canonicalRequiredText("identity value", typed, maxCanonicalTextBytes)
		return err
	case json.Number:
		if _, err := strconv.ParseInt(string(typed), 10, 64); err != nil {
			return fmt.Errorf("%w: canonical numbers must be signed 64-bit integers", ErrIncompleteIdentity)
		}
		return nil
	case bool:
		return nil
	case []any:
		if len(typed) == 0 || len(typed) > maxCanonicalEntries {
			return fmt.Errorf("%w: canonical array must contain 1-%d values", ErrIncompleteIdentity, maxCanonicalEntries)
		}
		for _, child := range typed {
			if err := validateCanonicalJSONValue(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if len(typed) == 0 || len(typed) > maxCanonicalEntries {
			return fmt.Errorf("%w: canonical object must contain 1-%d fields", ErrIncompleteIdentity, maxCanonicalEntries)
		}
		keys := make(map[string]struct{}, len(typed))
		for rawKey, child := range typed {
			key, err := canonicalKey(rawKey)
			if err != nil {
				return err
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("%w: canonical object has duplicate NFC key %q", ErrIncompleteIdentity, key)
			}
			keys[key] = struct{}{}
			if err := validateCanonicalJSONValue(child, depth+1); err != nil {
				return fmt.Errorf("canonical field %q: %w", key, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: canonical values cannot be null", ErrIncompleteIdentity)
	}
}

func appendCanonical(buffer *bytes.Buffer, value CanonicalValue, depth int) error {
	if depth > maxCanonicalDepth {
		return fmt.Errorf("%w: canonical value exceeds maximum depth", ErrIncompleteIdentity)
	}
	switch value.kind {
	case canonicalText:
		text, err := canonicalRequiredText("identity value", value.text, maxCanonicalTextBytes)
		if err != nil {
			return err
		}
		appendJSONString(buffer, text)
	case canonicalInteger:
		fmt.Fprintf(buffer, "%d", value.integer)
	case canonicalBoolean:
		if value.boolean {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case canonicalObject:
		if len(value.object) == 0 || len(value.object) > maxCanonicalEntries {
			return fmt.Errorf("%w: canonical object must contain 1-%d fields", ErrIncompleteIdentity, maxCanonicalEntries)
		}
		normalized := make(map[string]CanonicalValue, len(value.object))
		keys := make([]string, 0, len(value.object))
		for rawKey, child := range value.object {
			key, err := canonicalKey(rawKey)
			if err != nil {
				return err
			}
			if _, exists := normalized[key]; exists {
				return fmt.Errorf("%w: canonical object has duplicate NFC key %q", ErrIncompleteIdentity, key)
			}
			normalized[key] = child
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool { return utf16Less(keys[left], keys[right]) })
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			appendJSONString(buffer, key)
			buffer.WriteByte(':')
			if err := appendCanonical(buffer, normalized[key], depth+1); err != nil {
				return fmt.Errorf("canonical field %q: %w", key, err)
			}
		}
		buffer.WriteByte('}')
	case canonicalArray:
		if len(value.array) == 0 || len(value.array) > maxCanonicalEntries {
			return fmt.Errorf("%w: canonical array must contain 1-%d values", ErrIncompleteIdentity, maxCanonicalEntries)
		}
		buffer.WriteByte('[')
		for index, child := range value.array {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := appendCanonical(buffer, child, depth+1); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case canonicalStringSet:
		if len(value.set) == 0 || len(value.set) > maxCanonicalEntries {
			return fmt.Errorf("%w: canonical string set must contain 1-%d values", ErrIncompleteIdentity, maxCanonicalEntries)
		}
		unique := make(map[string]struct{}, len(value.set))
		values := make([]string, 0, len(value.set))
		for _, raw := range value.set {
			text, err := canonicalRequiredText("identity set value", raw, maxCanonicalTextBytes)
			if err != nil {
				return err
			}
			if _, exists := unique[text]; exists {
				continue
			}
			unique[text] = struct{}{}
			values = append(values, text)
		}
		sort.Slice(values, func(left, right int) bool { return utf16Less(values[left], values[right]) })
		buffer.WriteByte('[')
		for index, text := range values {
			if index > 0 {
				buffer.WriteByte(',')
			}
			appendJSONString(buffer, text)
		}
		buffer.WriteByte(']')
	default:
		return fmt.Errorf("%w: unsupported canonical value", ErrIncompleteIdentity)
	}
	return nil
}

func canonicalKey(value string) (string, error) {
	key, err := canonicalRequiredText("identity field name", value, maxCanonicalKeyBytes)
	if err != nil {
		return "", err
	}
	normalized := strings.Map(func(char rune) rune {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			return char
		}
		if char >= 'A' && char <= 'Z' {
			return char + ('a' - 'A')
		}
		return -1
	}, key)
	if sensitiveCanonicalKeys[normalized] {
		return "", fmt.Errorf("%w: field %q is not allowed", ErrSensitiveInput, key)
	}
	if timestampCanonicalKeys[normalized] {
		return "", fmt.Errorf("%w: timestamp field %q is not semantic identity", ErrIncompleteIdentity, key)
	}
	return key, nil
}

func canonicalRequiredText(field, value string, maxBytes int) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: %s must be valid UTF-8", ErrIncompleteIdentity, field)
	}
	value = norm.NFC.String(value)
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%w: %s is required", ErrIncompleteIdentity, field)
	}
	if len(value) > maxBytes {
		return "", fmt.Errorf("%w: %s exceeds %d bytes", ErrIncompleteIdentity, field, maxBytes)
	}
	return value, nil
}

func appendJSONString(buffer *bytes.Buffer, value string) {
	const hexDigits = "0123456789abcdef"
	buffer.WriteByte('"')
	for _, char := range value {
		switch char {
		case '"':
			buffer.WriteString(`\"`)
		case '\\':
			buffer.WriteString(`\\`)
		case '\b':
			buffer.WriteString(`\b`)
		case '\t':
			buffer.WriteString(`\t`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\f':
			buffer.WriteString(`\f`)
		case '\r':
			buffer.WriteString(`\r`)
		default:
			if char < 0x20 {
				buffer.WriteString(`\u00`)
				buffer.WriteByte(hexDigits[byte(char)>>4])
				buffer.WriteByte(hexDigits[byte(char)&0x0f])
			} else {
				buffer.WriteRune(char)
			}
		}
	}
	buffer.WriteByte('"')
}

func utf16Less(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for index := 0; index < limit; index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}

func cloneCanonicalObject(input map[string]CanonicalValue) map[string]CanonicalValue {
	if input == nil {
		return nil
	}
	output := make(map[string]CanonicalValue, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

var sensitiveCanonicalKeys = map[string]bool{
	"accesstoken": true, "apikey": true, "apitoken": true, "clientsecret": true,
	"credential": true, "credentials": true, "password": true, "passwd": true,
	"privatekey": true, "refreshtoken": true, "secret": true, "sessionkey": true, "token": true,
}

var timestampCanonicalKeys = map[string]bool{
	"createdat": true, "discoveredat": true, "firstseenat": true, "lastseenat": true,
	"observedat": true, "scannedat": true, "timestamp": true, "updatedat": true,
}
