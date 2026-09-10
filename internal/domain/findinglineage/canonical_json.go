package findinglineage

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// MarshalJSON preserves the canonical value when native producer inputs are
// retained. The unexported representation must never silently encode as {}.
func (value CanonicalValue) MarshalJSON() ([]byte, error) { return serializeCanonical(value) }

func (value *CanonicalValue) UnmarshalJSON(data []byte) error {
	if len(data) > maxCanonicalBytes {
		return fmt.Errorf("%w: canonical value too large", ErrIncompleteIdentity)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := validateCanonicalJSONValue(decoded, 0); err != nil {
		return err
	}
	*value = canonicalFromJSON(decoded)
	return nil
}

func canonicalFromJSON(value any) CanonicalValue {
	switch typed := value.(type) {
	case string:
		return Text(typed)
	case bool:
		return Boolean(typed)
	case json.Number:
		n, _ := typed.Int64()
		return Integer(n) // checked by validation
	case []any:
		items := make([]CanonicalValue, len(typed))
		for index, child := range typed {
			items[index] = canonicalFromJSON(child)
		}
		return OrderedArray(items...)
	case map[string]any:
		fields := make(map[string]CanonicalValue, len(typed))
		for key, child := range typed {
			fields[key] = canonicalFromJSON(child)
		}
		return Object(fields)
	default:
		return CanonicalValue{} // unreachable after validation
	}
}
