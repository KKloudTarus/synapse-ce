package jsresolve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const maxStrictJSONNestingDepth = 256

// validateNoDuplicateJSONKeys rejects JSON objects that repeat a member name.
// encoding/json otherwise accepts duplicates with last-value-wins semantics,
// which is unsafe for metadata used to establish an exact package identity.
func validateNoDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkStrictJSONValue(decoder, 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("read trailing JSON token: %w", err)
		}
		return fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	return nil
}

func walkStrictJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxStrictJSONNestingDepth {
		return fmt.Errorf("JSON nesting depth exceeds limit %d", maxStrictJSONNestingDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkStrictJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("expected JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := walkStrictJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("expected JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}
