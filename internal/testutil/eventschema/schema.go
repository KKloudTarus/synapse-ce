// Package eventschema validates the deliberately restricted Draft 2020-12 vocabulary
// published by notification contracts. Only schema tests import this helper.
package eventschema

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"time"
)

// The event schemas intentionally use a small, auditable JSON Schema 2020-12
// vocabulary. Reject unfamiliar keywords rather than silently ignoring them.
var contractKeywords = map[string]bool{
	"$schema": true, "$id": true, "title": true, "description": true,
	"type": true, "const": true, "enum": true, "format": true,
	"minLength": true, "minimum": true, "required": true,
	"properties": true, "additionalProperties": true,
}

func Check(node map[string]any) error {
	if node == nil {
		return fmt.Errorf("schema is not an object")
	}
	for key := range node {
		if !contractKeywords[key] {
			return fmt.Errorf("unsupported schema keyword %s", key)
		}
	}
	types, err := Types(node["type"])
	if err != nil {
		return err
	}
	if len(types) == 0 {
		return fmt.Errorf("schema has no type")
	}
	if v, ok := node["format"]; ok && v != "date-time" {
		return fmt.Errorf("unsupported schema format %v", v)
	}
	for _, field := range []string{"$schema", "$id", "title", "description"} {
		if raw, exists := node[field]; exists {
			if _, ok := raw.(string); !ok {
				return fmt.Errorf("%s must be a string", field)
			}
		}
	}
	if raw, exists := node["minLength"]; exists {
		n, ok := raw.(float64)
		if !ok || n < 0 || math.Trunc(n) != n {
			return fmt.Errorf("invalid minLength")
		}
	}
	if raw, exists := node["minimum"]; exists {
		if _, ok := raw.(float64); !ok {
			return fmt.Errorf("invalid minimum")
		}
	}
	properties := map[string]any{}
	if raw, exists := node["properties"]; exists {
		parsed, ok := raw.(map[string]any)
		properties = parsed
		if !ok {
			return fmt.Errorf("properties must be an object")
		}
	}
	if raw, exists := node["required"]; exists {
		required, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("required must be an array")
		}
		seen := map[string]bool{}
		for _, name := range required {
			field, ok := name.(string)
			if !ok || seen[field] {
				return fmt.Errorf("invalid required field %v", name)
			}
			seen[field] = true
			if _, ok := properties[field]; !ok {
				return fmt.Errorf("required field %s is undefined", field)
			}
		}
	}
	if v, ok := node["additionalProperties"]; ok {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("additionalProperties must be boolean")
		}
	}
	if v, ok := node["enum"]; ok {
		items, ok := v.([]any)
		if !ok || len(items) == 0 {
			return fmt.Errorf("invalid enum")
		}
		for i, item := range items {
			for _, previous := range items[:i] {
				if reflect.DeepEqual(item, previous) {
					return fmt.Errorf("duplicate enum value")
				}
			}
		}
	}
	for name, raw := range properties {
		child, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s property is not a schema", name)
		}
		if err := Check(child); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func Types(value any) ([]string, error) {
	var types []string
	switch value := value.(type) {
	case string:
		types = []string{value}
	case []any:
		for _, item := range value {
			name, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("non-string schema type")
			}
			types = append(types, name)
		}
	default:
		return nil, fmt.Errorf("missing or invalid schema type")
	}
	allowed := map[string]bool{"object": true, "array": true, "string": true, "integer": true, "number": true, "boolean": true, "null": true}
	seen := map[string]bool{}
	for _, name := range types {
		if !allowed[name] || seen[name] {
			return nil, fmt.Errorf("invalid or duplicate type %s", name)
		}
		seen[name] = true
	}
	return types, nil
}

func Match(node map[string]any, value any) error {
	types, err := Types(node["type"])
	if err != nil {
		return err
	}
	valid := false
	for _, name := range types {
		switch name {
		case "object":
			_, valid = value.(map[string]any)
		case "array":
			_, valid = value.([]any)
		case "string":
			_, valid = value.(string)
		case "number":
			_, valid = value.(float64)
		case "integer":
			n, ok := value.(float64)
			valid = ok && math.Trunc(n) == n
		case "boolean":
			_, valid = value.(bool)
		case "null":
			valid = value == nil
		}
		if valid {
			break
		}
	}
	if !valid {
		return fmt.Errorf("type mismatch: expected %v, got %T", types, value)
	}
	if expected, ok := node["const"]; ok && !reflect.DeepEqual(value, expected) {
		return fmt.Errorf("const mismatch")
	}
	if raw, ok := node["enum"]; ok {
		found := false
		for _, item := range raw.([]any) {
			if reflect.DeepEqual(value, item) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("enum mismatch")
		}
	}
	if text, ok := value.(string); ok {
		if n, ok := node["minLength"].(float64); ok && float64(len([]rune(text))) < n {
			return fmt.Errorf("string too short")
		}
		if node["format"] == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
				return fmt.Errorf("invalid date-time: %w", err)
			}
		}
	}
	if n, ok := value.(float64); ok {
		if floor, ok := node["minimum"].(float64); ok && n < floor {
			return fmt.Errorf("number below minimum")
		}
	}
	if object, ok := value.(map[string]any); ok {
		if required, ok := node["required"].([]any); ok {
			for _, field := range required {
				if _, exists := object[field.(string)]; !exists {
					return fmt.Errorf("missing %s", field)
				}
			}
		}
		properties, _ := node["properties"].(map[string]any)
		for key, childValue := range object {
			child, exists := properties[key]
			if !exists {
				if node["additionalProperties"] == false {
					return fmt.Errorf("unknown property %s", key)
				}
				continue
			}
			if err := Match(child.(map[string]any), childValue); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	return nil
}

func Decode(raw []byte) (map[string]any, error) {
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("JSON must be an object")
	}
	return result, nil
}
