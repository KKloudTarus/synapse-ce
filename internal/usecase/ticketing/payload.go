package ticketing

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ticketMarkerDescriptorValid keeps provider-selected marker locations small,
// deterministic and reversible. It is deliberately validated by the use case,
// not trusted merely because an adapter returned it.
func ticketMarkerDescriptorValid(d ports.TicketMarkerDescriptor) error {
	if d.Version != 1 || len(d.Path) == 0 || len(d.Path) > 8 {
		return shared.ErrValidation
	}
	switch d.Strategy {
	case ports.TicketMarkerJSONArray, ports.TicketMarkerTag, ports.TicketMarkerScalar, ports.TicketMarkerTextSuffix, ports.TicketMarkerJSONPatchAdd:
	default:
		return shared.ErrValidation
	}
	for _, part := range d.Path {
		if strings.TrimSpace(part) == "" || len(part) > 255 || !utf8.ValidString(part) || strings.ContainsRune(part, 0) || part == "_synapse" || strings.Contains(part, "/") {
			return shared.ErrValidation
		}
	}
	return nil
}

func addTicketMarker(wire json.RawMessage, d ports.TicketMarkerDescriptor, marker string) (json.RawMessage, error) {
	if err := ticketMarkerDescriptorValid(d); err != nil || !strings.HasPrefix(marker, "synapse-intent-") {
		return nil, shared.ErrValidation
	}
	if d.Strategy == ports.TicketMarkerJSONPatchAdd {
		var operations []json.RawMessage
		if json.Unmarshal(wire, &operations) != nil {
			return nil, shared.ErrValidation
		}
		operation, err := json.Marshal(map[string]any{"op": "add", "path": ticketJSONPointer(d.Path), "value": marker})
		if err != nil {
			return nil, shared.ErrValidation
		}
		operations = append(operations, operation)
		out, err := json.Marshal(operations)
		return out, err
	}
	root, parent, key, err := ticketWireTarget(wire, d.Path)
	if err != nil {
		return nil, err
	}
	switch d.Strategy {
	case ports.TicketMarkerJSONArray:
		values, ok := parent[key].([]any)
		if !ok {
			return nil, shared.ErrValidation
		}
		for _, value := range values {
			if text, ok := value.(string); !ok || text == marker {
				return nil, shared.ErrValidation
			}
		}
		parent[key] = append(values, marker)
	case ports.TicketMarkerTag:
		value, ok := parent[key].(string)
		if !ok || strings.Contains(value, "synapse-intent-") {
			return nil, shared.ErrValidation
		}
		parts := strings.Split(value, ",")
		for _, part := range parts {
			if strings.TrimSpace(part) == marker {
				return nil, shared.ErrValidation
			}
		}
		if value == "" {
			parent[key] = marker
		} else {
			parent[key] = value + "," + marker
		}
	case ports.TicketMarkerScalar:
		value, ok := parent[key].(string)
		if !ok || value != "" {
			return nil, shared.ErrValidation
		}
		parent[key] = marker
	case ports.TicketMarkerTextSuffix:
		value, ok := parent[key].(string)
		if !ok || strings.Contains(value, "synapse-intent-") {
			return nil, shared.ErrValidation
		}
		parent[key] = value + ticketMarkerSuffix(marker)
	}
	out, err := json.Marshal(root)
	return out, err
}

func removeTicketMarker(wire json.RawMessage, d ports.TicketMarkerDescriptor, marker string) (json.RawMessage, error) {
	if err := ticketMarkerDescriptorValid(d); err != nil {
		return nil, err
	}
	if d.Strategy == ports.TicketMarkerJSONPatchAdd {
		var operations []json.RawMessage
		if json.Unmarshal(wire, &operations) != nil {
			return nil, shared.ErrValidation
		}
		kept, matches := make([]json.RawMessage, 0, len(operations)), 0
		for _, raw := range operations {
			var operation struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value string `json:"value"`
			}
			if json.Unmarshal(raw, &operation) == nil && operation.Op == "add" && operation.Path == ticketJSONPointer(d.Path) && operation.Value == marker {
				matches++
				continue
			}
			kept = append(kept, raw)
		}
		if matches != 1 {
			return nil, shared.ErrValidation
		}
		out, err := json.Marshal(kept)
		return out, err
	}
	root, parent, key, err := ticketWireTarget(wire, d.Path)
	if err != nil {
		return nil, err
	}
	switch d.Strategy {
	case ports.TicketMarkerJSONArray:
		values, ok := parent[key].([]any)
		if !ok {
			return nil, shared.ErrValidation
		}
		kept, matches := make([]any, 0, len(values)), 0
		for _, value := range values {
			if text, ok := value.(string); ok && text == marker {
				matches++
				continue
			}
			kept = append(kept, value)
		}
		if matches != 1 {
			return nil, shared.ErrValidation
		}
		parent[key] = kept
	case ports.TicketMarkerTag:
		value, ok := parent[key].(string)
		if !ok {
			return nil, shared.ErrValidation
		}
		parts, kept, matches := strings.Split(value, ","), make([]string, 0), 0
		for _, part := range parts {
			if strings.TrimSpace(part) == marker {
				matches++
				continue
			}
			kept = append(kept, part)
		}
		if matches != 1 {
			return nil, shared.ErrValidation
		}
		parent[key] = strings.Join(kept, ",")
	case ports.TicketMarkerScalar:
		value, ok := parent[key].(string)
		if !ok || value != marker {
			return nil, shared.ErrValidation
		}
		parent[key] = ""
	case ports.TicketMarkerTextSuffix:
		value, ok := parent[key].(string)
		suffix := ticketMarkerSuffix(marker)
		if !ok || strings.Count(value, suffix) != 1 || !strings.HasSuffix(value, suffix) {
			return nil, shared.ErrValidation
		}
		parent[key] = strings.TrimSuffix(value, suffix)
	}
	out, err := json.Marshal(root)
	return out, err
}

func ticketWireTarget(wire json.RawMessage, path []string) (map[string]any, map[string]any, string, error) {
	var root map[string]any
	if json.Unmarshal(wire, &root) != nil {
		return nil, nil, "", shared.ErrValidation
	}
	current := root
	for index, part := range path {
		if index == len(path)-1 {
			value, ok := current[part]
			if !ok {
				return nil, nil, "", shared.ErrValidation
			}
			switch value.(type) {
			case string, []any:
				return root, current, part, nil
			default:
				return nil, nil, "", shared.ErrValidation
			}
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			return nil, nil, "", shared.ErrValidation
		}
		current = next
	}
	return nil, nil, "", shared.ErrValidation
}

func ticketMarkerSuffix(marker string) string { return "\n\n[" + marker + "]" }
func ticketJSONPointer(path []string) string {
	escaped := make([]string, len(path))
	for index, part := range path {
		escaped[index] = strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	}
	return "/" + strings.Join(escaped, "/")
}

// ticketPayloadInputFields serializes only already-filtered values for an
// adapter. It cannot observe raw findings or unredacted mapping literals.
func ticketPayloadInputFields(fields map[string]any) (map[string]json.RawMessage, error) {
	out := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("%w: ticket field cannot be encoded", shared.ErrValidation)
		}
		out[key] = raw
	}
	return out, nil
}
