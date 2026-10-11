package notification

import "github.com/KKloudTarus/synapse-ce/internal/testutil/eventschema"

func checkEventSchema(s map[string]any) error { return eventschema.Check(s) }
func schemaTypes(s any) ([]string, error) { return eventschema.Types(s) }
func matchEventSchema(s map[string]any, v any) error { return eventschema.Match(s, v) }
func decodeEventJSON(raw []byte) (map[string]any, error) { return eventschema.Decode(raw) }
