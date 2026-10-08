// Package ocsf validates exported findings against vendored OCSF schemas.
package ocsf

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

//go:embed schemas/*.json
var documents embed.FS

var _ ports.SIEMOCSFValidator = (*Validator)(nil)

// Validator holds immutable compiled schemas and can be shared between ticks.
type Validator struct{ classes map[int]*jsonschema.Schema }

type offlineLoader struct{}

func (offlineLoader) Load(string) (any, error) {
	return nil, fmt.Errorf("OCSF schema references must be vendored")
}

// New compiles all exported classes without network access. The upstream
// unfiltered documents include required cloud/osint profile fields. Neither
// profile is emitted by this mapper, so their conditional requirements are
// removed from the base finding classes; every nested schema stays intact.
func New() (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(offlineLoader{})
	v := &Validator{classes: make(map[int]*jsonschema.Schema)}
	for _, class := range []struct {
		uid  int
		name string
	}{{2002, "vulnerability_finding"}, {2004, "detection_finding"}, {2005, "incident_finding"}} {
		body, err := documents.ReadFile("schemas/" + class.name + ".json")
		if err != nil {
			return nil, fmt.Errorf("read OCSF schema: %w", err)
		}
		var schema map[string]any
		if err := json.Unmarshal(body, &schema); err != nil {
			return nil, fmt.Errorf("decode OCSF schema: %w", err)
		}
		if class.uid != 2005 {
			var required []any
			for _, field := range schema["required"].([]any) {
				if field != "cloud" && field != "osint" {
					required = append(required, field)
				}
			}
			schema["required"] = required
		}
		location := schema["$id"].(string)
		if err := compiler.AddResource(location, schema); err != nil {
			return nil, fmt.Errorf("register OCSF schema: %w", err)
		}
		compiled, err := compiler.Compile(location)
		if err != nil {
			return nil, fmt.Errorf("compile OCSF schema: %w", err)
		}
		v.classes[class.uid] = compiled
	}
	return v, nil
}

// Validate checks the complete JSON document, including referenced objects,
// arrays, enums, unknown fields and OCSF object constraints. Errors never carry
// source values; callers store only the schema_validation reason.
func (v *Validator) Validate(body []byte) error {
	if len(body) == 0 || len(body) > siem.MaxRecordBytes {
		return fmt.Errorf("OCSF record size is invalid")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("OCSF record is not a JSON object")
	}
	if err := siem.ValidateOCSF(doc); err != nil {
		return fmt.Errorf("OCSF export contract is invalid")
	}
	class := int(doc["class_uid"].(float64))
	if v == nil || v.classes[class] == nil {
		return fmt.Errorf("OCSF class schema is unavailable")
	}
	if err := v.classes[class].Validate(doc); err != nil {
		return fmt.Errorf("OCSF schema validation failed")
	}
	return nil
}
