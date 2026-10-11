package msgtemplate

import (
	"fmt"
	"sort"
)

// SchemaSpec declares every variable a template may reference. The notification event catalog and
// the ticket context spec each build one; this package imports neither.
//
// Scalars are plain strings. A list is a slice of flat string maps whose keys are Fields; Cap bounds
// both the static iteration cost and the number of items Render passes to the template.
// MaxValueRunes bounds every value; Render cuts longer values, so the static cost model can rely on
// it. Zero selects DefaultMaxValueRunes.
type SchemaSpec struct {
	Vars          []string
	Lists         map[string]List
	MaxValueRunes int
}

// List declares one list variable.
type List struct {
	Cap    int
	Fields []string
}

// Schema is a validated SchemaSpec. Build it once, at the composition root, with NewSchema: a bad
// spec is a programming error in the catalog and must fail at startup, not reach a tenant as an
// invalid template.
type Schema struct {
	vars          map[string]bool
	lists         map[string]schemaList
	maxValueRunes int
}

type schemaList struct {
	cap    int
	fields map[string]bool
}

// NewSchema validates spec. Errors wrap ErrInvalidSchema.
func NewSchema(spec SchemaSpec) (*Schema, error) {
	maxValue := spec.MaxValueRunes
	if maxValue == 0 {
		maxValue = DefaultMaxValueRunes
	}
	if maxValue < 1 || maxValue > MaxOutputRunes {
		return nil, schemaError("MaxValueRunes out of range")
	}
	s := &Schema{vars: map[string]bool{}, lists: map[string]schemaList{}, maxValueRunes: maxValue}
	for _, name := range spec.Vars {
		if !validName(name) || s.vars[name] {
			return nil, schemaError("invalid or duplicate variable " + name)
		}
		s.vars[name] = true
	}
	for _, name := range sortedKeys(spec.Lists) {
		list, err := newSchemaList(name, spec.Lists[name], s.vars)
		if err != nil {
			return nil, err
		}
		s.lists[name] = list
	}
	return s, nil
}

func newSchemaList(name string, spec List, vars map[string]bool) (schemaList, error) {
	if !validName(name) || vars[name] {
		return schemaList{}, schemaError("invalid list name " + name)
	}
	if spec.Cap < 1 || spec.Cap > MaxIterationProduct || len(spec.Fields) == 0 {
		return schemaList{}, schemaError(fmt.Sprintf("list %s needs a cap in [1, %d] and at least one field", name, MaxIterationProduct))
	}
	fields := make(map[string]bool, len(spec.Fields))
	for _, field := range spec.Fields {
		if !validName(field) || fields[field] {
			return schemaList{}, schemaError("invalid or duplicate field " + name + "." + field)
		}
		fields[field] = true
	}
	return schemaList{cap: spec.Cap, fields: fields}, nil
}

func sortedKeys(lists map[string]List) []string {
	names := make([]string, 0, len(lists))
	for name := range lists {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validName accepts lower snake case, which is also a valid text/template field name.
func validName(name string) bool {
	if name == "" || len(name) > 64 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
