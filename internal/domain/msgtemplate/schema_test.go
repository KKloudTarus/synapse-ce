package msgtemplate

import (
	"errors"
	"testing"
)

func TestNewSchemaRejectsInvalidSpecs(t *testing.T) {
	for _, spec := range []SchemaSpec{
		{Vars: []string{"Title"}},
		{Vars: []string{"title", "title"}},
		{Vars: []string{"items"}, Lists: map[string]List{"items": {Cap: 1, Fields: []string{"a"}}}},
		{Lists: map[string]List{"items": {Cap: 0, Fields: []string{"a"}}}},
		{Lists: map[string]List{"items": {Cap: MaxIterationProduct + 1, Fields: []string{"a"}}}},
		{Lists: map[string]List{"items": {Cap: 1}}},
		{Lists: map[string]List{"items": {Cap: 1, Fields: []string{"a-b"}}}},
		{MaxValueRunes: -1},
		{MaxValueRunes: MaxOutputRunes + 1},
	} {
		_, err := NewSchema(spec)
		if !errors.Is(err, ErrInvalidSchema) || errors.Is(err, ErrInvalidTemplate) {
			t.Fatalf("NewSchema(%+v) error = %v, want ErrInvalidSchema only", spec, err)
		}
	}
}

func TestNewSchemaDefaultsValueBound(t *testing.T) {
	schema := mustSchema(SchemaSpec{Vars: []string{"title"}})
	if schema.maxValueRunes != DefaultMaxValueRunes {
		t.Fatalf("maxValueRunes = %d, want %d", schema.maxValueRunes, DefaultMaxValueRunes)
	}
}

func TestCompileRejectsNilSchemaAsUsage(t *testing.T) {
	_, err := Compile("test", "x", nil)
	if !errors.Is(err, ErrUsage) || errors.Is(err, ErrInvalidTemplate) {
		t.Fatalf("err = %v, want ErrUsage only", err)
	}
}
