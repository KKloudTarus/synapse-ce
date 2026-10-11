package msgtemplate

import (
	"errors"
	"strings"
	"testing"
)

// reviewSchema reproduces the schema from the #1467 review: two lists of 100 and one of 10,000.
func reviewSchema() *Schema {
	return mustSchema(SchemaSpec{Lists: map[string]List{
		"a":   {Cap: 100, Fields: []string{"name"}},
		"b":   {Cap: 100, Fields: []string{"name"}},
		"big": {Cap: MaxIterationProduct, Fields: []string{"name"}},
	}})
}

func TestCompileRejectsExpensiveCalls(t *testing.T) {
	for name, source := range map[string]string{
		// The review's template: 21 nodes, no output, 12 s per render before the fix.
		"join in a condition": `{{range $.a}}{{range $.b}}{{if eq (join "name" "," $.big) "zz"}}!{{end}}{{end}}{{end}}`,
		"join at the root":    `{{join "name" "," .big}}`,
		"string work in loop": `{{range $.a}}{{range $.b}}{{if eq (upper .name) (lower .name)}}!{{end}}{{end}}{{end}}`,
	} {
		_, err := Compile("test", source, reviewSchema())
		var tmplErr *Error
		if !errors.As(err, &tmplErr) || tmplErr.Code != CodeCostBoundExceeded {
			t.Errorf("%s: err = %v, want %s", name, err, CodeCostBoundExceeded)
		}
	}
}

func TestCompileAcceptsRealisticTemplates(t *testing.T) {
	for _, source := range []string{
		`{{range .items}}- {{severity_label .severity}} {{.title | truncate 120}}{{range $.affected}} {{.host}}{{end}}
{{end}}`,
		`{{plural (count .items) "finding" "findings"}}: {{join "title" ", " .items | truncate 500}}`,
		`{{if eq .severity "critical"}}**{{.title | upper}}**{{else}}{{.title}}{{end}}`,
	} {
		mustCompile(t, source)
	}
}

func TestMeterStopsARunawayRender(t *testing.T) {
	m := &meter{used: MaxEvaluationCost}
	f := funcs{meter: m}
	if _, err := f.join("name", ",", []map[string]string{{"name": "x"}}); !errors.Is(err, errBudget) {
		t.Fatalf("join over budget: err = %v", err)
	}
	if _, err := f.eq("a", "a"); !errors.Is(err, errBudget) {
		t.Fatalf("eq over budget: err = %v", err)
	}
	if code := renderCode(errBudget); code != CodeRenderBudgetExceeded {
		t.Fatalf("renderCode = %s", code)
	}
}

func TestRenderCutsValuesToTheSchemaBound(t *testing.T) {
	schema := mustSchema(SchemaSpec{Vars: []string{"title"}, MaxValueRunes: 10})
	tmpl, err := Compile("test", "{{.title}}", schema)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tmpl.Render(Data{Vars: map[string]string{"title": strings.Repeat("y", 50)}}, 100)
	if err != nil || out.Text != strings.Repeat("y", 9)+truncationMarker {
		t.Fatalf("got %q, %v", out.Text, err)
	}
}
