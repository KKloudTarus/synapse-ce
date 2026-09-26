package msgtemplate

import (
	"testing"
)

func testSchema() Schema {
	return Schema{
		Vars: []string{"title", "severity", "summary", "count_new", "owner"},
		Lists: map[string]List{
			"items":    {Cap: 100, Fields: []string{"title", "severity"}},
			"affected": {Cap: 50, Fields: []string{"host"}},
			"big":      {Cap: 200, Fields: []string{"name"}},
		},
	}
}

func mustCompile(t *testing.T, source string) *Template {
	t.Helper()
	tmpl, err := Compile("test", source, testSchema())
	if err != nil {
		t.Fatalf("Compile(%q): %v", source, err)
	}
	return tmpl
}

func render(t *testing.T, source string, data Data) string {
	t.Helper()
	out, err := mustCompile(t, source).Render(data, 4000)
	if err != nil {
		t.Fatalf("Render(%q): %v", source, err)
	}
	return out.Text
}
