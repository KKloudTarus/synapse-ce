package msgtemplate

import (
	"errors"
	"strings"
	"testing"
)

func TestRenderFillsMissingValuesAndDropsUndeclared(t *testing.T) {
	data := Data{
		Vars: map[string]string{"undeclared": "dropped value"},
		Lists: map[string][]map[string]string{
			"items": {{"title": "a", "extra": "dropped value"}},
		},
	}
	got := render(t, `[{{.title}}]{{range .items}}{{.title}}/{{.severity}}{{end}}`, data)
	if got != "[]a/" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderCapsListsAtDeclaredCap(t *testing.T) {
	items := make([]map[string]string, 120)
	for i := range items {
		items[i] = map[string]string{"title": "x"}
	}
	got := render(t, `{{count .items}}`, Data{Lists: map[string][]map[string]string{"items": items}})
	if got != "100" {
		t.Fatalf("count = %s, want 100", got)
	}
}

func TestRenderRejectsInvalidLimit(t *testing.T) {
	tmpl := mustCompile(t, "x")
	for _, limit := range []int{0, -1, MaxOutputRunes + 1} {
		if _, err := tmpl.Render(Data{}, limit); !errors.Is(err, ErrRender) {
			t.Fatalf("limit %d: err = %v", limit, err)
		}
	}
}

func TestRenderErrorNeverCarriesValues(t *testing.T) {
	const value = "not a number 7f3a"
	_, err := mustCompile(t, `{{plural .count_new "a" "b"}}`).Render(Data{Vars: map[string]string{"count_new": value}}, 100)
	var tmplErr *Error
	if !errors.As(err, &tmplErr) || tmplErr.Code != CodeInvalidArgument || !errors.Is(err, ErrRender) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error leaks value: %v", err)
	}
}

func TestTemplateIsReusable(t *testing.T) {
	tmpl := mustCompile(t, "{{.title}}")
	for _, title := range []string{"a", "b"} {
		out, err := tmpl.Render(Data{Vars: map[string]string{"title": title}}, 10)
		if err != nil || out.Text != title {
			t.Fatalf("got %+v, %v", out, err)
		}
	}
}

func BenchmarkRenderAtCostBound(b *testing.B) {
	body := strings.Repeat(`{{if eq $.title "x"}}{{end}}`, 2)
	tmpl, err := Compile("bench", `{{range $.items}}{{range $.items}}`+body+`{{end}}{{end}}`, testSchema())
	if err != nil {
		b.Fatal(err)
	}
	items := make([]map[string]string, 100)
	for i := range items {
		items[i] = map[string]string{"title": "a"}
	}
	data := Data{Vars: map[string]string{"title": "y"}, Lists: map[string][]map[string]string{"items": items}}
	for b.Loop() {
		if _, err := tmpl.Render(data, 100); err != nil {
			b.Fatal(err)
		}
	}
}
