package msgtemplate

import (
	"testing"
)

func TestRenderFunctions(t *testing.T) {
	data := Data{
		Vars: map[string]string{"title": "sql injection", "severity": "CRITICAL", "count_new": "1", "owner": " "},
		Lists: map[string][]map[string]string{
			"items": {{"title": "a", "severity": "high"}, {"title": "b", "severity": "low"}},
		},
	}
	cases := map[string]string{
		`{{.title | upper}}`:                                    "SQL INJECTION",
		`{{.severity | lower}}`:                                 "critical",
		`{{severity_label .severity}}`:                          "Critical",
		`{{severity_label .summary}}`:                           "Unknown",
		`{{.owner | default "unassigned"}}`:                     "unassigned",
		`{{.title | truncate 5}}`:                               "sql …",
		`{{.title | truncate -3}}`:                              "",
		`{{.title | truncate 99999999}}`:                        "sql injection",
		`{{count .items}}`:                                      "2",
		`{{.items | join "title" ", "}}`:                        "a, b",
		`{{plural .count_new "finding" "findings"}}`:            "finding",
		`{{plural (count .items) "item" "items"}}`:              "items",
		`{{range $i, $x := .items}}{{$i}}={{$x.title}};{{end}}`: "0=a;1=b;",
		`{{range .items}}{{.title}}{{break}}{{end}}`:            "a",
		`{{range .affected}}x{{else}}none{{end}}`:               "none",
		`{{if eq .severity "CRITICAL"}}yes{{end}}`:              "yes",
	}
	for source, want := range cases {
		if got := render(t, source, data); got != want {
			t.Fatalf("%s rendered %q, want %q", source, got, want)
		}
	}
}
