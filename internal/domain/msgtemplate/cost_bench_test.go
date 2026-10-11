package msgtemplate

import (
	"strconv"
	"strings"
	"testing"
)

// worstCaseFamilies are the most expensive shapes the cost model admits: long string comparisons,
// string functions and joins, each repeated as often as MaxEvaluationCost allows.
var worstCaseFamilies = []struct {
	name, prefix, repeat, suffix string
}{
	{"root comparisons", ``, `{{if eq .title "z"}}{{end}}`, ``},
	{"root joins", ``, `{{if eq (join "name" "," $.big) "z"}}{{end}}`, ``},
	{"loop joins", `{{range $.a}}`, `{{if eq (join "name" "," $.big) "z"}}{{end}}`, `{{end}}`},
	{"loop string functions", `{{range $.a}}`, `{{if eq (.name | upper | truncate 30000) "z"}}{{end}}`, `{{end}}`},
	{"loop outputs", `{{range $.a}}`, `{{.name}}`, `{{end}}`},
}

// largestAccepted returns the family's template with the most repetitions that still compiles.
func largestAccepted(schema *Schema, prefix, repeat, suffix string) (*Template, int) {
	var best *Template
	count := 0
	for k := 1; k <= MaxNodes; k++ {
		tmpl, err := Compile("bench", prefix+strings.Repeat(repeat, k)+suffix, schema)
		if err != nil {
			break
		}
		best, count = tmpl, k
	}
	return best, count
}

func benchItems(n, size int) []map[string]string {
	items := make([]map[string]string, n)
	for i := range items {
		items[i] = map[string]string{"name": strings.Repeat("x", size)}
	}
	return items
}

// BenchmarkRenderWorstCase renders, for every family, the largest template the cost model accepts,
// with every value at its length bound. Its result is the worst-case figure quoted for
// MaxEvaluationCost.
func BenchmarkRenderWorstCase(b *testing.B) {
	measured := 0
	for _, maxValue := range []int{DefaultMaxValueRunes, MaxOutputRunes} {
		schema := mustSchema(SchemaSpec{Vars: []string{"title"}, MaxValueRunes: maxValue, Lists: map[string]List{
			"a":   {Cap: 100, Fields: []string{"name"}},
			"big": {Cap: 1000, Fields: []string{"name"}},
		}})
		data := Data{
			Vars:  map[string]string{"title": strings.Repeat("t", maxValue)},
			Lists: map[string][]map[string]string{"a": benchItems(100, maxValue), "big": benchItems(1000, maxValue)},
		}
		for _, family := range worstCaseFamilies {
			tmpl, count := largestAccepted(schema, family.prefix, family.repeat, family.suffix)
			if tmpl == nil {
				continue // the model rejects even one repetition at this value bound
			}
			measured++
			b.Run(family.name+"/value="+strconv.Itoa(maxValue)+"/x"+strconv.Itoa(count), func(b *testing.B) {
				for b.Loop() {
					if _, err := tmpl.Render(data, MaxOutputRunes); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
	if measured == 0 {
		b.Fatal("the cost model accepted no worst-case template; the benchmark measured nothing")
	}
}
