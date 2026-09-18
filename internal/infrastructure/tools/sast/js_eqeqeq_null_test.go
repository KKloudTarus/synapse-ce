package sast

import (
	"context"
	"testing"
)

// TestJsEqEqNullIdiom pins that js-eqeqeq (the loose-equality bug rule) does not fire on the `== null` /
// `!= null` idiom, which tests for null-or-undefined in one comparison and is not a coercion bug. The
// dedicated js-eq-null smell still covers it. A line that mixes the null idiom with a real loose comparison
// must still report the coercion bug. This mirrors eslint's eqeqeq `{ "null": "ignore" }` default.
func TestJsEqEqNullIdiom(t *testing.T) {
	cases := []struct {
		name       string
		content    string
		wantEqEq   []int // lines where js-eqeqeq must fire
		wantEqNull []int // lines where js-eq-null must fire
	}{
		{
			name:       "bare null check is not a bug",
			content:    "if (value == null) {\n  handle();\n}\n",
			wantEqEq:   nil,
			wantEqNull: []int{1},
		},
		{
			name:       "not-equal null check is not a bug",
			content:    "if (value != null) {\n  handle();\n}\n",
			wantEqEq:   nil,
			wantEqNull: nil, // js-eq-null targets `== null`; `!= null` is not flagged by either rule
		},
		{
			name:       "real loose equality is still a bug",
			content:    "if (a == b) {\n  handle();\n}\n",
			wantEqEq:   []int{1},
			wantEqNull: nil,
		},
		{
			name:       "mixed line still reports the coercion bug",
			content:    "if (n != null && a == b) {\n  handle();\n}\n",
			wantEqEq:   []int{1},
			wantEqNull: nil,
		},
		{
			name:       "strict equality is never flagged",
			content:    "if (p === null) {\n  handle();\n}\n",
			wantEqEq:   nil,
			wantEqNull: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "sample.js", tc.content)
			findings, err := New().AnalyzeSource(context.Background(), root)
			if err != nil {
				t.Fatalf("AnalyzeSource: %v", err)
			}
			var gotEqEq, gotEqNull []int
			for _, f := range findings {
				switch f.RuleID {
				case "js-eqeqeq":
					gotEqEq = append(gotEqEq, f.Line)
				case "js-eq-null":
					gotEqNull = append(gotEqNull, f.Line)
				}
			}
			if !equalInts(gotEqEq, tc.wantEqEq) {
				t.Errorf("js-eqeqeq lines = %v, want %v (findings=%+v)", gotEqEq, tc.wantEqEq, findings)
			}
			if !equalInts(gotEqNull, tc.wantEqNull) {
				t.Errorf("js-eq-null lines = %v, want %v (findings=%+v)", gotEqNull, tc.wantEqNull, findings)
			}
		})
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
