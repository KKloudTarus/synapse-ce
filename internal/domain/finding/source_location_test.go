package finding

import (
	"errors"
	"testing"
)

func TestSourceLocationValidate(t *testing.T) {
	column := func(v int) *int { return &v }
	cases := []struct {
		name string
		loc  SourceLocation
		want error
	}{
		{"single line", SourceLocation{File: "cmd/api/main.go", StartLine: 7, EndLine: 7}, nil},
		{"multiline byte columns", SourceLocation{File: "cmd/api/main.go", StartLine: 7, EndLine: 9, StartColumn: column(2), EndColumn: column(5)}, nil},
		{"missing file", SourceLocation{StartLine: 1, EndLine: 1}, ErrSourceLocationFile},
		{"traversal", SourceLocation{File: "../secret.go", StartLine: 1, EndLine: 1}, ErrSourceLocationFile},
		{"uncanonical separator", SourceLocation{File: "cmd\\api\\main.go", StartLine: 1, EndLine: 1}, ErrSourceLocationFile},
		{"zero start", SourceLocation{File: "main.go", StartLine: 0, EndLine: 1}, ErrSourceLocationLines},
		{"reversed lines", SourceLocation{File: "main.go", StartLine: 2, EndLine: 1}, ErrSourceLocationLines},
		{"one column", SourceLocation{File: "main.go", StartLine: 1, EndLine: 1, StartColumn: column(0)}, ErrSourceLocationColumns},
		{"negative column", SourceLocation{File: "main.go", StartLine: 1, EndLine: 1, StartColumn: column(-1), EndColumn: column(0)}, ErrSourceLocationColumns},
		{"reversed columns", SourceLocation{File: "main.go", StartLine: 1, EndLine: 1, StartColumn: column(3), EndColumn: column(2)}, ErrSourceLocationColumns},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loc.Validate()
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSourceLocationFromLegacy(t *testing.T) {
	loc, ok := SourceLocationFromLegacy("internal/service.go:42")
	if !ok {
		t.Fatal("legacy location was not parsed")
	}
	if loc.File != "internal/service.go" || loc.StartLine != 42 || loc.EndLine != 42 {
		t.Fatalf("location = %+v", loc)
	}

	for _, raw := range []string{"", "main.go", "main.go:0", "../main.go:1", "C:/main.go:1", "main.go:not-a-line"} {
		if _, ok := SourceLocationFromLegacy(raw); ok {
			t.Fatalf("invalid legacy location %q parsed", raw)
		}
	}
}
