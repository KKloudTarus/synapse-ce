package measure

import "testing"

func sampleReport() ComplexityReport {
	return ComplexityReport{Functions: []FunctionComplexity{
		{File: "a.go", Line: 10, Name: "a", Cyclomatic: 3, Cognitive: 2},
		{File: "b.go", Line: 5, Name: "b", Cyclomatic: 9, Cognitive: 12},
		{File: "a.go", Line: 20, Name: "c", Cyclomatic: 9, Cognitive: 4},
		{File: "c.go", Line: 1, Name: "d", Cyclomatic: 1, Cognitive: 0},
	}}
}

func TestMaxCyclomatic(t *testing.T) {
	if got := sampleReport().MaxCyclomatic(); got != 9 {
		t.Errorf("MaxCyclomatic = %d, want 9", got)
	}
	if got := (ComplexityReport{}).MaxCyclomatic(); got != 0 {
		t.Errorf("empty MaxCyclomatic = %d, want 0", got)
	}
}

func TestOverCyclomatic(t *testing.T) {
	over := sampleReport().OverCyclomatic(3)
	if len(over) != 2 {
		t.Fatalf("OverCyclomatic(3) = %d functions, want 2 (%+v)", len(over), over)
	}
	// Ties on cyclomatic (both 9) break by file then line: a.go:20 before b.go:5.
	if over[0].Name != "c" || over[1].Name != "b" {
		t.Errorf("tie ordering wrong: got %s,%s want c,b", over[0].Name, over[1].Name)
	}
	if len(sampleReport().OverCyclomatic(100)) != 0 {
		t.Errorf("OverCyclomatic(100) should be empty")
	}
}

func TestOverCognitive(t *testing.T) {
	over := sampleReport().OverCognitive(3)
	if len(over) != 2 {
		t.Fatalf("OverCognitive(3) = %d functions, want 2 (%+v)", len(over), over)
	}
	if over[0].Name != "b" || over[1].Name != "c" {
		t.Errorf("ordering wrong: got %s,%s want b,c", over[0].Name, over[1].Name)
	}
	if len(sampleReport().OverCognitive(100)) != 0 {
		t.Error("OverCognitive(100) should be empty")
	}
}

func TestTopByCyclomatic(t *testing.T) {
	top := sampleReport().TopByCyclomatic(2)
	if len(top) != 2 || top[0].Cyclomatic != 9 || top[1].Cyclomatic != 9 {
		t.Errorf("TopByCyclomatic(2) wrong: %+v", top)
	}
	if n := len(sampleReport().TopByCyclomatic(100)); n != 4 {
		t.Errorf("TopByCyclomatic(100) = %d, want all 4", n)
	}
}

func TestFileCyclomatic(t *testing.T) {
	// Legacy report without Files returns false
	legacy := sampleReport()
	if _, ok := legacy.FileCyclomatic("a.go"); ok {
		t.Errorf("legacy report without coverage evidence must return ok=false")
	}

	rep := ComplexityReport{
		Functions: []FunctionComplexity{
			{File: "a.go", Cyclomatic: 3},
			{File: "a.go", Cyclomatic: 5},
		},
		Files: []ComplexityFileCoverage{
			{File: "a.go", Language: "Go", Supported: true, Parsed: true},
			{File: "zero.go", Language: "Go", Supported: true, Parsed: true}, // 0 functions in file
			{File: "err.go", Language: "Go", Supported: true, Parsed: false, ParseError: true},
			{File: "unsupported.txt", Language: "Text", Supported: false, Parsed: false},
		},
	}

	// a.go sum = 3 + 5 = 8
	if sum, ok := rep.FileCyclomatic("a.go"); !ok || sum != 8 {
		t.Errorf("a.go want sum=8 ok=true, got sum=%d ok=%v", sum, ok)
	}

	// zero.go sum = 0, ok = true (file parsed successfully with 0 functions)
	if sum, ok := rep.FileCyclomatic("zero.go"); !ok || sum != 0 {
		t.Errorf("zero.go want sum=0 ok=true, got sum=%d ok=%v", sum, ok)
	}

	// err.go ok = false
	if _, ok := rep.FileCyclomatic("err.go"); ok {
		t.Errorf("err.go want ok=false")
	}

	// unsupported.txt ok = false
	if _, ok := rep.FileCyclomatic("unsupported.txt"); ok {
		t.Errorf("unsupported.txt want ok=false")
	}

	// unknown.go ok = false
	if _, ok := rep.FileCyclomatic("unknown.go"); ok {
		t.Errorf("unknown.go want ok=false")
	}
}

func TestComplexityIndexIsBoundedAndCoverageAware(t *testing.T) {
	report := ComplexityReport{
		Version: ComplexitySchemaVersion,
		Files: []ComplexityFileCoverage{
			{File: "ok.go", Language: "Go", Supported: true, Parsed: true},
			{File: "broken.go", Language: "Go", Supported: true, Parsed: false, ParseError: true},
		},
		Functions: []FunctionComplexity{
			{File: "ok.go", Cyclomatic: 3, Cognitive: 4},
			{File: "ok.go", Cyclomatic: 5, Cognitive: 6},
			{File: "broken.go", Cyclomatic: 99, Cognitive: 99},
		},
	}
	index, err := report.ComplexityIndex()
	if err != nil {
		t.Fatal(err)
	}
	if index["ok.go"].Cyclomatic != 8 || index["ok.go"].Cognitive != 10 || !index["ok.go"].Available {
		t.Fatalf("ok index = %+v", index["ok.go"])
	}
	if index["broken.go"].Available || index["broken.go"].Cyclomatic != 0 {
		t.Fatalf("broken file must stay unavailable: %+v", index["broken.go"])
	}

	duplicate := report
	duplicate.Files = append(append([]ComplexityFileCoverage(nil), report.Files...), ComplexityFileCoverage{File: "ok.go", Supported: true, Parsed: true})
	if _, err := duplicate.ComplexityIndex(); err == nil {
		t.Fatal("expected duplicate coverage path error")
	}

	bad := report
	bad.Functions = append([]FunctionComplexity(nil), report.Functions...)
	bad.Functions[0].File = "../outside.go"
	if _, err := bad.ComplexityIndex(); err == nil {
		t.Fatal("expected non-canonical function path error")
	}
}
