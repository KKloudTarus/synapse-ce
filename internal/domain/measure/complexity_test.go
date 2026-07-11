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

func TestTopByCyclomatic(t *testing.T) {
	top := sampleReport().TopByCyclomatic(2)
	if len(top) != 2 || top[0].Cyclomatic != 9 || top[1].Cyclomatic != 9 {
		t.Errorf("TopByCyclomatic(2) wrong: %+v", top)
	}
	if n := len(sampleReport().TopByCyclomatic(100)); n != 4 {
		t.Errorf("TopByCyclomatic(100) = %d, want all 4", n)
	}
}
