//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestQualityForCSharpStructuredRules(t *testing.T) {
	root := t.TempDir()
	source := `class Sample {
    int Complex(int a, int b, int c) {
        int total = 0;
        if (a > 0) {
            for (int i = 0; i < a; i++) {
                if (b > 0) {
                    while (c > 0) {
                        if (a > b) {
                            if (b > c) {
                                total += 1;
                            }
                        }
                    }
                }
            }
        }
        return total;
    }
    void Swallow() {
        try { Work(); } catch (System.Exception e) { }
    }
    void SwallowSemicolon() {
        try { Work(); } catch (System.Exception e) { ; }
    }
    void Route(int x) {
        switch (x) {
            case 1: Work(); break;
            case 2: Work(); break;
        }
    }
    void Work() {}
}
`
	if err := os.WriteFile(filepath.Join(root, "Sample.cs"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	want := map[string]int{
		"csharp-ast-empty-catch":            2, // both `{ }` and `{ ; }` swallow
		"csharp-ast-missing-switch-default": 1,
	}
	counts := map[string]int{}
	for _, f := range got.Findings {
		counts[f.Rule]++
		if f.File != "Sample.cs" || f.Line <= 0 || f.Title == "" || f.Description == "" {
			t.Errorf("incomplete finding metadata: %+v", f)
		}
	}
	for r, c := range want {
		if counts[r] != c {
			t.Errorf("%s count = %d, want %d; findings=%+v", r, counts[r], c, got.Findings)
		}
	}
}

func TestQualityForCSharpCompliant(t *testing.T) {
	root := t.TempDir()
	source := `class Clean {
    int Simple(int a) {
        if (a > 0) return 1;
        return 0;
    }
    string Dispatch(int c) {
        if (c == 0) return "a";
        else if (c == 1) return "b";
        else if (c == 2) return "c";
        else if (c == 3) return "d";
        else if (c == 4) return "e";
        else return "z";
    }
    void Handled() {
        try { Work(); } catch (System.Exception e) { Log(e); }
    }
    void Route(int x) {
        switch (x) {
            case 1: Work(); break;
            default: Work(); break;
        }
    }
    void Work() {}
    void Log(System.Exception e) {}
}
`
	if err := os.WriteFile(filepath.Join(root, "Clean.cs"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	for _, f := range got.Findings {
		if f.File == "Clean.cs" {
			t.Errorf("clean C# source produced a finding (false positive): %+v", f)
		}
	}
}

// TestQualityForCSharpExhaustivePatternSwitch pins that an unguarded catch-all pattern section
// (`case var x:` or `case _:`) counts as a default, so an exhaustive pattern switch is NOT flagged,
// while a switch whose only catch-all-shaped section is GUARDED by `when` still is.
func TestQualityForCSharpExhaustivePatternSwitch(t *testing.T) {
	root := t.TempDir()
	source := `class P {
    void VarCatchAll(object v) {
        switch (v) {
            case int i: Handle(i); break;
            case var unexpected: throw new System.InvalidOperationException($"{unexpected}");
        }
    }
    void DiscardCatchAll(object v) {
        switch (v) {
            case int i: Handle(i); break;
            case _: Handle(0); break;
        }
    }
    void GuardedOnly(object v) {
        switch (v) {
            case var x when x != null: Handle(1); break;
        }
    }
    void Handle(int n) {}
}
`
	if err := os.WriteFile(filepath.Join(root, "P.cs"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	// Only the GuardedOnly switch (a lone `case var x when ...:`) is non-exhaustive; the var-pattern
	// and discard catch-all switches must NOT be flagged.
	var missingLines []int
	for _, f := range got.Findings {
		if f.File == "P.cs" && f.Rule == "csharp-ast-missing-switch-default" {
			missingLines = append(missingLines, f.Line)
		}
	}
	if len(missingLines) != 1 || missingLines[0] < 14 {
		t.Errorf("missing-switch-default lines = %v, want exactly one on the guarded-only switch (line >= 14); findings=%+v", missingLines, got.Findings)
	}
}
