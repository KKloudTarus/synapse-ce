//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestQualityForPHPStructuredRules(t *testing.T) {
	root := t.TempDir()
	source := `<?php
class Sample {
    function complex($a, $b, $c, $items) {
        $total = 0;
        if ($a > 0) {
            foreach ($items as $i) {
                if ($b > 0) {
                    while ($c > 0) {
                        if ($a > $b) {
                            if ($b > $c) {
                                $total += 1;
                            }
                        }
                    }
                }
            }
        }
        return $total;
    }
    function swallow() {
        try { work(); } catch (Exception $e) { }
    }
    function swallowSemicolon() {
        try { work(); } catch (Exception $e) { ; }
    }
    function route($x) {
        switch ($x) {
            case 1: work(); break;
            case 2: work(); break;
        }
    }
}
`
	if err := os.WriteFile(filepath.Join(root, "Sample.php"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	want := map[string]int{
		"php-ast-empty-catch":            2, // both `{ }` and `{ ; }` swallow
		"php-ast-missing-switch-default": 1,
	}
	counts := map[string]int{}
	for _, f := range got.Findings {
		counts[f.Rule]++
		if f.File != "Sample.php" || f.Line <= 0 || f.Title == "" || f.Description == "" {
			t.Errorf("incomplete finding metadata: %+v", f)
		}
	}
	for r, c := range want {
		if counts[r] != c {
			t.Errorf("%s count = %d, want %d; findings=%+v", r, counts[r], c, got.Findings)
		}
	}
}

func TestQualityForPHPCompliant(t *testing.T) {
	root := t.TempDir()
	source := `<?php
class Clean {
    function simple($a) {
        if ($a > 0) return 1;
        return 0;
    }
    function handled() {
        try { work(); } catch (Throwable $e) { log($e); }
    }
    function route($x) {
        switch ($x) {
            case 1: work(); break;
            default: work(); break;
        }
    }
}
`
	if err := os.WriteFile(filepath.Join(root, "Clean.php"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	for _, f := range got.Findings {
		if f.File == "Clean.php" {
			t.Errorf("clean PHP source produced a finding (false positive): %+v", f)
		}
	}
}
