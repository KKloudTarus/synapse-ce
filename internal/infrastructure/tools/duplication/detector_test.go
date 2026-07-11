package duplication

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const dupBody = `func Compute(x int) int {
	total := 0
	for i := 0; i < x; i++ {
		total = total + i*i
	}
	return total
}
`

func TestCrossFileDuplication(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", "package a\n"+dupBody+"func UA() { println(1) }\n")
	write(t, root, "b.go", "package b\n"+dupBody+"func UB() { println(2) }\n")

	rep, err := New(10).Duplication(context.Background(), root)
	if err != nil {
		t.Fatalf("duplication: %v", err)
	}
	if len(rep.Blocks) != 1 {
		t.Fatalf("want 1 duplicated block, got %d (%+v)", len(rep.Blocks), rep.Blocks)
	}
	b := rep.Blocks[0]
	if len(b.Occurrences) != 2 {
		t.Fatalf("want 2 occurrences, got %d", len(b.Occurrences))
	}
	if b.Occurrences[0].File != "a.go" || b.Occurrences[1].File != "b.go" {
		t.Errorf("occurrence files wrong: %+v", b.Occurrences)
	}
	if rep.Files != 2 {
		t.Errorf("want 2 files with duplication, got %d", rep.Files)
	}
	if rep.Density() <= 0 {
		t.Errorf("density should be > 0, got %.1f", rep.Density())
	}
}

func TestCommentInsensitive(t *testing.T) {
	// The same code with DIFFERENT comments must still be detected as a clone.
	root := t.TempDir()
	write(t, root, "a.go", "package a\n// first copy\n"+dupBody)
	write(t, root, "b.go", "package b\n/* a totally different comment here */\n"+dupBody)
	rep, err := New(10).Duplication(context.Background(), root)
	if err != nil {
		t.Fatalf("duplication: %v", err)
	}
	if len(rep.Blocks) != 1 {
		t.Fatalf("comment-only differences must not hide the clone: got %d blocks", len(rep.Blocks))
	}
}

func TestBelowThresholdNotReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", "package a\n"+dupBody+"func UA(){}\n")
	write(t, root, "b.go", "package b\n"+dupBody+"func UB(){}\n")
	// The shared block is ~38 tokens; a threshold above that yields no duplication.
	rep, err := New(500).Duplication(context.Background(), root)
	if err != nil {
		t.Fatalf("duplication: %v", err)
	}
	if len(rep.Blocks) != 0 {
		t.Errorf("min-tokens above the clone size must report nothing, got %+v", rep.Blocks)
	}
}

func TestNoDuplication(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", "package a\nfunc A() { println(1) }\n")
	write(t, root, "b.go", "package b\nfunc B() { println(2) }\n")
	rep, err := New(6).Duplication(context.Background(), root)
	if err != nil {
		t.Fatalf("duplication: %v", err)
	}
	if len(rep.Blocks) != 0 || rep.DuplicatedLines != 0 || rep.Density() != 0 {
		t.Errorf("distinct files must have no duplication, got %+v", rep)
	}
}

func TestIntraFileDuplication(t *testing.T) {
	// Two identical blocks in ONE file must be detected.
	root := t.TempDir()
	write(t, root, "a.go", "package a\n"+dupBody+"func Mid(){}\n"+dupBody)
	rep, err := New(10).Duplication(context.Background(), root)
	if err != nil {
		t.Fatalf("duplication: %v", err)
	}
	if len(rep.Blocks) != 1 || len(rep.Blocks[0].Occurrences) != 2 {
		t.Fatalf("intra-file clone not detected: %+v", rep.Blocks)
	}
	if rep.Blocks[0].Occurrences[0].File != "a.go" || rep.Blocks[0].Occurrences[1].File != "a.go" {
		t.Errorf("both occurrences should be in a.go: %+v", rep.Blocks[0].Occurrences)
	}
}

func TestDeterministic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", "package a\n"+dupBody)
	write(t, root, "b.go", "package b\n"+dupBody)
	r1, _ := New(10).Duplication(context.Background(), root)
	r2, _ := New(10).Duplication(context.Background(), root)
	if len(r1.Blocks) != len(r2.Blocks) || r1.DuplicatedLines != r2.DuplicatedLines {
		t.Errorf("non-deterministic: %+v vs %+v", r1, r2)
	}
}
