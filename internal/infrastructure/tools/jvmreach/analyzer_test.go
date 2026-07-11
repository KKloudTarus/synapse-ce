package jvmreach

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// End-to-end over real compiled fixtures: the app (target/classes) references com.deplib but not
// com.unused, so the deplib component is reachable and the unusedlib component is unreferenced.
func TestAnalyzeReachableVsUnreferenced(t *testing.T) {
	comps := []sbom.Component{
		{Name: "com.deplib:deplib", Version: "1.0", PURL: "pkg:maven/com.deplib/deplib@1.0"},
		{Name: "com.unused:unusedlib", Version: "1.0", PURL: "pkg:maven/com.unused/unusedlib@1.0"},
	}
	n, err := New().Analyze(context.Background(), "testdata", comps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("tagged = %d, want 2", n)
	}
	byName := map[string]string{}
	for _, c := range comps {
		byName[c.Name] = c.Reachability
	}
	if byName["com.deplib:deplib"] != sbom.ReachabilityReachable {
		t.Errorf("deplib = %q, want reachable", byName["com.deplib:deplib"])
	}
	if byName["com.unused:unusedlib"] != sbom.ReachabilityUnreferenced {
		t.Errorf("unusedlib = %q, want unreferenced", byName["com.unused:unusedlib"])
	}
}

// CONSERVATIVE guard: with no application root classes (source not built – only dep jars present), the
// analyzer must tag NOTHING. An "unreferenced" verdict is never emitted without app roots to anchor it,
// so a not-built project can't be mislabeled as having dead dependencies.
func TestAnalyzeNotBuiltTagsNothing(t *testing.T) {
	dir := t.TempDir()
	// copy only the dep jar (no target/classes app roots)
	data, err := os.ReadFile(filepath.Join("testdata", "target", "dependency", "deplib-1.0.jar"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deplib-1.0.jar"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	comps := []sbom.Component{{Name: "com.deplib:deplib", Version: "1.0"}}
	n, err := New().Analyze(context.Background(), dir, comps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || comps[0].Reachability != "" {
		t.Fatalf("not-built must tag nothing, got n=%d reachability=%q", n, comps[0].Reachability)
	}
}

// A component whose classes aren't in the workspace is left unknown (not falsely "unreferenced").
func TestAnalyzeUnknownComponentUntouched(t *testing.T) {
	comps := []sbom.Component{{Name: "org.absent:absent", Version: "9.9"}}
	_, err := New().Analyze(context.Background(), "testdata", comps)
	if err != nil {
		t.Fatal(err)
	}
	if comps[0].Reachability != "" {
		t.Errorf("absent component = %q, want unknown (empty)", comps[0].Reachability)
	}
}

func TestReachClosure(t *testing.T) {
	// app -> a -> b; c is unreferenced
	refs := map[string][]string{
		"app": {"a"},
		"a":   {"b"},
		"b":   {},
		"c":   {"a"},
	}
	got := reachClosure(refs, map[string]bool{"app": true})
	for _, want := range []string{"app", "a", "b"} {
		if !got[want] {
			t.Errorf("%q should be reachable", want)
		}
	}
	if got["c"] {
		t.Error("c should NOT be reachable")
	}
}
