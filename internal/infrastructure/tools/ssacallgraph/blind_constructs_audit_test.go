package ssacallgraph

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

func TestBuildGraphRecordsDotImportedUnsafeInitializer(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module dotunsafefix\n\ngo 1.21\n",
		"main.go": `package main
import . "unsafe"
var opaque = Pointer(new(byte))
func main() {}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	if !contains(g.BlindConstructs, "unsafe") {
		t.Fatalf("dot-imported unsafe use in package init must block suppression; got %v", g.BlindConstructs)
	}
}

func TestSourceBlindFunctionsSkipsIgnoredBuildFiles(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "active.go")
	ignored := filepath.Join(dir, "ignored.go")
	if err := os.WriteFile(active, []byte("package p\nfunc target() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ignored, []byte("package p\nimport \"unsafe\"\nfunc target(p *byte) uintptr { return uintptr(unsafe.Pointer(p)) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sourceBlindFunctions([]*packages.Package{{
		PkgPath:      "ignoredfix",
		GoFiles:      []string{active, ignored},
		IgnoredFiles: []string{ignored},
	}})
	if err != nil {
		t.Fatalf("scan source: %v", err)
	}
	if got["unsafe"]["ignoredfix.target"] {
		t.Fatalf("build-excluded unsafe implementation must not poison the active target: %#v", got["unsafe"])
	}
}

func TestGoOpaqueBlindConstructsNeverSuppress(t *testing.T) {
	for _, construct := range goOpaqueConstructs {
		construct := construct
		t.Run(construct, func(t *testing.T) {
			claim := judgment.ReachabilityClaim{
				Reachable:          judgment.NotReachable,
				Tier:               judgment.Tier2,
				EntrypointsPresent: true,
				BlindConstructs:    []string{construct},
			}
			if claim.SuppressesFinding() {
				t.Fatalf("Tier-2 not_reachable with %q blind construct must never suppress: %+v", construct, claim)
			}
		})
	}
}
