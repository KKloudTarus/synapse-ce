package ssacallgraph

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestBuildGraphRecordsDetachedGoLinkname(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module detachedlinkfix\n\ngo 1.21\n",
		"main.go": `package main
import _ "unsafe"
//go:linkname runtimeNano runtime.nanotime

func runtimeNano() int64
func main() { _ = runtimeNano() }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	if !contains(g.BlindConstructs, "go:linkname") {
		t.Fatalf("reachable detached //go:linkname must block suppression; got %v", g.BlindConstructs)
	}
}

func TestBuildGraphDoesNotRecordDeadDetachedGoLinkname(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module deadlinkfix\n\ngo 1.21\n",
		"main.go": `package main
import _ "unsafe"
//go:linkname runtimeNano runtime.nanotime

func runtimeNano() int64
func main() {}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	if contains(g.BlindConstructs, "go:linkname") {
		t.Fatalf("dead detached //go:linkname must keep reachable scoping; got %v", g.BlindConstructs)
	}
}

func TestSourceBlindFunctionsDetachedLinknameVariableFailsOpenViaInit(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.go")
	const src = `package main
import _ "unsafe"
//go:linkname runtimeSeed runtime.seed

var runtimeSeed uintptr
func main() {}
`
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sourceBlindFunctions([]*packages.Package{{PkgPath: "detachedvarfix", GoFiles: []string{file}}})
	if err != nil {
		t.Fatalf("scan source: %v", err)
	}
	if !got["go:linkname"]["detachedvarfix.init"] {
		t.Fatalf("detached linknamed package variable must fail open through init; got %#v", got["go:linkname"])
	}
}
