package ssacallgraph

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestSourceBlindFunctionsRecognizesCgoWithoutCgoToolchain(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.go")
	const src = `package main
/*
int opaque(void) { return 1; }
*/
import "C"

func opaque() int { return int(C.opaque()) }
func main() { _ = opaque() }
`
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sourceBlindFunctions([]*packages.Package{{PkgPath: "cgofix", GoFiles: []string{file}}})
	if err != nil {
		t.Fatalf("scan source: %v", err)
	}
	if !got["cgo"]["cgofix.opaque"] {
		t.Fatalf("C selector in opaque must be recorded as cgo blind construct; got %#v", got["cgo"])
	}
	if got["cgo"]["cgofix.main"] {
		t.Fatalf("caller with no direct C surface must not be marked cgo-blind; got %#v", got["cgo"])
	}
}

func TestBuildGraphRecordsReachableGoOpaqueConstructs(t *testing.T) {
	tests := []struct {
		name  string
		want  string
		files map[string]string
	}{
		{
			name: "unsafe",
			want: "unsafe",
			files: map[string]string{
				"go.mod": "module unsafefix\n\ngo 1.21\n",
				"main.go": `package main
import "unsafe"
func opaque(p *byte) uintptr { return uintptr(unsafe.Pointer(p)) }
func main() { var b byte; _ = opaque(&b) }
`,
			},
		},
		{
			name: "go_linkname",
			want: "go:linkname",
			files: map[string]string{
				"go.mod": "module linkfix\n\ngo 1.21\n",
				"main.go": `package main
import _ "unsafe"
//go:linkname runtimeNano runtime.nanotime
func runtimeNano() int64
func main() { _ = runtimeNano() }
`,
			},
		},
		{
			name: "assembly",
			want: "assembly",
			files: map[string]string{
				"go.mod": "module asmfix\n\ngo 1.21\n",
				"main.go": `package main
func opaque()
func main() { opaque() }
`,
				"opaque.s": "// assembly-backed fixture; body is irrelevant to go/packages type/SSA loading\n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeModule(t, tt.files)
			g, err := BuildGraph(context.Background(), dir)
			if err != nil {
				t.Fatalf("build graph: %v", err)
			}
			if !contains(g.BlindConstructs, tt.want) {
				t.Fatalf("reachable %s construct must be blind; got %v", tt.want, g.BlindConstructs)
			}
		})
	}
}

func TestBuildGraphRecordsOpaquePackageInitializer(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module initunsafefix\n\ngo 1.21\n",
		"main.go": `package main
import "unsafe"
var p = unsafe.Pointer(new(byte))
func main() {}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	if !contains(g.BlindConstructs, "unsafe") {
		t.Fatalf("package-level unsafe initializer runs from reachable init and must be blind; got %v", g.BlindConstructs)
	}
}

func TestBuildGraphDoesNotRecordDeadUnsafeConstruct(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module deadunsafefix\n\ngo 1.21\n",
		"main.go": `package main
import "unsafe"
func dead(p *byte) uintptr { return uintptr(unsafe.Pointer(p)) }
func main() {}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	if contains(g.BlindConstructs, "unsafe") {
		t.Fatalf("unreachable unsafe code must not globally disable suppression; got %v", g.BlindConstructs)
	}
}
