package gobinreach

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildFixture compiles a tiny Go program (with a distinctively-named exported function) to a binary in a
// fresh dir and returns the dir. Extra ldflags allow a stripped build.
func buildFixture(t *testing.T, ldflags string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	src := t.TempDir()
	// //go:noinline keeps VulnFuncMarker a distinct pclntab function; a trivial inlinable body is folded into
	// main and would not appear as its own symbol (an inlining caveat this feature is deliberately blind to).
	prog := `package main

//go:noinline
func VulnFuncMarker() { println("x") }

func main() { VulnFuncMarker() }
`
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module binfixture\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	args := []string{"build", "-o", filepath.Join(outDir, "app")}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable in this env: %v: %s", err, out)
	}
	return outDir
}

func hasSymbolContaining(refs []string, want string) bool {
	for _, r := range refs {
		if r == want {
			return true
		}
	}
	return false
}

// A normal Go binary yields its function symbols, including the fixture's own (non-inlined) function.
func TestScanNormalBinaryExtractsSymbols(t *testing.T) {
	dir := buildFixture(t, "")
	refs, err := New().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !hasSymbolContaining(refs, "main.VulnFuncMarker") {
		t.Fatalf("expected main.VulnFuncMarker among symbols; got %d refs, e.g. %v", len(refs), firstN(refs, 8))
	}
}

// A `-s -w` "stripped" Go binary STILL carries pclntab function names: -s removes the .symtab/DWARF, not the
// .gopclntab (the runtime needs it for stack traces). So normal stripping does NOT blind this evidence, which
// is a strength of the pclntab source. A binary truly lacking a pclntab is the no-coverage case, exercised by
// TestScanMalformedBinaryNoCrash / TestScanNonBinaryTreeNoCoverage.
func TestScanStrippedBinaryStillHasPclntab(t *testing.T) {
	dir := buildFixture(t, "-s -w")
	refs, err := New().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatalf("stripped binary must not error: %v", err)
	}
	if !hasSymbolContaining(refs, "main.VulnFuncMarker") {
		t.Fatalf("a -s -w Go binary keeps its pclntab; expected main.VulnFuncMarker, got %v", firstN(refs, 8))
	}
}

// A malformed/truncated binary is panic-contained and yields no coverage, no crash.
func TestScanMalformedBinaryNoCrash(t *testing.T) {
	dir := t.TempDir()
	// An ELF magic followed by garbage: passes the magic pre-filter, fails/parses-corruptly downstream.
	if err := os.WriteFile(filepath.Join(dir, "broken"), append([]byte("\x7fELF"), make([]byte, 4096)...), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New().ScanSymbolRefs(context.Background(), dir); err != nil {
		t.Fatalf("a malformed binary must not error: %v", err)
	}
}

// A non-binary source tree yields no coverage (the magic pre-filter skips it fast).
func TestScanNonBinaryTreeNoCoverage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	refs, err := New().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("a source-only tree must yield no binary symbols, got %v", firstN(refs, 8))
	}
}

func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
