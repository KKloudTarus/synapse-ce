//go:build linux

package ebpf

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// pinnedClangMajor is the clang major version the committed eBPF objects are built with. BPF codegen and
// BTF differ across clang majors, so the reproducible-build check asserts byte-equality ONLY under this
// toolchain and skips loudly on any other clang — it never false-fails a contributor on a different clang.
const pinnedClangMajor = 15

var clangVersionRe = regexp.MustCompile(`clang version (\d+)`)

// clangBin / stripBin honor the same CLANG / LLVM_STRIP overrides as build.sh, so a contributor whose
// pinned toolchain is reachable only as e.g. clang-15 is version-checked (and built) with that binary
// rather than silently skipped.
func clangBin() string {
	if c := os.Getenv("CLANG"); c != "" {
		return c
	}
	return "clang"
}

func stripBin() string {
	if s := os.Getenv("LLVM_STRIP"); s != "" {
		return s
	}
	return "llvm-strip"
}

func clangMajor() (int, bool) {
	out, err := exec.Command(clangBin(), "--version").Output()
	if err != nil {
		return 0, false
	}
	m := clangVersionRe.FindSubmatch(out)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, false
	}
	return n, true
}

// TestCommittedObjectsAreReproducible rebuilds every eBPF object with the pinned clang into a scratch dir
// and asserts each is byte-identical to the committed one. This closes the "a committed binary cannot be
// reviewed by eye" gap: an object that drifted from its .bpf.c source — wrong toolchain, tampering, or a
// forgotten `make ebpf-generate` — fails here rather than shipping unnoticed.
func TestCommittedObjectsAreReproducible(t *testing.T) {
	if _, err := exec.LookPath(clangBin()); err != nil {
		t.Skip("clang not available; skipping eBPF reproducible-build check")
	}
	if _, err := exec.LookPath(stripBin()); err != nil {
		t.Skip("llvm-strip not available; skipping eBPF reproducible-build check")
	}
	major, ok := clangMajor()
	if !ok {
		t.Skip("could not determine clang version; skipping eBPF reproducible-build check")
	}
	if major != pinnedClangMajor {
		t.Skipf("clang %d != pinned %d; reproducible-build check runs only under the pinned toolchain", major, pinnedClangMajor)
	}

	// The test runs with cwd = this package dir (internal/infrastructure/ebpf), so the repo root is three
	// levels up.
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Skipf("cannot resolve repo root: %v", err)
	}
	script := filepath.Join(root, "scripts", "ebpf", "build.sh")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("eBPF build script not found (%v); skipping", err)
	}
	srcDir := filepath.Join(root, "internal", "infrastructure", "ebpf", "c")

	tmp := t.TempDir()
	cmd := exec.Command("bash", script)
	// Run from the repo root so clang's embedded compilation directory matches the canonical
	// `make ebpf-generate` invocation — otherwise a different cwd yields byte-different objects.
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "OUT_DIR="+tmp)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rebuild failed: %v\n%s", err, out)
	}

	committed, err := filepath.Glob(filepath.Join(srcDir, "*.bpf.o"))
	if err != nil {
		t.Fatal(err)
	}
	if len(committed) == 0 {
		t.Fatal("no committed .bpf.o objects found")
	}
	for _, path := range committed {
		name := filepath.Base(path)
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(tmp, name))
		if err != nil {
			t.Errorf("rebuilt object missing for %s: %v", name, err)
			continue
		}
		if !bytes.Equal(want, got) {
			// Byte-equality is gated on the clang MAJOR only; llvm-strip and the system headers pulled by
			// build.sh are not pinned, so a mismatch usually means the committed object drifted from its
			// source (forgotten regen / tampering), but on the same clang major it could also indicate a
			// divergent llvm-strip or libc headers.
			t.Errorf("%s is not reproducible: committed (%d bytes) != clang-%d rebuild (%d bytes) — run `make ebpf-generate` under the pinned toolchain (clang %d) and commit the result",
				name, len(want), pinnedClangMajor, len(got), pinnedClangMajor)
		}
	}
}
