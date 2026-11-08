package binregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestTOFUPinsThenDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("original"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := New(nil, true)
	if _, err := r.Verify(bin); err != nil {
		t.Fatalf("first Verify (TOFU pin) should succeed: %v", err)
	}
	if _, err := r.Verify(bin); err != nil {
		t.Fatalf("unchanged binary should still verify: %v", err)
	}
	// Replace the binary – a later run must be refused.
	if err := os.WriteFile(bin, []byte("TAMPERED"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Verify(bin); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a replaced binary must fail integrity, got %v", err)
	}
}

func TestExpectedHashMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	r := New(map[string]string{"tool": "deadbeef"}, false) // wrong pin
	resolved, err := r.Verify(bin)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a binary not matching its authoritative pin must be refused, got %v", err)
	}
	if resolved != "" {
		t.Fatalf("a failed verification must not return an executable path, got %q", resolved)
	}
}

func TestNoPinNoTOFUAllows(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	if _, err := New(nil, false).Verify(bin); err != nil {
		t.Fatalf("with no pin and tofu off, verification is a no-op: %v", err)
	}
}

func TestVerifyReturnsResolvedPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tool-v1")
	link := filepath.Join(dir, "tool")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	resolved, err := New(nil, false).Verify(link)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != want || resolved == link {
		t.Fatalf("Verify(%q) returned %q, want resolved target %q", link, resolved, want)
	}
}

func TestVerifySymlinkAuthoritativePins(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "real")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetDir, "tool-v1")
	content := []byte("original")
	if err := os.WriteFile(target, content, 0o755); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(dir, "tool")
	parentLink := filepath.Join(dir, "alias")
	for link, dest := range map[string]string{fileLink: target, parentLink: targetDir} {
		if err := os.Symlink(dest, link); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	good := hex.EncodeToString(sum[:])
	wrong := "deadbeef"

	for _, requested := range []string{fileLink, filepath.Join(parentLink, "tool-v1")} {
		t.Run(filepath.Base(filepath.Dir(requested))+"-"+filepath.Base(requested), func(t *testing.T) {
			cases := []struct {
				name string
				pins map[string]string
				fail bool
			}{
				{"requested path correct", map[string]string{requested: good}, false},
				{"requested path wrong", map[string]string{requested: wrong}, true},
				{"requested basename wrong", map[string]string{filepath.Base(requested): wrong}, true},
				{"requested wrong resolved correct", map[string]string{requested: wrong, resolved: good}, true},
				{"requested correct resolved wrong", map[string]string{requested: good, resolved: wrong}, true},
				{"requested basename wrong resolved correct", map[string]string{filepath.Base(requested): wrong, resolved: good}, true},
				{"all matching", map[string]string{requested: good, filepath.Base(requested): good, resolved: good, filepath.Base(resolved): good}, false},
				{"no pin", nil, false},
			}
			for _, tc := range cases {
				for _, tofu := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/tofu=%t", tc.name, tofu), func(t *testing.T) {
						got, err := New(tc.pins, tofu).Verify(requested)
						if tc.fail {
							if !errors.Is(err, ErrIntegrity) || got != "" {
								t.Fatalf("Verify(%q) = %q, %v; want integrity refusal and no path", requested, got, err)
							}
						} else if err != nil || got != resolved {
							t.Fatalf("Verify(%q) = %q, %v; want %q, nil", requested, got, err, resolved)
						}
					})
				}
			}
		})
	}
}

// TestVerifyRejectsNonAbsoluteResolvedPath proves the verify==exec invariant is total: a bare name
// that host PATH resolution left unresolved resolves against CWD and comes back relative, which the
// sandbox cannot bind - so Verify must refuse it rather than return a path bwrap would re-resolve.
func TestVerifyRejectsNonAbsoluteResolvedPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir) // so EvalSymlinks("tool") resolves relative to this dir and stays relative
	resolved, err := New(nil, true).Verify("tool")
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a non-absolute resolved path must be refused, got %v", err)
	}
	if resolved != "" {
		t.Fatalf("a refused verification must not return a path, got %q", resolved)
	}
}
