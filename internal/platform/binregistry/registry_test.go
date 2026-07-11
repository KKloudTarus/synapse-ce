package binregistry

import (
	"errors"
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
	if err := r.Verify(bin); err != nil {
		t.Fatalf("first Verify (TOFU pin) should succeed: %v", err)
	}
	if err := r.Verify(bin); err != nil {
		t.Fatalf("unchanged binary should still verify: %v", err)
	}
	// Replace the binary – a later run must be refused.
	if err := os.WriteFile(bin, []byte("TAMPERED"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(bin); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a replaced binary must fail integrity, got %v", err)
	}
}

func TestExpectedHashMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	r := New(map[string]string{"tool": "deadbeef"}, false) // wrong pin
	if err := r.Verify(bin); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a binary not matching its authoritative pin must be refused, got %v", err)
	}
}

func TestNoPinNoTOFUAllows(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	if err := New(nil, false).Verify(bin); err != nil {
		t.Fatalf("with no pin and tofu off, verification is a no-op: %v", err)
	}
}
