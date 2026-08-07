package worksign

import (
	"errors"
	"strings"
	"testing"
)

func TestNewRejectsWeakKey(t *testing.T) {
	for _, k := range [][]byte{nil, []byte(""), []byte("short"), make([]byte, MinKeyLen-1)} {
		if _, err := New(k); !errors.Is(err, ErrWeakKey) {
			t.Fatalf("key of len %d should be rejected, got %v", len(k), err)
		}
	}
	if _, err := New(make([]byte, MinKeyLen)); err != nil {
		t.Fatalf("key of len %d should be accepted, got %v", MinKeyLen, err)
	}
}

func TestSignVerify(t *testing.T) {
	s, err := New([]byte(strings.Repeat("k", MinKeyLen)))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	sig := s.Sign("payload-1")
	if sig == "" {
		t.Fatalf("empty signature")
	}
	if !s.Verify("payload-1", sig) {
		t.Fatalf("valid signature must verify")
	}
	if s.Verify("payload-2", sig) {
		t.Fatalf("signature must not verify for a different payload")
	}
	if s.Verify("payload-1", sig+"x") {
		t.Fatalf("tampered signature must not verify")
	}
	// A different key produces a different, non-verifying signature.
	other, _ := New([]byte(strings.Repeat("j", MinKeyLen)))
	if other.Verify("payload-1", sig) {
		t.Fatalf("signature from another key must not verify")
	}
}

func TestNewCopiesKey(t *testing.T) {
	key := []byte(strings.Repeat("k", MinKeyLen))
	s, err := New(key)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	sig := s.Sign("p")
	key[0] = 'z' // mutate caller's slice after construction
	if s.Sign("p") != sig {
		t.Fatalf("signer must copy the key so caller mutation does not change signatures")
	}
}
