package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCipherRoundTrip(t *testing.T) {
	c, err := NewCipher(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("hunter2-API-token")
	ad := aad("eng1", "github_pat")
	sealed, err := c.Seal(secret, ad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(sealed), secret) {
		t.Fatal("ciphertext must not contain the plaintext")
	}
	got, err := c.Open(sealed, ad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestCipherRejectsWrongKey(t *testing.T) {
	c1, _ := NewCipher(testKey(t))
	c2, _ := NewCipher(testKey(t))
	sealed, _ := c1.Seal([]byte("s"), aad("e", "n"))
	if _, err := c2.Open(sealed, aad("e", "n")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a different key must fail to decrypt, got %v", err)
	}
}

func TestCipherRejectsWrongAAD(t *testing.T) {
	c, _ := NewCipher(testKey(t))
	sealed, _ := c.Seal([]byte("s"), aad("eng1", "name1"))
	// A ciphertext stored for (eng1,name1) cannot be opened as (eng1,name2) – defeats
	// swapping blobs between credentials even with DB write access.
	if _, err := c.Open(sealed, aad("eng1", "name2")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatched AAD must fail, got %v", err)
	}
}

func TestCipherRejectsTamper(t *testing.T) {
	c, _ := NewCipher(testKey(t))
	sealed, _ := c.Seal([]byte("secret"), aad("e", "n"))
	tampered := sealed[:len(sealed)-4] + "AAAA"
	if _, err := c.Open(tampered, aad("e", "n")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered ciphertext must fail, got %v", err)
	}
}

func TestNewCipherRejectsBadKeyLen(t *testing.T) {
	if _, err := NewCipher([]byte("short")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a non-32-byte key must be ErrValidation, got %v", err)
	}
}

func TestDecodeKey(t *testing.T) {
	// 64 hex chars.
	hexKey := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if b, err := DecodeKey(hexKey); err != nil || len(b) != 32 {
		t.Fatalf("hex key: %v len=%d", err, len(b))
	}
	// base64 of 32 bytes.
	if b, err := DecodeKey("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU="); err != nil || len(b) != 32 {
		t.Fatalf("base64 key: %v len=%d", err, len(b))
	}
	if _, err := DecodeKey("too-short"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad key must be ErrValidation, got %v", err)
	}
}
