package responsekey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func trustBundle(t *testing.T, mutate func(map[string]any)) ([]byte, string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := evidence.KeyFingerprint(public)
	key := map[string]any{
		"key_id": keyID, "public_key": base64.StdEncoding.EncodeToString(public),
		"not_before": time.Unix(100, 0).UTC(), "not_after": time.Unix(300, 0).UTC(),
	}
	if mutate != nil {
		mutate(key)
	}
	document := map[string]any{"version": 1, "keys": []any{key}}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data, keyID
}

func TestResolverPinsValidatedKeyAndReturnsCopy(t *testing.T) {
	data, keyID := trustBundle(t, nil)
	resolver, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	key, err := resolver.ResolveResponseCommandKey(context.Background(), keyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.UsableAt(time.Unix(200, 0).UTC()); err != nil {
		t.Fatalf("resolved key is not usable: %v", err)
	}
	key.PublicKey[0] ^= 0xff
	again, err := resolver.ResolveResponseCommandKey(context.Background(), keyID)
	if err != nil || again.PublicKey[0] == key.PublicKey[0] {
		t.Fatalf("resolver exposed mutable key storage: err=%v", err)
	}
}

func TestResolverRejectsUntrustedOrAmbiguousBundles(t *testing.T) {
	valid, keyID := trustBundle(t, nil)
	tests := map[string][]byte{
		"unknown field": append(valid[:len(valid)-1], []byte(`,"extra":true}`)...),
		"trailing data": append(valid, []byte(`{}`)...),
	}
	badFingerprint, _ := trustBundle(t, func(key map[string]any) { key["key_id"] = "wrong" })
	tests["fingerprint mismatch"] = badFingerprint
	var duplicateDocument map[string]any
	if err := json.Unmarshal(valid, &duplicateDocument); err != nil {
		t.Fatal(err)
	}
	keys := duplicateDocument["keys"].([]any)
	duplicateDocument["keys"] = append(keys, keys[0])
	duplicate, err := json.Marshal(duplicateDocument)
	if err != nil {
		t.Fatal(err)
	}
	tests["duplicate key"] = duplicate

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(data); err == nil {
				t.Fatal("invalid trust bundle was accepted")
			}
		})
	}
	if _, err := New([]byte(`{"version":1,"keys":[]}`)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty bundle error=%v", err)
	}
	if _, err := New([]byte(`{"version":2,"keys":[{"key_id":"` + keyID + `"}]}`)); err == nil {
		t.Fatal("unsupported bundle version was accepted")
	}
}

func TestResolverEnforcesRevocationAndContext(t *testing.T) {
	data, keyID := trustBundle(t, func(key map[string]any) { key["revoked_at"] = time.Unix(180, 0).UTC() })
	resolver, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	key, err := resolver.ResolveResponseCommandKey(context.Background(), keyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.UsableAt(time.Unix(200, 0).UTC()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("revoked key usability error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveResponseCommandKey(cancelled, keyID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolution error=%v", err)
	}
	if _, err := resolver.ResolveResponseCommandKey(context.Background(), "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing key error=%v", err)
	}
}

func TestLoadFileRejectsWritableTrustRoot(t *testing.T) {
	data, _ := trustBundle(t, nil)
	path := filepath.Join(t.TempDir(), "response-trust.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatalf("protected trust bundle rejected: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("writable trust bundle error=%v", err)
	}
}
