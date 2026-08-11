package fptriagecache

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func cacheTestKey() ports.FPTriageCacheKey {
	return ports.FPTriageCacheKey{
		TenantID: "tenant-a", ScopeID: "project-a", FindingFingerprint: "sast:rule:src/app.go:10",
		SourceSHA256: strings.Repeat("a", 64), ContextSHA256: strings.Repeat("b", 64),
		ProposerProvider: "provider-a", ProposerModel: "provider/model-a",
		VerifierProvider: "provider-b", VerifierModel: "provider/model-b",
		PromptVersion: "prompt-v1", PolicyVersion: "policy-v1",
	}
}

func cacheTestDecision() ports.FPTriageCachedDecision {
	return ports.FPTriageCachedDecision{
		Verdict: "refuted", Driver: "input_sanitized", Confidence: 91, VerifierPresent: true,
		VerifierVerdict: "refuted", VerifierDriver: "input_sanitized", VerifierConfidence: 89,
	}
}

func TestStoreLoadRoundTrip(t *testing.T) {
	cache := New(t.TempDir())
	key, want := cacheTestKey(), cacheTestDecision()
	if err := cache.Store(context.Background(), key, want); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, ok, err := cache.Load(context.Background(), key)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decision changed across cache: got %+v want %+v", got, want)
	}
}

func TestEveryKeyedInputInvalidates(t *testing.T) {
	cache := New(t.TempDir())
	base := cacheTestKey()
	if err := cache.Store(context.Background(), base, cacheTestDecision()); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*ports.FPTriageCacheKey){
		"tenant":              func(k *ports.FPTriageCacheKey) { k.TenantID = shared.ID("tenant-b") },
		"project scope":       func(k *ports.FPTriageCacheKey) { k.ScopeID = shared.ID("project-b") },
		"finding fingerprint": func(k *ports.FPTriageCacheKey) { k.FindingFingerprint += ":changed" },
		"source":              func(k *ports.FPTriageCacheKey) { k.SourceSHA256 = strings.Repeat("c", 64) },
		"context":             func(k *ports.FPTriageCacheKey) { k.ContextSHA256 = strings.Repeat("d", 64) },
		"proposer provider":   func(k *ports.FPTriageCacheKey) { k.ProposerProvider = "provider-c" },
		"proposer model":      func(k *ports.FPTriageCacheKey) { k.ProposerModel = "provider/model-c" },
		"verifier provider":   func(k *ports.FPTriageCacheKey) { k.VerifierProvider = "provider-c" },
		"verifier model":      func(k *ports.FPTriageCacheKey) { k.VerifierModel = "provider/model-c" },
		"prompt version":      func(k *ports.FPTriageCacheKey) { k.PromptVersion = "prompt-v2" },
		"policy version":      func(k *ports.FPTriageCacheKey) { k.PolicyVersion = "policy-v2" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if _, ok, err := cache.Load(context.Background(), changed); err != nil || ok {
				t.Fatalf("changed key must miss: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestCorruptOrMismatchedEntryFailsClosedToMiss(t *testing.T) {
	root := t.TempDir()
	cache := New(root)
	key := cacheTestKey()
	if err := cache.Store(context.Background(), key, cacheTestDecision()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, digestKey(key)+".json")
	if err := os.WriteFile(path, []byte(`{"version":1,"key":{},"decision":{"verdict":"refuted","driver":"input_sanitized","confidence":100}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := cache.Load(context.Background(), key); err != nil || ok {
		t.Fatalf("tampered entry must be a clean miss: ok=%v err=%v", ok, err)
	}
	if err := cache.Store(context.Background(), key, cacheTestDecision()); err != nil {
		t.Fatalf("Store must heal the invalid exact-key entry: %v", err)
	}
	if _, ok, err := cache.Load(context.Background(), key); err != nil || !ok {
		t.Fatalf("healed entry must hit: ok=%v err=%v", ok, err)
	}
}

func TestValidLookingPayloadTamperFailsChecksum(t *testing.T) {
	root := t.TempDir()
	cache := New(root)
	key := cacheTestKey()
	if err := cache.Store(context.Background(), key, cacheTestDecision()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, digestKey(key)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"confidence":91`, `"confidence":81`, 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := cache.Load(context.Background(), key); err != nil || ok {
		t.Fatalf("checksum mismatch must be a clean miss: ok=%v err=%v", ok, err)
	}
}

func TestLoadRefusesSharedWritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permissions are ACL-based")
	}
	root := t.TempDir()
	cache := New(root)
	key := cacheTestKey()
	if err := cache.Store(context.Background(), key, cacheTestDecision()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := cache.Load(context.Background(), key); err != nil || ok {
		t.Fatalf("shared-writable cache must fail closed to miss: ok=%v err=%v", ok, err)
	}
}

func TestIncompleteVerifierDecisionIsRejected(t *testing.T) {
	cache := New(t.TempDir())
	decision := cacheTestDecision()
	decision.VerifierPresent = false
	decision.VerifierVerdict = ""
	decision.VerifierDriver = ""
	decision.VerifierConfidence = 0
	if err := cache.Store(context.Background(), cacheTestKey(), decision); err == nil {
		t.Fatal("a configured verifier without a completed claim must not be cached")
	}
}
