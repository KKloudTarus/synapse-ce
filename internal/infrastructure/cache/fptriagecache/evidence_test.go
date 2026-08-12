package fptriagecache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCacheRoundTripsEvidenceCitationsWithoutTokenValues(t *testing.T) {
	h := sha256.Sum256([]byte("x"))
	digest := hex.EncodeToString(h[:])
	key := ports.FPTriageCacheKey{TenantID: "tenant", ScopeID: "eng", FindingFingerprint: "f", SourceSHA256: digest, ContextSHA256: digest, ProposerProvider: "p", ProposerModel: "m", PromptVersion: "fp-triage-v3", PolicyVersion: "policy"}
	decision := ports.FPTriageCachedDecision{Verdict: "sound", Driver: "attacker_controlled", Confidence: 80, EvidenceTokens: []string{"ev:cwe"}}
	cache := New(t.TempDir())
	if err := cache.Store(context.Background(), key, decision); err != nil {
		t.Fatal(err)
	}
	got, ok, err := cache.Load(context.Background(), key)
	if err != nil || !ok || len(got.EvidenceTokens) != 1 || got.EvidenceTokens[0] != "ev:cwe" {
		t.Fatalf("roundtrip ok=%v err=%v got=%+v", ok, err, got)
	}
}

func TestCacheRejectsDuplicateEvidenceCitations(t *testing.T) {
	h := sha256.Sum256([]byte("x"))
	digest := hex.EncodeToString(h[:])
	key := ports.FPTriageCacheKey{TenantID: "tenant", ScopeID: "eng", FindingFingerprint: "f", SourceSHA256: digest, ContextSHA256: digest, ProposerProvider: "p", ProposerModel: "m", PromptVersion: "fp-triage-v3", PolicyVersion: "policy"}
	decision := ports.FPTriageCachedDecision{Verdict: "sound", Driver: "attacker_controlled", Confidence: 80, EvidenceTokens: []string{"ev:cwe", "ev:cwe"}}
	if err := New(t.TempDir()).Store(context.Background(), key, decision); err == nil {
		t.Fatal("duplicate citations cached")
	}
}

func TestCacheRejectsMalformedEvidenceCitationIDs(t *testing.T) {
	h := sha256.Sum256([]byte("x"))
	digest := hex.EncodeToString(h[:])
	key := ports.FPTriageCacheKey{TenantID: "tenant", ScopeID: "eng", FindingFingerprint: "f", SourceSHA256: digest, ContextSHA256: digest, ProposerProvider: "p", ProposerModel: "m", PromptVersion: "fp-triage-v3", PolicyVersion: "policy"}
	for _, id := range []string{"ev:bad-id", "ev:", " ev:cwe", "ev:cwe ", "ev:CWE"} {
		decision := ports.FPTriageCachedDecision{Verdict: "sound", Driver: "attacker_controlled", Confidence: 80, EvidenceTokens: []string{id}}
		if err := New(t.TempDir()).Store(context.Background(), key, decision); err == nil {
			t.Fatalf("malformed evidence citation %q was cached", id)
		}
	}
}
