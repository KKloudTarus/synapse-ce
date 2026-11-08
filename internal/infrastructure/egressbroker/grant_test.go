package egressbroker

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestGrantSignerBindsRequestAndExpires(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	signer, err := NewGrantSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewGrantVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	req := GrantRequest{
		TenantID:      "tenant-test",
		ExecutionKind: "recon",
		ExecutionID:   "job-1",
		RunID:         "syn1",
		Slot:          1,
		PID:           1234,
		Rules:         []CanonicalRule{{Allow: true, CIDR: "203.0.113.0/24", Ports: []uint16{443}}},
	}
	token, err := signer.Sign(req, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(token, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claims.TenantID != req.TenantID || claims.ExecutionKind != req.ExecutionKind || claims.ExecutionID != req.ExecutionID || claims.RunID != req.RunID || claims.Slot != req.Slot || claims.PID != req.PID || !CanonicalRulesEqual(claims.Rules, req.Rules) {
		t.Fatalf("claims = %+v, want request binding", claims)
	}
	if _, err := verifier.Verify(token, now.Add(time.Minute)); err == nil {
		t.Fatal("expired grant must be rejected")
	}
}

func TestGrantVerifierRejectsTampering(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	signer, err := NewGrantSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewGrantVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	token, err := signer.Sign(GrantRequest{TenantID: "tenant-test", ExecutionKind: "recon", ExecutionID: "job-1", RunID: "syn1", Slot: 1, PID: 1234}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	payload[0] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1]
	if _, err := verifier.Verify(tampered, now); err == nil {
		t.Fatal("tampered grant must be rejected")
	}
}
