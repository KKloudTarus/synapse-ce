package egressbroker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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

func TestGrantSupportsFencedScanExecutionIdentity(t *testing.T) {
	execution := ports.DASTScanExecution{
		TenantID: shared.ID(strings.Repeat("t", 200)),
		RunID:    shared.ID(strings.Repeat("r", 32)),
		JobID:    strings.Repeat("r", 32) + "-job",
		Fence:    1 << 62,
	}
	id, err := execution.ExecutionID()
	if err != nil {
		t.Fatal(err)
	}
	var seed [ed25519.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	signer, err := NewGrantSigner(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	req := GrantRequest{TenantID: execution.TenantID.String(), ExecutionKind: "dast-session", ExecutionID: id, RunID: "syn1", PID: 1234}
	token, err := signer.Sign(req, now, time.Minute)
	if err != nil {
		t.Fatalf("valid full fenced identity cannot receive a grant: %v", err)
	}
	verifier, err := NewGrantVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(token, now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ports.ParseDASTScanExecutionID(claims.ExecutionID)
	if err != nil || decoded != execution {
		t.Fatalf("signed claim lost execution ownership: %+v %v", decoded, err)
	}
	wire := request{Version: protocolVersion, Action: "setup", TenantID: req.TenantID, ExecutionKind: req.ExecutionKind, ExecutionID: id, RunID: req.RunID, PID: req.PID, Grant: token}
	if err := validateRequest(wire); err != nil {
		t.Fatalf("valid full fenced identity rejected on broker wire: %v", err)
	}
	req.ExecutionID = strings.Repeat("x", 1025)
	if _, err := signer.Sign(req, now, time.Minute); err == nil {
		t.Fatal("unbounded execution identity was signed")
	}
	wire.ExecutionID = req.ExecutionID
	if err := validateRequest(wire); err == nil {
		t.Fatal("unbounded execution identity reached broker setup")
	}
}
