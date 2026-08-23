package egressbroker

import (
	"context"
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEgressGrantCanonicalizerUsesBrokerCanonicalContract(t *testing.T) {
	rules, err := (EgressGrantCanonicalizer{}).Canonicalize(context.Background(), ports.EgressPolicy{Rules: []ports.EgressRule{
		{Allow: true, Net: netip.MustParsePrefix("203.0.113.0/24"), Ports: []uint16{443}},
		{Allow: false, Net: netip.MustParsePrefix("198.51.100.0/24")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Allow || rules[0].CIDR != "198.51.100.0/24" || !rules[1].Allow || rules[1].CIDR != "203.0.113.0/24" {
		t.Fatalf("canonical rules = %+v", rules)
	}
}

func TestEgressGrantSignerPreservesAuthorityBinding(t *testing.T) {
	brokerSigner, err := NewGrantSigner(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewEgressGrantSigner(brokerSigner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	req := ports.EgressGrantRequest{
		TenantID:      "tenant-test",
		ExecutionKind: "recon",
		ExecutionID:   "run-1",
		RunID:         "syn1",
		Slot:          1,
		PID:           1234,
		Rules:         []ports.CanonicalEgressRule{{Allow: true, CIDR: "203.0.113.0/24", Ports: []uint16{443}}},
	}
	token, err := adapter.Sign(req, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewGrantVerifier(brokerSigner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(token, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.TenantID != req.TenantID || claims.ExecutionKind != req.ExecutionKind || claims.ExecutionID != req.ExecutionID || claims.RunID != req.RunID || claims.Slot != req.Slot || claims.PID != req.PID {
		t.Fatalf("claims = %+v", claims)
	}
}
