package dastsession

import (
	"context"
	"net/url"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egressbroker"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestSessionEgressPolicyEnforcesLiteralOriginPort(t *testing.T) {
	target, err := url.Parse("https://203.0.113.10:8443")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := sessionEgressPolicy(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := (egressbroker.EgressGrantCanonicalizer{}).Canonicalize(context.Background(), *policy)
	if err != nil {
		t.Fatalf("approved literal origin cannot reach signed policy boundary: %v", err)
	}
	want := []ports.CanonicalEgressRule{{Allow: true, CIDR: "203.0.113.10/32", Ports: []uint16{8443}}}
	if !ports.CanonicalEgressRulesEqual(rules, want) {
		t.Fatalf("literal-origin permission changed: got %+v, want %+v", rules, want)
	}
}
