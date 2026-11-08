package egressgrant

import (
	"context"
	"net/url"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egressbroker"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestDASTOriginAuthorityPreservesLiteralIPAndPort(t *testing.T) {
	for _, test := range []struct {
		origin string
		port   uint16
	}{
		{origin: "https://203.0.113.10", port: 443},
		{origin: "https://203.0.113.10:8443", port: 8443},
	} {
		t.Run(test.origin, func(t *testing.T) {
			origin, err := url.Parse(test.origin)
			if err != nil {
				t.Fatal(err)
			}
			rules, err := (egressbroker.EgressGrantCanonicalizer{}).Canonicalize(context.Background(), dastOriginPolicy(origin))
			if err != nil {
				t.Fatalf("approved literal origin could not be independently authorized: %v", err)
			}
			want := []ports.CanonicalEgressRule{{Allow: true, CIDR: "203.0.113.10/32", Ports: []uint16{test.port}}}
			if !ports.CanonicalEgressRulesEqual(rules, want) {
				t.Fatalf("origin authority broadened: got %+v, want %+v", rules, want)
			}
		})
	}
}
