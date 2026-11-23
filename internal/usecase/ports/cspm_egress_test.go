package ports

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
)

func TestCSPMExecutionIDRejectsNonCanonicalIndexes(t *testing.T) {
	for _, id := range []string{"cspm/v1/run/01", "cspm/v1/run/-1", "cspm/v1/run/1/extra", "cspm/v1//1", "cspm/v2/run/1"} {
		if _, _, err := ParseCSPMExecutionID(id); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	run, n, err := ParseCSPMExecutionID(CSPMExecutionID("run", 1))
	if err != nil || run != "run" || n != 1 {
		t.Fatalf("run=%s index=%d err=%v", run, n, err)
	}
}
func TestCSPMEgressPolicyRejectsNonHostEntries(t *testing.T) {
	for _, host := range []string{"*.example.com", "https://example.com", "example.com:443", "127.0.0.1", "[::1]", "bad..example", "EXAMPLE.COM"} {
		if _, err := CSPMEgressPolicy(cloudposture.ProviderAzure, []string{host}); err == nil {
			t.Fatalf("accepted %q", host)
		}
	}
	p, err := CSPMEgressPolicy(cloudposture.ProviderAzure, []string{"management.azure.com"})
	if err != nil || len(p.AllowDomainRules) != 1 || p.AllowDomainRules[0].Ports[0] != 443 {
		t.Fatalf("policy=%+v err=%v", p, err)
	}
}
