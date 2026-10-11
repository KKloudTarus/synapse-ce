package siemuc

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

func TestSentinelClientSecretIsKnownToExporterScrubber(t *testing.T) {
	const credential = `{"tenant_id":"11111111-1111-4111-8111-111111111111","client_id":"22222222-2222-4222-8222-222222222222","client_secret":"sentinel-client-secret"}`

	known := redactionSecrets(siem.ProviderMicrosoftSentinel, credential)
	exported := siem.ExportAudit("tenant-a", siem.AuditFact{
		ID: 1, Action: "siem.test", Severity: "info", AtUnixMicro: 1_790_000_000_000_000,
		Hash: "hash-1", HashVersion: 2, Actor: "sentinel-client-secret", Title: "sentinel-client-secret",
	}, siem.ClassSummary, known, "")
	if exported.Disposition != siem.ItemPending {
		t.Fatalf("export disposition = %s", exported.Disposition)
	}
	got := string(exported.Body)
	if strings.Contains(got, "sentinel-client-secret") {
		t.Fatalf("client secret was not scrubbed from exported payload: %q", got)
	}
	if !strings.Contains(got, privacy.RedactionPlaceholder) {
		t.Fatalf("exported payload omitted the redaction marker: %q", got)
	}
}

func TestOpaqueProviderSecretRedactionIsUnchanged(t *testing.T) {
	const secret = "splunk-token-value"
	known := redactionSecrets(siem.ProviderSplunk, secret)
	if len(known) != 1 || known[0] != secret {
		t.Fatalf("known secrets = %#v", known)
	}
}
