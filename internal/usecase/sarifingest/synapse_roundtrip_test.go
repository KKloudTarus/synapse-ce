package sarifingest

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	exportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/export"
)

// synapse-cli scan --server --engagement pushes its own SARIF through this ingest. A decision recorded
// against one of those observations is keyed on its cross-import identity, so that identity must be the
// same when a later run pushes the same finding again, from another runner and another checkout path.
// The fingerprint the export writes is what carries it.
func TestSynapseSARIFKeepsItsIdentityAcrossReimports(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{ID: "v1", Title: "CVE-2020-15250 in junit:junit@4.12", Severity: shared.SeverityMedium, Status: finding.StatusOpen, Kind: finding.KindSCA, DedupKey: "vuln:CVE-2020-15250:junit:junit:4.12"},
		{ID: "s1", Title: "Database connection string with credentials (src/Db.java:2)", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSecret, RuleKey: "db-connection-string", DedupKey: "secret:db-connection-string:src/Db.java:2", SourceLocation: &finding.SourceLocation{File: "src/Db.java", StartLine: 2, EndLine: 2}},
	}
	manifest := func(f finding.Finding) string {
		if strings.HasPrefix(f.DedupKey, "vuln:") {
			return "svc/pom.xml"
		}
		return ""
	}
	identities := func(version string) map[string]string {
		t.Helper()
		doc, err := exportuc.MarshalSARIF(findings, version, exportuc.SARIFOptions{Manifest: manifest})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		svc, store, _ := newService(t)
		if result, err := ingest(t, svc, string(doc)); err != nil || result.Accepted != len(findings) {
			t.Fatalf("ingest: result=%+v err=%v", result, err)
		}
		stored, err := store.ListByEngagement(context.Background(), "t1", "eng1")
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, imported := range stored {
			if imported.Fingerprint == "" {
				t.Errorf("rule %q was stored without the fingerprint the export wrote", imported.Provenance.RuleID)
			}
			identity := imported.BindingExternalIdentity()
			if !strings.HasPrefix(identity, "fingerprint:") {
				t.Errorf("rule %q: binding identity %q is derived from rule and location, not from the fingerprint", imported.Provenance.RuleID, identity)
			}
			out[imported.Provenance.RuleID] = identity
		}
		return out
	}

	// Two runs of different builds produce documents with different digests, so the second import stores new
	// rows rather than deduplicating the first. Their identities must still match.
	first, second := identities("v1.0.0"), identities("v1.1.0")
	if len(first) != len(findings) {
		t.Fatalf("identities = %v, want one per finding", first)
	}
	for rule, identity := range first {
		if second[rule] != identity {
			t.Errorf("rule %q: identity %q in the first import and %q in the second", rule, identity, second[rule])
		}
	}
	if first["CVE-2020-15250"] == first["db-connection-string"] {
		t.Errorf("two different findings share the identity %q", first["CVE-2020-15250"])
	}
}
