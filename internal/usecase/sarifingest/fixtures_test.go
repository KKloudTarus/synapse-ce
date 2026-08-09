package sarifingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestRealToolFixtures ingests SARIF as three real scanners emit it. Each exercises a different shape:
// CodeQL addresses its rule by index and carries a CVSS-style security-severity, semgrep uses a
// tool-specific problem.severity, and Trivy attaches a logical location instead of a source symbol.
func TestRealToolFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		file         string
		wantTool     string
		wantRule     string
		wantSeverity shared.Severity
		wantPath     string
	}{
		{file: "codeql.sarif", wantTool: "CodeQL", wantRule: "go/sql-injection", wantSeverity: shared.SeverityHigh, wantPath: "internal/store/query.go"},
		{file: "semgrep.sarif", wantTool: "semgrep", wantRule: "go.lang.security.audit.crypto.use-of-md5", wantSeverity: shared.SeverityMedium, wantPath: "pkg/hash/legacy.go"},
		{file: "trivy.sarif", wantTool: "Trivy", wantRule: "CVE-2023-44487", wantSeverity: shared.SeverityHigh, wantPath: "go.sum"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.file, func(t *testing.T) {
			t.Parallel()
			document, err := os.ReadFile(filepath.Join("testdata", test.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			svc, store, _ := newService(t)
			result, err := svc.Ingest(context.Background(), IngestRequest{
				TenantID: "t1", EngagementID: "eng1", Document: document, Actor: "human:alice",
			})
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			if result.Accepted != 1 || len(result.Refused) != 0 {
				t.Fatalf("expected a clean single-result ingest, got %+v", result)
			}
			stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
			got := stored[0]
			if got.Provenance.ToolName != test.wantTool {
				t.Errorf("tool = %q, want %q", got.Provenance.ToolName, test.wantTool)
			}
			if got.Provenance.RuleID != test.wantRule {
				t.Errorf("rule = %q, want %q", got.Provenance.RuleID, test.wantRule)
			}
			if got.Severity != test.wantSeverity {
				t.Errorf("severity = %q, want %q", got.Severity, test.wantSeverity)
			}
			if got.Location.Path != test.wantPath {
				t.Errorf("path = %q, want %q", got.Location.Path, test.wantPath)
			}
			if got.Provenance.ToolVersion == "" {
				t.Error("tool version must be recorded")
			}
		})
	}
}
