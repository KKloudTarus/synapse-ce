package postgres

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// fakeRow feeds scanImportedFinding a positional row, so the projection's column ORDER is checked
// without a database. The integration test that needs one is skipped in normal CI, which is exactly
// where a silently reordered column would otherwise live.
type fakeRow struct{ values []any }

func (r fakeRow) Scan(dest ...any) error {
	if len(dest) != len(r.values) {
		return fmt.Errorf("scan wants %d destinations, row has %d", len(dest), len(r.values))
	}
	for i, value := range r.values {
		switch target := dest[i].(type) {
		case *string:
			*target = value.(string)
		case *int:
			*target = value.(int)
		case *bool:
			*target = value.(bool)
		case *time.Time:
			*target = value.(time.Time)
		default:
			return fmt.Errorf("unsupported destination %T at position %d", dest[i], i)
		}
	}
	return nil
}

// TestScanImportedFindingMatchesTheProjection asserts the scan destinations line up with
// importedFindingCols one for one. A column inserted in the middle of that constant without a matching
// destination would otherwise put the tool name in the rule field — provenance silently rearranged.
func TestScanImportedFindingMatchesTheProjection(t *testing.T) {
	t.Parallel()

	columns := strings.Split(importedFindingCols, ", ")
	ingestedAt := time.Unix(1700000000, 0).UTC()
	createdAt := time.Unix(1700000001, 0).UTC()
	values := []any{
		"if-1", "t1", "eng-1", "f-9", "high", "Injection", "message body",
		"src/app.go", 42, 7, "Pkg.Method", true, "fp-1", "semgrep", "1.2.3", "rule.a",
		"digest-a", "human:alice", ingestedAt, createdAt, createdAt,
	}
	if len(values) != len(columns) {
		t.Fatalf("the fixture has %d values for %d projected columns (%v)", len(values), len(columns), columns)
	}

	got, err := scanImportedFinding(fakeRow{values: values})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Each assertion pins one column to the field it must land in.
	checks := []struct {
		column string
		got    any
		want   any
	}{
		{"id", got.ID, shared.ID("if-1")},
		{"tenant_id", got.TenantID, shared.ID("t1")},
		{"engagement_id", got.EngagementID, shared.ID("eng-1")},
		{"finding_id", got.FindingID, shared.ID("f-9")},
		{"severity", got.Severity, shared.SeverityHigh},
		{"title", got.Title, "Injection"},
		{"message", got.Message, "message body"},
		{"path", got.Location.Path, "src/app.go"},
		{"start_line", got.Location.StartLine, 42},
		{"start_column", got.Location.StartColumn, 7},
		{"logical_name", got.Location.LogicalName, "Pkg.Method"},
		{"suppressed", got.Suppressed, true},
		{"fingerprint", got.Fingerprint, "fp-1"},
		{"tool_name", got.Provenance.ToolName, "semgrep"},
		{"tool_version", got.Provenance.ToolVersion, "1.2.3"},
		{"rule_id", got.Provenance.RuleID, "rule.a"},
		{"source_digest", got.Provenance.SourceDigest, "digest-a"},
		{"ingested_by", got.Provenance.IngestedBy, shared.ID("human:alice")},
		{"ingested_at", got.Provenance.IngestedAt, ingestedAt},
		{"created_at", got.Audit.CreatedAt, createdAt},
		{"updated_at", got.Audit.UpdatedAt, createdAt},
	}
	if len(checks) != len(columns) {
		t.Fatalf("%d columns are projected but only %d are asserted", len(columns), len(checks))
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Fatalf("column %s landed as %v, want %v", check.column, check.got, check.want)
		}
	}

	// The scanned row must be a valid domain object: the projection is what a reader gets back.
	if err := got.Validate(); err != nil {
		t.Fatalf("a scanned finding must satisfy the domain invariants: %v", err)
	}
}
