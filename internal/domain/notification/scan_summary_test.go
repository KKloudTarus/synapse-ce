package notification

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func scanFinding(id string, severity shared.Severity) finding.Finding {
	return finding.Finding{ID: shared.ID(id), DedupKey: id, Kind: finding.KindSCA, Severity: severity, Title: "finding " + id, Status: finding.StatusOpen}
}

func TestScanSummaryPresentationIsIndependentOfObservationOrder(t *testing.T) {
	severities := []shared.Severity{shared.SeverityInfo, shared.SeverityLow, shared.SeverityMedium, shared.SeverityHigh, shared.SeverityCritical}
	input := make([]finding.Finding, 120)
	for i := range input {
		input[i] = scanFinding(fmt.Sprintf("finding-%03d", i), severities[i%len(severities)])
	}
	want := NewScanSummary("target", "git", true, input)
	random := rand.New(rand.NewPCG(17, 29))
	for range 8 {
		shuffled := append([]finding.Finding(nil), input...)
		random.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got := NewScanSummary("target", "git", true, shuffled)
		if !reflect.DeepEqual(got, want) || len(got.Findings) != 50 || got.Total != 120 {
			t.Fatal("presentation or exact counts depend on observation order")
		}
	}
}

func TestScanSummaryScrubsSecretsBeforeBoundingPresentation(t *testing.T) {
	item := scanFinding("safe-id", shared.SeverityHigh)
	item.Title = "Key -----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("MIIEow", 300) + "\n-----END RSA PRIVATE KEY----- committed"
	summary := NewScanSummary("target", "git", true, []finding.Finding{item})
	if got := summary.Findings[0].Title; got != "Key [redacted] committed" {
		t.Fatalf("persisted presentation = %q, want scrubbed full key before truncation", got)
	}
	item.Title = "pass" + string(rune(0x200b)) + "word=Hunter2!"
	if got := NewScanSummary("target", "git", true, []finding.Finding{item}).Findings[0].Title; got != "password=[redacted]" {
		t.Fatalf("sanitized presentation = %q", got)
	}
	item.Title = "Clone from https://" + strings.Repeat("token", 300) + "@git.example.test/repo failed"
	if got := NewScanSummary("target", "git", true, []finding.Finding{item}).Findings[0].Title; got != "Clone from https://***@git.example.test/repo failed" {
		t.Fatalf("token-only URL was truncated before scrubbing: %q", got)
	}
}

func TestScanSummaryComparesOnlyCompatibleCompleteSnapshots(t *testing.T) {
	previous := NewScanSummary("target", "sast", true, []finding.Finding{scanFinding("same", shared.SeverityHigh), scanFinding("fixed", shared.SeverityLow)})
	current := NewScanSummary("target", "sast", true, []finding.Finding{scanFinding("same", shared.SeverityHigh), scanFinding("new", shared.SeverityCritical)}).WithBaselineID(previous, "scan-prior")
	if !current.DeltaAvailable || current.New != 1 || current.Fixed != 1 || current.Unchanged != 1 || current.BaselineJobID != "scan-prior" {
		t.Fatalf("comparison = %+v", current)
	}
	for _, incompatible := range []ScanSummary{
		NewScanSummary("other", "sast", true, nil),
		NewScanSummary("target", "dast", true, nil),
		NewScanSummary("target", "sast", false, nil),
	} {
		if got := incompatible.WithBaseline(previous); got.DeltaAvailable {
			t.Fatalf("incompatible comparison became available: %+v", got)
		}
	}
}

func TestScanSummaryDeduplicatesAndBoundsTemplateItems(t *testing.T) {
	items := []finding.Finding{scanFinding("same", shared.SeverityHigh), scanFinding("same", shared.SeverityHigh)}
	for i := 0; i < 60; i++ {
		items = append(items, scanFinding(fmt.Sprintf("id-%03d", i), shared.SeverityInfo))
	}
	summary := NewScanSummary("target", "sast", true, items)
	if summary.Total != 61 || len(summary.Keys) != 61 {
		t.Fatalf("deduped counts = total=%d keys=%d", summary.Total, len(summary.Keys))
	}
	_, lists := summary.TemplateValues()
	if len(lists["findings"]) != 50 {
		t.Fatalf("template items = %d, want 50", len(lists["findings"]))
	}
	if _, leaked := lists["findings"][0]["identity"]; leaked {
		t.Fatal("internal identity leaked into template list")
	}
}

func TestScanSummaryTruncationNeverClaimsDelta(t *testing.T) {
	items := make([]finding.Finding, maxScanSummaryFindings+1)
	for i := range items {
		items[i] = scanFinding(fmt.Sprintf("id-%05d", i), shared.SeverityLow)
	}
	items[len(items)-1] = scanFinding("late-critical", shared.SeverityCritical)
	current := NewScanSummary("target", "sast", true, items)
	if !current.Truncated || len(current.Keys) != maxScanSummaryFindings {
		t.Fatalf("snapshot bound = %+v", current)
	}
	if current.WithBaseline(NewScanSummary("target", "sast", true, nil)).DeltaAvailable {
		t.Fatal("truncated summary reported a delta")
	}
	if current.Findings[0].Identity != "late-critical" {
		t.Fatalf("top presentation item = %+v, want late critical finding", current.Findings[0])
	}
}

func TestScanSummaryWithoutStableKeysNeverClaimsDelta(t *testing.T) {
	previous := NewScanSummary("target", "sast", true, []finding.Finding{{ID: "old", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
	current := NewScanSummary("target", "sast", true, []finding.Finding{{ID: "new", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
	if !previous.Unstable || current.WithBaseline(previous).DeltaAvailable {
		t.Fatal("per-run finding IDs must not establish a scan delta")
	}
}
