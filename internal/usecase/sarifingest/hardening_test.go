package sarifingest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestPercentEncodedLocationsAreDecodedBeforeTheyAreChecked is the regression for the traversal bypass:
// SARIF requires artifactLocation.uri to be percent-ENCODED, so a guard that runs path.Clean on the
// still-encoded string sees one harmless segment and lets `%2e%2e%2f` straight through.
func TestPercentEncodedLocationsAreDecodedBeforeTheyAreChecked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uri  string
		want importedfinding.RefusalCode
	}{
		{"fully encoded traversal", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", importedfinding.RefusalPathTraversal},
		{"mixed encoded traversal", "%2e%2e/%2e%2e/etc/passwd", importedfinding.RefusalPathTraversal},
		{"encoded separator only", "..%2fsecret", importedfinding.RefusalPathTraversal},
		{"encoded absolute", "%2Fetc%2Fpasswd", importedfinding.RefusalAbsolutePath},
		{"encoded absolute lowercase", "%2fetc%2fpasswd", importedfinding.RefusalAbsolutePath},
		{"double encoded traversal", "%252e%252e%252fetc", importedfinding.RefusalInvalidLocation},
		{"encoded scheme", "https%3A%2F%2Fevil.example%2Fx", importedfinding.RefusalUnsupportedURI},
		{"encoded nul", "src%2Fapp%00.go", importedfinding.RefusalInvalidLocation},
		{"encoded escape sequence", "src%2F%1b%5b31mapp.go", importedfinding.RefusalInvalidLocation},
		{"remote file authority", "file://evil.example/etc/passwd", importedfinding.RefusalUnsupportedURI},
		{"remote file authority, encoded path", "file://evil.example/%2e%2e/x", importedfinding.RefusalUnsupportedURI},
		{"localhost file authority stays absolute", "file://localhost/etc/passwd", importedfinding.RefusalAbsolutePath},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, code := normalizeArtifactURI(test.uri)
			if code != test.want {
				t.Fatalf("normalizeArtifactURI(%q) = (%q, %q), want refusal %q", test.uri, got, code, test.want)
			}
		})
	}
}

// A legitimately encoded path must still resolve, otherwise every file with a space in its name would be
// silently mismatched against the first-party finding at the decoded path.
func TestLegitimatePercentEncodingIsDecodedNotRefused(t *testing.T) {
	t.Parallel()

	tests := []struct{ uri, want string }{
		{"src/my%20file.go", "src/my file.go"},
		{"src%2Fnested%2Fapp.go", "src/nested/app.go"},
		{"file://localhost/../..", ""}, // absolute → refused, asserted by code below
		{"./src/app.go", "src/app.go"},
		{"src/./a/../b.go", "src/b.go"},
	}
	for _, test := range tests {
		got, code := normalizeArtifactURI(test.uri)
		if test.want == "" {
			if code == "" {
				t.Fatalf("normalizeArtifactURI(%q) = %q, expected a refusal", test.uri, got)
			}
			continue
		}
		if code != "" || got != test.want {
			t.Fatalf("normalizeArtifactURI(%q) = (%q, %q), want %q", test.uri, got, code, test.want)
		}
	}
}

// TestUnknownURIBaseIsRefused is the regression for a location expressed relative to a base OUTSIDE the
// scanned tree being relabelled as repository-relative — and for two distinct results under different
// bases collapsing onto one idempotency key.
func TestUnknownURIBaseIsRefused(t *testing.T) {
	t.Parallel()

	doc := docWith(`{"ruleId":"rule.a","level":"error","message":{"text":"x"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":".ssh/id_rsa","uriBaseId":"HOME"},"region":{"startLine":1}}}]}`)
	svc, store, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted != 0 || len(result.Refused) != 1 {
		t.Fatalf("a location relative to a non-root base must be refused, got %+v", result)
	}
	if result.Refused[0].Code != importedfinding.RefusalUnsupportedURIBase {
		t.Fatalf("refusal code = %q, want unsupported-uri-base", result.Refused[0].Code)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 0 {
		t.Fatalf("nothing must be stored for a refused location, got %d", len(stored))
	}

	// %SRCROOT% — the base CodeQL emits — is the repository root and must be accepted.
	accepted := docWith(`{"ruleId":"rule.a","level":"error","message":{"text":"x"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.go","uriBaseId":"%SRCROOT%"},"region":{"startLine":1}}}]}`)
	svc2, _, _ := newService(t)
	ok, err := ingest(t, svc2, accepted)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if ok.Accepted != 1 {
		t.Fatalf("%%SRCROOT%% is the repository root and must be accepted, got %+v", ok)
	}
}

// TestNegativeRegionIsRefusedNotClamped locks that a nonsensical position is refused rather than silently
// rewritten to line 0, which would move the finding to a location the tool never reported.
func TestNegativeRegionIsRefusedNotClamped(t *testing.T) {
	t.Parallel()

	doc := docWith(`{"ruleId":"rule.a","level":"error","message":{"text":"x"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":-5}}}]}`)
	svc, _, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Refused) != 1 || result.Refused[0].Code != importedfinding.RefusalInvalidLocation {
		t.Fatalf("a negative region must be refused, got %+v", result.Refused)
	}
}

// TestStoredTextIsSanitizedAndCapped is the regression for storing untrusted tool text verbatim: control
// bytes, ANSI introducers and bidi overrides must not survive into the row that the report path, the UI
// and the CSV export all read.
func TestStoredTextIsSanitizedAndCapped(t *testing.T) {
	t.Parallel()

	// A title carrying an ANSI CSI sequence, a message carrying a right-to-left override and a NUL in
	// the rule id — each of which a naive renderer would execute or misdisplay.
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"tool","version":"1",
		"rules":[{"id":"rule.a","shortDescription":{"text":"safe\u001b[31m red \u0007title"}}]}},
		"results":[{"ruleId":"rule.a","level":"error",
		  "message":{"text":"before \u202e after \u0000 nul"},
		  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`
	svc, store, _ := newService(t)
	if _, err := ingest(t, svc, doc); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 1 {
		t.Fatalf("expected one finding, got %d", len(stored))
	}
	got := stored[0]
	for _, field := range []string{got.Title, got.Message, got.Provenance.RuleID} {
		for _, r := range field {
			if r < 0x20 && r != '\n' && r != '\t' {
				t.Fatalf("a C0 control byte %U survived into stored text %q", r, field)
			}
			if r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiOrZeroWidth(r) {
				t.Fatalf("a control or bidi rune %U survived into stored text %q", r, field)
			}
		}
	}
	if !strings.Contains(got.Title, "red") || !strings.Contains(got.Message, "after") {
		t.Fatalf("sanitizing must strip the controls, not the words: %+v", got)
	}
}

func TestOverlongTextIsTruncatedAndDisclosed(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("A", maxMessageBytes+500)
	doc := docWith(`{"ruleId":"rule.a","level":"error","message":{"text":"` + long + `"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}`)
	svc, store, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored[0].Message) > maxMessageBytes {
		t.Fatalf("stored message is %d bytes, over the %d bound", len(stored[0].Message), maxMessageBytes)
	}
	// Truncation is DISCLOSED. A silently shortened message presented as the tool's own words is the
	// same failure mode as a silent refusal.
	if len(result.Coverage) == 0 {
		t.Fatal("truncating stored text must be reported as a coverage issue, not applied silently")
	}
	found := false
	for _, issue := range result.Coverage {
		if strings.Contains(issue.Detail, "truncated") {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage must name the truncation, got %+v", result.Coverage)
	}
}

// TestCoverageReportsWhatCouldNotBeRepresented locks that an unmappable severity and a recorded
// suppression are both surfaced rather than left for the reader to infer.
func TestCoverageReportsWhatCouldNotBeRepresented(t *testing.T) {
	t.Parallel()

	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"tool","version":"1",
		"rules":[{"id":"rule.x"}]}},
		"results":[{"ruleId":"rule.x","message":{"text":"x"},"suppressions":[{"kind":"external"}],
		  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`
	svc, _, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	joined := ""
	for _, issue := range result.Coverage {
		joined += issue.Detail + "\n"
	}
	if !strings.Contains(joined, "unknown") {
		t.Fatalf("an unmappable severity must be disclosed, got %q", joined)
	}
	if !strings.Contains(joined, "suppressed") {
		t.Fatalf("a recorded-but-not-obeyed suppression must be disclosed, got %q", joined)
	}
}

// TestRuleIndexResolvesInDocumentOrder locks BOTH the correctness fix (ruleIndex addresses the rules
// array, not a sorted key set) and the absence of the per-result insertion sort that made it quadratic.
func TestRuleIndexResolvesInDocumentOrder(t *testing.T) {
	t.Parallel()

	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"tool","version":"1",
		"rules":[{"id":"zeta"},{"id":"alpha"}]}},
		"results":[{"ruleIndex":0,"level":"error","message":{"text":"x"},
		  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`
	svc, store, _ := newService(t)
	if _, err := ingest(t, svc, doc); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if stored[0].Provenance.RuleID != "zeta" {
		t.Fatalf("ruleIndex 0 must resolve to the FIRST declared rule, got %q", stored[0].Provenance.RuleID)
	}
}

// TestLargeRuleTableWithIndexedResultsStaysLinear is the regression for the CPU exhaustion: rebuilding
// and insertion-sorting the rule ids per result made one request ~O(results x rules^2). With the ids
// computed once per run this completes in well under a second; before the fix it did not finish.
func TestLargeRuleTableWithIndexedResultsStaysLinear(t *testing.T) {
	t.Parallel()

	const rules, results = 2000, 20000
	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"tool","version":"1","rules":[`)
	for i := 0; i < rules; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":"r`)
		b.WriteString(pad(i))
		b.WriteString(`"}`)
	}
	b.WriteString(`]}},"results":[`)
	for i := 0; i < results; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"ruleIndex":0,"level":"error","message":{"text":"x"}}`)
	}
	b.WriteString(`]}]}`)

	parsedDoc, err := parseDocument(context.Background(), []byte(b.String()), DefaultLimits())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsedDoc.results) != results {
		t.Fatalf("expected %d candidates, got %d", results, len(parsedDoc.results))
	}
}

func pad(n int) string {
	s := ""
	for i := 0; i < 5; i++ {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// TestResultBoundAbortsBeforeDecodingTheRest is the regression for the memory amplification: the result
// budget is enforced WHILE streaming, so a document that fits the byte bound cannot first be expanded
// into millions of Go values and only then rejected.
func TestResultBoundAbortsBeforeDecodingTheRest(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","version":"1"}},"results":[`)
	for i := 0; i < 50000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"ruleId":"a","level":"error"}`)
	}
	b.WriteString(`]}]}`)

	limits := DefaultLimits()
	limits.MaxResults = 10
	if _, err := parseDocument(context.Background(), []byte(b.String()), limits); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("exceeding the result bound must be a typed error, got %v", err)
	}
}

// TestParseHonoursCancellation locks that a disconnected client stops the parser instead of leaving it
// to run a large document to completion.
func TestParseHonoursCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseDocument(ctx, []byte(docWith(resultA)), DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context must stop the parse, got %v", err)
	}
}

// TestUnreadMembersAreSkippedNotMaterialised locks the streaming walk: a member this ingester does not
// read must cost nothing, and must not break parsing of the members it does read.
func TestUnreadMembersAreSkippedNotMaterialised(t *testing.T) {
	t.Parallel()

	filler := strings.Repeat(`"x",`, 20000) + `"x"`
	doc := `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json",
		"inlineExternalProperties":[{"noise":[` + filler + `]}],
		"version":"2.1.0",
		"runs":[{"invocations":[{"noise":[` + filler + `]}],
		 "tool":{"driver":{"name":"tool","version":"1","rules":[{"id":"rule.a"}]}},
		 "results":[{"ruleId":"rule.a","level":"error","message":{"text":"x"},
		   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`
	svc, _, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted != 1 {
		t.Fatalf("unread members must not affect the read ones, got %+v", result)
	}
}

// TestResultsBeforeToolStillResolveRules covers the key order JSON does not guarantee.
func TestResultsBeforeToolStillResolveRules(t *testing.T) {
	t.Parallel()

	doc := `{"version":"2.1.0","runs":[{
		"results":[{"ruleIndex":0,"level":"error","message":{"text":"x"},
		  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}],
		"tool":{"driver":{"name":"tool","version":"1","rules":[{"id":"rule.z"}]}}}]}`
	svc, store, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted != 1 {
		t.Fatalf("results declared before tool must still resolve, got %+v", result)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if stored[0].Provenance.RuleID != "rule.z" {
		t.Fatalf("rule id = %q, want rule.z", stored[0].Provenance.RuleID)
	}
}

// TestNaNSecuritySeverityIsUnknownNotInfo is the regression for ParseFloat accepting "NaN": every band
// comparison is false for NaN, so a range guard alone let an unassessable value fall through to a
// concrete severity.
func TestNaNSecuritySeverityIsUnknownNotInfo(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"NaN", "nan", "-nan"} {
		if got := mapSecuritySeverity(raw); got != shared.SeverityUnknown {
			t.Fatalf("mapSecuritySeverity(%q) = %q, want unknown — an unassessable score must never become a level", raw, got)
		}
	}
	// The bands themselves must keep working.
	for raw, want := range map[string]shared.Severity{
		"9.8": shared.SeverityCritical, "7.5": shared.SeverityHigh,
		"5.0": shared.SeverityMedium, "0.5": shared.SeverityLow, "0": shared.SeverityInfo,
		"11": shared.SeverityUnknown, "-1": shared.SeverityUnknown, "Inf": shared.SeverityUnknown,
	} {
		if got := mapSecuritySeverity(raw); got != want {
			t.Fatalf("mapSecuritySeverity(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestVersionErrorDoesNotReflectTheWholeDocument locks that the attacker-controlled version is clamped
// and stripped before it is echoed back in the 400 body.
func TestVersionErrorDoesNotReflectTheWholeDocument(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("v", 100000)
	_, err := parseDocument(context.Background(), []byte(`{"version":"`+huge+`","runs":[]}`), DefaultLimits())
	if err == nil {
		t.Fatal("an unsupported version must be refused")
	}
	if len(err.Error()) > 256 {
		t.Fatalf("the version error reflects %d bytes of attacker-controlled input", len(err.Error()))
	}
}

// TestDeduplicationIsCaseSensitive locks that src/App.go and src/app.go are NOT conflated: a false match
// links an external result to the wrong first-party finding.
func TestDeduplicationIsCaseSensitive(t *testing.T) {
	t.Parallel()

	if dedupKey("src/App.go", 1) == dedupKey("src/app.go", 1) {
		t.Fatal("dedupKey must distinguish paths that differ only in case")
	}
}

// TestDeduplicatedIngestIsAudited locks that the digest short circuit — a state-observing response on a
// state-changing route — leaves an audit entry rather than passing silently.
func TestDeduplicatedIngestIsAudited(t *testing.T) {
	t.Parallel()

	svc, _, audit := newService(t)
	doc := docWith(resultA)
	if _, err := ingest(t, svc, doc); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if _, err := ingest(t, svc, doc); err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if audit.entries != 2 {
		t.Fatalf("a deduplicated ingest must still be audited, got %d entries", audit.entries)
	}
}

// TestFailedBatchPersistsNothingAndRecordsNoDigest is the store-contract regression: a mid-batch failure
// must not leave a prefix behind, and must not record the document digest — which would make the retry
// report a clean deduplicated ingest while the un-persisted tail was lost for good.
func TestFailedBatchPersistsNothingAndRecordsNoDigest(t *testing.T) {
	t.Parallel()

	store := memory.NewImportedFindingStore()
	good := importedfinding.ImportedFinding{
		ID: "i-1", TenantID: "t1", EngagementID: "eng1", Severity: shared.SeverityHigh,
		Provenance: importedfinding.Provenance{
			ToolName: "tool", ToolVersion: "1", RuleID: "r", SourceDigest: "digest",
			IngestedBy: "human:alice", IngestedAt: "2024-01-01T00:00:00Z",
		},
	}
	bad := good
	bad.ID = "i-2"
	bad.Provenance.ToolVersion = "" // incomplete provenance

	if _, _, err := store.Save(context.Background(), "t1", []importedfinding.ImportedFinding{good, bad}); err == nil {
		t.Fatal("a batch containing an unattributable finding must fail")
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 0 {
		t.Fatalf("a failed batch must persist nothing, got %d findings", len(stored))
	}
	exists, _ := store.ExistsDigest(context.Background(), "t1", "eng1", "digest")
	if exists {
		t.Fatal("a failed batch must not record the document digest: a retry would report a clean deduplicated ingest")
	}
}

// TestDigestHistoryIsTenantScoped locks that one tenant's ingest history cannot be observed — or
// collided with — from another tenant, independently of the HTTP tenant gate.
func TestDigestHistoryIsTenantScoped(t *testing.T) {
	t.Parallel()

	store := memory.NewImportedFindingStore()
	f := importedfinding.ImportedFinding{
		ID: "i-1", TenantID: "t1", EngagementID: "eng1", Severity: shared.SeverityHigh,
		Provenance: importedfinding.Provenance{
			ToolName: "tool", ToolVersion: "1", RuleID: "r", SourceDigest: "digest",
			IngestedBy: "human:alice", IngestedAt: "2024-01-01T00:00:00Z",
		},
	}
	if _, _, err := store.Save(context.Background(), "t1", []importedfinding.ImportedFinding{f}); err != nil {
		t.Fatalf("save: %v", err)
	}
	mine, _ := store.ExistsDigest(context.Background(), "t1", "eng1", "digest")
	theirs, _ := store.ExistsDigest(context.Background(), "t2", "eng1", "digest")
	if !mine {
		t.Fatal("the ingesting tenant must see its own digest")
	}
	if theirs {
		t.Fatal("another tenant must not observe this tenant's ingest history")
	}
}

// TestIngestFailsClosedWhenTheAuditLogDoes locks that an ingest whose audit entry cannot be written is
// an error, not a silent success — the audit trail is the record that the ingest happened.
func TestIngestFailsClosedWhenTheAuditLogDoes(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	svc.audit = failingAudit{}
	if _, err := ingest(t, svc, docWith(resultA)); err == nil {
		t.Fatal("an ingest that cannot be audited must fail")
	}
}

type failingAudit struct{}

func (failingAudit) Record(context.Context, ports.AuditEntry) error {
	return errors.New("audit log unavailable")
}
