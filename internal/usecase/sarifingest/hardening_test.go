package sarifingest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
	// Literal expectations, not a predicate: asserting with the same helper the code uses would make a
	// bug in that helper agree with itself.
	if got.Title != "safe[31m red title" {
		t.Fatalf("title = %q, want the ANSI introducer and the bell removed and nothing else", got.Title)
	}
	if got.Message != "before  after  nul" {
		t.Fatalf("message = %q, want the bidi override and the NUL removed and nothing else", got.Message)
	}
}

// Zero-width joiners are NOT control characters: stripping them silently rewrites legitimate Persian,
// Devanagari and emoji text. Only the directional overrides are removed.
func TestSanitizeKeepsJoinersAndStripsOverrides(t *testing.T) {
	t.Parallel()

	kept, _ := sanitizeText("\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645 \U0001F468\u200d\U0001F4BB", maxMessageBytes, false)
	for _, r := range []rune{0x200c, 0x200d} {
		if !strings.ContainsRune(kept, r) {
			t.Fatalf("%U is required for correct rendering and must be kept, got %q", r, kept)
		}
	}
	stripped, _ := sanitizeText("safe\u202egnp.exe", maxMessageBytes, false)
	if strings.ContainsRune(stripped, 0x202e) {
		t.Fatalf("a right-to-left override must be removed: %q", stripped)
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

// TestPerResultWorkIsIndependentOfRuleSize is the regression for the CPU exhaustion. The defect was not
// only the per-result sort: EVERY per-result read of shared rule data — the rule's tag list, its
// description — multiplies that data by the result budget. One rule with a huge tag list and a hundred
// thousand results referencing it is a few megabytes of JSON and hours of CPU.
//
// The deadline is the assertion. Without it the complexity claim would be enforced only by the package
// test timeout, so a regression would hang CI instead of failing it.
func TestPerResultWorkIsIndependentOfRuleSize(t *testing.T) {
	t.Parallel()

	const (
		tags    = 20000
		results = 20000
	)
	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"tool","version":"1","rules":[{"id":"r0","properties":{"tags":[`)
	for i := 0; i < tags; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"noise/` + pad(i) + `"`)
	}
	b.WriteString(`]},"shortDescription":{"text":"` + strings.Repeat(" ", 1<<20) + `title"}}]}},"results":[`)
	for i := 0; i < results; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"ruleIndex":0,"level":"error","message":{"text":"x"}}`)
	}
	b.WriteString(`]}]}`)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan struct{})
	var parsedDoc parsed
	var err error
	go func() {
		defer close(done)
		parsedDoc, err = parseDocument(ctx, []byte(b.String()), DefaultLimits())
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("parsing did not finish: per-result work is proportional to the rule's shared data again")
	}
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsedDoc.results) != results {
		t.Fatalf("expected %d candidates, got %d", results, len(parsedDoc.results))
	}
}

// TestRuleTableIsBounded is the memory half: rules are held for the whole run and a rule costs far more
// in memory than the JSON that declares it, so an unbounded table turns a modest document into gigabytes.
func TestRuleTableIsBounded(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","version":"1","rules":[`)
	for i := 0; i < 200; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":"r` + pad(i) + `"}`)
	}
	b.WriteString(`]}},"results":[]}]}`)

	limits := DefaultLimits()
	limits.MaxRules = 100
	if _, err := parseDocument(context.Background(), []byte(b.String()), limits); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("exceeding the rule bound must be a typed error, got %v", err)
	}
	limits.MaxRules = 200
	if _, err := parseDocument(context.Background(), []byte(b.String()), limits); err != nil {
		t.Fatalf("a table at the bound must be accepted: %v", err)
	}
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
	if len(audit.entries) != 2 {
		t.Fatalf("a deduplicated ingest must still be audited, got %d entries", len(audit.entries))
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
			IngestedBy: "human:alice", IngestedAt: time.Unix(1700000000, 0).UTC(),
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
			IngestedBy: "human:alice", IngestedAt: time.Unix(1700000000, 0).UTC(),
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

	store := memory.NewImportedFindingStore()
	svc, err := NewService(store, fakeFindings{}, fakeEngagements{}, failingAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	_, err = ingest(t, svc, docWith(resultA))
	if err == nil {
		t.Fatal("an ingest that cannot be audited must fail")
	}
	// The findings ARE already persisted when the audit write fails, so the error has to say so —
	// reporting only "audit failed" would leave the caller believing nothing was written.
	if !strings.Contains(err.Error(), "persisted") {
		t.Fatalf("the error must state that findings were persisted: %v", err)
	}
}

type failingAudit struct{}

func (failingAudit) Record(context.Context, ports.AuditEntry) error {
	return errors.New("audit log unavailable")
}

// pad renders a fixed-width numeric suffix so generated rule ids sort and compare predictably.
func pad(n int) string {
	out := ""
	for i := 0; i < 5; i++ {
		out = string(rune('0'+n%10)) + out
		n /= 10
	}
	return out
}

// TestRelativePrefixDoesNotDisableTheSchemeGuard is the regression for the `./` escape hatch: the
// scheme and Windows-volume checks were skipped for any value starting "./", so `./https%3A%2F%2F…`
// was stored as a "repository-relative path" that is in fact a URL.
func TestRelativePrefixDoesNotDisableTheSchemeGuard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		uri  string
		want importedfinding.RefusalCode
	}{
		{"./https%3A%2F%2Fevil.example%2Fpayload", importedfinding.RefusalUnsupportedURI},
		// The volume is no longer at position 0 once "./" precedes it, so it is refused as an
		// unsupported scheme rather than as an absolute path. Either way it is refused, and the code
		// names what was actually seen.
		{"./C%3A%5CWindows%5Csystem32", importedfinding.RefusalUnsupportedURI},
		{"./mailto:x", importedfinding.RefusalUnsupportedURI},
	}
	for _, test := range tests {
		got, code := normalizeArtifactURI(test.uri)
		if code != test.want {
			t.Fatalf("normalizeArtifactURI(%q) = (%q, %q), want refusal %q", test.uri, got, code, test.want)
		}
	}
	// An ordinary "./" path is still accepted — the guard costs nothing legitimate.
	if got, code := normalizeArtifactURI("./src/app.go"); code != "" || got != "src/app.go" {
		t.Fatalf("normalizeArtifactURI(\"./src/app.go\") = (%q, %q), want src/app.go", got, code)
	}
}

// TestTrailingContentIsRefused: bytes after the top-level object mean these are not one SARIF document,
// and accepting them hands an attacker a one-byte way to change the digest and force a full re-ingest of
// a report that was already stored.
func TestTrailingContentIsRefused(t *testing.T) {
	t.Parallel()

	doc := docWith(resultA) + " trailing"
	if _, err := parseDocument(context.Background(), []byte(doc), DefaultLimits()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("trailing content must be refused, got %v", err)
	}
}

// A tool that writes `null` for an empty array means "none", not "malformed". Refusing the document
// would turn a clean scan into a parse error.
func TestNullArraysMeanEmptyNotMalformed(t *testing.T) {
	t.Parallel()

	for _, doc := range []string{
		`{"version":"2.1.0","runs":null}`,
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","version":"1","rules":null}},"results":null}]}`,
	} {
		result, err := parseDocument(context.Background(), []byte(doc), DefaultLimits())
		if err != nil {
			t.Fatalf("a null array must parse as empty, got %v", err)
		}
		if len(result.results) != 0 || len(result.refusals) != 0 {
			t.Fatalf("expected nothing ingested, got %+v", result)
		}
		// An empty ingest is disclosed rather than presented as a clean scan.
		if len(result.coverage) == 0 {
			t.Fatal("an empty document must be disclosed as coverage, not reported as a clean result")
		}
	}
}

// TestOnlyTheTwoOneLineIsAccepted: a prefix test on "2.1" also matches "2.15", a different specification.
func TestOnlyTheTwoOneLineIsAccepted(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"2.1", "2.1.0"} {
		if err := checkVersion(version); err != nil {
			t.Fatalf("version %q must be accepted: %v", version, err)
		}
	}
	for _, version := range []string{"2.15.0", "2.10", "2.2.0", "1.0.0", "", "2"} {
		if err := checkVersion(version); err == nil {
			t.Fatalf("version %q must be refused", version)
		}
	}
}

// TestRuleIndexDoesNotSilentlyBorrowAnExtensionRule: attributing a finding to a rule the tool never
// associated with it is worse than a disclosed refusal, because provenance is the point of the type.
func TestRuleIndexDoesNotSilentlyBorrowAnExtensionRule(t *testing.T) {
	t.Parallel()

	// The driver HAS a rule table, so an out-of-range index is unresolved — not silently taken from the
	// extension that follows it.
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","version":"1","rules":[{"id":"drv.one"}]},
		"extensions":[{"name":"ext","version":"1","rules":[{"id":"ext.one"}]}]},
		"results":[{"ruleIndex":1,"level":"error","message":{"text":"x"}}]}]}`
	svc, _, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted != 0 || len(result.Refused) != 1 {
		t.Fatalf("an out-of-range index must be refused, not borrowed: %+v", result)
	}

	// When the driver declares NO rule table at all, the extension's is the only one there is; that
	// resolution is documented and deterministic.
	doc = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","version":"1"},
		"extensions":[{"name":"ext","version":"1","rules":[{"id":"ext.one"}]}]},
		"results":[{"ruleIndex":0,"level":"error","message":{"text":"x"}}]}]}`
	svc2, store, _ := newService(t)
	if _, err := ingest(t, svc2, doc); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 1 || stored[0].Provenance.RuleID != "ext.one" {
		t.Fatalf("with no driver rules the extension table resolves, got %+v", stored)
	}
}

// TestRefusalListIsCappedAndSaysSo: a truncated refusal list that did not say it was truncated would be
// read as "these are all the refusals" — the same silent-gap failure the list exists to prevent.
func TestRefusalListIsCappedAndSaysSo(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","version":"1"}},"results":[`)
	for i := 0; i < maxRefusals+50; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		// No ruleId and no ruleIndex: unattributable, so every one is refused.
		b.WriteString(`{"level":"error","message":{"text":"x"}}`)
	}
	b.WriteString(`]}]}`)

	result, err := parseDocument(context.Background(), []byte(b.String()), DefaultLimits())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(result.refusals) != maxRefusals {
		t.Fatalf("refusals = %d, want the cap %d", len(result.refusals), maxRefusals)
	}
	disclosed := false
	for _, issue := range result.coverage {
		if strings.Contains(issue.Detail, "refusal list is capped") {
			disclosed = true
		}
	}
	if !disclosed {
		t.Fatal("a capped refusal list must disclose that MORE was refused than is reported")
	}
}

// TestIngestRefusesAnEngagementTheCallerCannotSee locks that the use case resolves the engagement itself
// rather than trusting its caller: a worker or CLI must not be able to write governed findings into an
// arbitrary engagement id, and an engagement outside the tenant is not found, never forbidden.
func TestIngestRefusesAnEngagementTheCallerCannotSee(t *testing.T) {
	t.Parallel()

	store := memory.NewImportedFindingStore()
	audit := &fakeAudit{}
	svc, err := NewService(store, fakeFindings{}, missingEngagements{}, audit, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if _, err := ingest(t, svc, docWith(resultA)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("an engagement the caller cannot see must be not-found, got %v", err)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 0 {
		t.Fatalf("nothing may be persisted for an unauthorized engagement, got %d", len(stored))
	}
	if len(audit.entries) != 0 {
		t.Fatalf("a refused ingest is not an audited state change, got %d entries", len(audit.entries))
	}
}

// TestRowsAreStampedWithTheEngagementsTenant is the other half of that contract: the tenant that owns
// the rows comes from the engagement that authorized the write, not from the principal.
func TestRowsAreStampedWithTheEngagementsTenant(t *testing.T) {
	t.Parallel()

	store := memory.NewImportedFindingStore()
	svc, err := NewService(store, fakeFindings{}, fakeEngagements{tenant: "tenantB"}, &fakeAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if _, err := ingest(t, svc, docWith(resultA)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if stored, _ := store.ListByEngagement(context.Background(), "tenantB", "eng1"); len(stored) != 1 {
		t.Fatalf("the rows must land in the engagement's tenant, got %d", len(stored))
	}
	if stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1"); len(stored) != 0 {
		t.Fatalf("the rows must NOT land in the principal's tenant, got %d", len(stored))
	}
}

// A store must refuse a finding whose stamped tenant differs from the partition it is being written to.
func TestStoreRefusesATenantMismatch(t *testing.T) {
	t.Parallel()

	store := memory.NewImportedFindingStore()
	f := importedfinding.ImportedFinding{
		ID: "i-1", TenantID: "t1", EngagementID: "eng1", Severity: shared.SeverityHigh,
		Provenance: importedfinding.Provenance{
			ToolName: "tool", ToolVersion: "1", RuleID: "r", SourceDigest: "digest",
			IngestedBy: "human:alice", IngestedAt: time.Unix(1700000000, 0).UTC(),
		},
	}
	if _, _, err := store.Save(context.Background(), "t2", []importedfinding.ImportedFinding{f}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a finding stamped t1 must not be saved into t2, got %v", err)
	}
}
