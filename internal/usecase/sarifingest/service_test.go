package sarifingest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	f.entries = append(f.entries, entry)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID { s.n++; return shared.ID("id-" + itoa(s.n)) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

type fakeFindings struct{ list []finding.Finding }

func (f fakeFindings) ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return f.list, nil
}

// fakeEngagements resolves any engagement id inside the requested tenant. Tests that care about the
// tenant gate use missingEngagements instead.
type fakeEngagements struct{ tenant shared.ID }

func (f fakeEngagements) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engagement.Engagement, error) {
	stamped := f.tenant
	if stamped == "" {
		stamped = tenantID
	}
	return &engagement.Engagement{ID: id, TenantID: stamped}, nil
}

// missingEngagements is the gate closing: an engagement the caller cannot see is not found.
type missingEngagements struct{}

func (missingEngagements) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return nil, shared.ErrNotFound
}

func newService(t *testing.T, first ...finding.Finding) (*Service, *memory.ImportedFindingStore, *fakeAudit) {
	t.Helper()
	store := memory.NewImportedFindingStore()
	audit := &fakeAudit{}
	svc, err := NewService(store, fakeFindings{list: first}, fakeEngagements{}, audit, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, store, audit
}

func ingest(t *testing.T, svc *Service, doc string) (IngestResult, error) {
	t.Helper()
	return svc.Ingest(context.Background(), IngestRequest{
		TenantID: "t1", EngagementID: "eng1", Document: []byte(doc), Actor: "human:alice",
	})
}

// A minimal well-formed document, parameterised so each test can vary one thing.
func docWith(results string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","semanticVersion":"1.2.3",
	"rules":[{"id":"rule.a","name":"Rule A","shortDescription":{"text":"Injection"},
	"defaultConfiguration":{"level":"error"}}]}},"results":[` + results + `]}]}`
}

const resultA = `{"ruleId":"rule.a","level":"error","message":{"text":"bad"},
	"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.go"},"region":{"startLine":42}}}]}`

func TestIngestAcceptsAWellFormedDocument(t *testing.T) {
	t.Parallel()

	svc, store, audit := newService(t)
	result, err := ingest(t, svc, docWith(resultA))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted != 1 || len(result.Refused) != 0 {
		t.Fatalf("expected one accepted finding, got %+v", result)
	}
	stored, err := store.ListByEngagement(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected one stored finding, got %d", len(stored))
	}
	got := stored[0]
	// Provenance is mandatory and complete.
	if got.Provenance.ToolName != "semgrep" || got.Provenance.ToolVersion != "1.2.3" || got.Provenance.RuleID != "rule.a" {
		t.Fatalf("provenance incomplete: %+v", got.Provenance)
	}
	if got.Provenance.SourceDigest == "" || got.Provenance.IngestedBy != "human:alice" {
		t.Fatalf("provenance missing digest or actor: %+v", got.Provenance)
	}
	// An imported finding is structurally distinguishable and can never self-promote.
	if !got.External() || got.CanSelfPromote() {
		t.Fatal("an imported finding must be external and must never self-promote")
	}
	if got.Location.Path != "src/app.go" || got.Location.StartLine != 42 {
		t.Fatalf("location = %+v", got.Location)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("ingest must be audited exactly once, got %d", len(audit.entries))
	}
}

func TestResultWithoutProvenanceIsRefused(t *testing.T) {
	t.Parallel()

	// No ruleId and no ruleIndex: the result cannot be attributed to a rule.
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"tool","version":"1"}},
		"results":[{"level":"error","message":{"text":"x"}}]}]}`
	svc, _, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted != 0 || len(result.Refused) != 1 {
		t.Fatalf("an unattributable result must be refused, got %+v", result)
	}
	if result.Refused[0].Code != importedfinding.RefusalNoProvenance {
		t.Fatalf("refusal code = %q, want no-provenance", result.Refused[0].Code)
	}
}

// TestHostileArtifactLocations covers the acceptance list one case per line: each must be REFUSED with
// its own typed code, never normalized into something that points outside the scanned tree.
func TestHostileArtifactLocations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uri  string
		want importedfinding.RefusalCode
	}{
		{name: "parent traversal", uri: "../../etc/passwd", want: importedfinding.RefusalPathTraversal},
		{name: "traversal after a segment", uri: "src/../../../etc/passwd", want: importedfinding.RefusalPathTraversal},
		{name: "absolute path", uri: "/etc/passwd", want: importedfinding.RefusalAbsolutePath},
		{name: "file uri absolute", uri: "file:///etc/passwd", want: importedfinding.RefusalAbsolutePath},
		{name: "windows volume", uri: `C:\Windows\System32\config`, want: importedfinding.RefusalAbsolutePath},
		{name: "http scheme", uri: "https://evil.example/x", want: importedfinding.RefusalUnsupportedURI},
		{name: "data scheme", uri: "data:text/plain;base64,AAAA", want: importedfinding.RefusalUnsupportedURI},
		{name: "jar scheme", uri: "jar:file:///a.jar!/b", want: importedfinding.RefusalUnsupportedURI},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			doc := docWith(`{"ruleId":"rule.a","level":"error","message":{"text":"x"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + strings.ReplaceAll(test.uri, `\`, `\\`) + `"}}}]}`)
			svc, _, _ := newService(t)
			result, err := ingest(t, svc, doc)
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			if result.Accepted != 0 {
				t.Fatalf("%s must not be ingested", test.name)
			}
			if len(result.Refused) != 1 || result.Refused[0].Code != test.want {
				t.Fatalf("refusal = %+v, want code %q", result.Refused, test.want)
			}
		})
	}
}

func TestCyclicRelatedLocationsAreRefused(t *testing.T) {
	t.Parallel()

	var related []string
	for i := 0; i < maxRelatedLocations+1; i++ {
		related = append(related, `{"physicalLocation":{"artifactLocation":{"uri":"a.go"}}}`)
	}
	doc := docWith(`{"ruleId":"rule.a","level":"error","message":{"text":"x"},
		"relatedLocations":[` + strings.Join(related, ",") + `]}`)
	svc, _, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Refused) != 1 || result.Refused[0].Code != importedfinding.RefusalTooManyElements {
		t.Fatalf("unbounded related locations must be refused, got %+v", result.Refused)
	}
}

// TestBoundsPersistNothing asserts the acceptance rule that exceeding any bound leaves NO partial state.
func TestBoundsPersistNothing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		limits Limits
		doc    string
	}{
		{
			name:   "document size",
			limits: Limits{MaxDocumentBytes: 10, MaxRuns: 10, MaxResults: 10},
			doc:    docWith(resultA),
		},
		{
			name:   "run count",
			limits: Limits{MaxDocumentBytes: 1 << 20, MaxRuns: 0, MaxResults: 10},
			doc:    docWith(resultA),
		},
		{
			name:   "result count",
			limits: Limits{MaxDocumentBytes: 1 << 20, MaxRuns: 10, MaxResults: 0},
			doc:    docWith(resultA),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := memory.NewImportedFindingStore()
			svc, err := NewService(store, fakeFindings{}, fakeEngagements{}, &fakeAudit{}, fixedClock{}, &seqIDs{})
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			svc = svc.withLimits(test.limits)
			if _, err := ingest(t, svc, test.doc); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("exceeding the %s bound must be a typed error, got %v", test.name, err)
			}
			stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
			if len(stored) != 0 {
				t.Fatalf("exceeding a bound must persist nothing, got %d findings", len(stored))
			}
		})
	}
}

func TestIngestIsIdempotentByDocumentDigest(t *testing.T) {
	t.Parallel()

	svc, store, _ := newService(t)
	doc := docWith(resultA)
	if _, err := ingest(t, svc, doc); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	second, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if second.Accepted != 0 || second.Deduped == 0 {
		t.Fatalf("re-ingesting the same document must not duplicate, got %+v", second)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 1 {
		t.Fatalf("expected one finding after two identical ingests, got %d", len(stored))
	}
}

// TestDeduplicationRecordsBothSourcesAndSurfacesDisagreement locks the acceptance rule that a match
// keeps both sources and that a severity difference is reported rather than silently resolved.
func TestDeduplicationRecordsBothSourcesAndSurfacesDisagreement(t *testing.T) {
	t.Parallel()

	firstParty := finding.Finding{
		ID: "f-1", EngagementID: "eng1", Severity: shared.SeverityLow,
		SourceLocation: &finding.SourceLocation{File: "src/app.go", StartLine: 42, EndLine: 42},
	}
	svc, store, _ := newService(t, firstParty)

	result, err := ingest(t, svc, docWith(resultA))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Matched != 1 {
		t.Fatalf("expected the external result to match the first-party finding, got %+v", result)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 1 || stored[0].FindingID != "f-1" {
		t.Fatalf("both sources must be recorded: the imported finding must link the first-party one, got %+v", stored)
	}
	// The tool says error (high); this system said low. That disagreement is information.
	if len(result.Disagreements) != 1 {
		t.Fatalf("a severity disagreement must be surfaced, got %+v", result.Disagreements)
	}
	if result.Disagreements[0].FirstPartyLevel != shared.SeverityLow || result.Disagreements[0].ExternalLevel != shared.SeverityHigh {
		t.Fatalf("disagreement = %+v", result.Disagreements[0])
	}
}

func TestUnmappableSeverityBecomesUnknownNeverMedium(t *testing.T) {
	t.Parallel()

	// No level anywhere, and a vocabulary nothing recognises.
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"tool","version":"1",
		"rules":[{"id":"rule.x","properties":{"problem.severity":"spicy"}}]}},
		"results":[{"ruleId":"rule.x","message":{"text":"x"}}]}]}`
	svc, store, _ := newService(t)
	if _, err := ingest(t, svc, doc); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 1 {
		t.Fatalf("expected one finding, got %d", len(stored))
	}
	if stored[0].Severity != shared.SeverityUnknown {
		t.Fatalf("an unmappable severity must be unknown, got %q — a defaulted level invents a risk nobody assessed", stored[0].Severity)
	}
}

func TestIngestRequiresAnActor(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	_, err := svc.Ingest(context.Background(), IngestRequest{
		TenantID: "t1", EngagementID: "eng1", Document: []byte(docWith(resultA)),
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ingest without an actor must be refused, got %v", err)
	}
}

func TestRefusalsAreAListNotACount(t *testing.T) {
	t.Parallel()

	doc := docWith(`{"ruleId":"rule.a","level":"error","message":{"text":"x"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/etc/passwd"}}}]},
		{"level":"error","message":{"text":"y"}}`)
	svc, _, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Refused) != 2 {
		t.Fatalf("every refusal must be listed individually, got %+v", result.Refused)
	}
	// Ordered by position in the document, so a reader can find each one.
	if result.Refused[0].ResultIndex > result.Refused[1].ResultIndex {
		t.Fatalf("refusals must be ordered by document position, got %+v", result.Refused)
	}
	for _, refusal := range result.Refused {
		if !refusal.Code.Valid() {
			t.Fatalf("refusal code %q is not a known code", refusal.Code)
		}
	}
}

func TestSuppressionIsRecordedNotObeyed(t *testing.T) {
	t.Parallel()

	doc := docWith(`{"ruleId":"rule.a","level":"error","message":{"text":"x"},
		"suppressions":[{"kind":"external"}],
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}`)
	svc, store, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// The finding is still stored: an external tool's suppression is information, not authority over
	// this system's gate.
	if result.Accepted != 1 {
		t.Fatalf("a suppressed result must still be ingested, got %+v", result)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if !stored[0].Suppressed {
		t.Fatal("the suppression must be recorded on the finding")
	}
}

func TestMultipleRunsAndToolsAndRuleIndex(t *testing.T) {
	t.Parallel()

	// Two runs, two tools, one result addressing its rule by index and one by id, plus a rule that
	// lives in an extension rather than the driver.
	doc := `{"version":"2.1.0","runs":[
		{"tool":{"driver":{"name":"toolA","version":"1","rules":[{"id":"a.one"}]}},
		 "results":[{"ruleId":"a.one","level":"warning","message":{"text":"x"},
		   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]},
		{"tool":{"driver":{"name":"toolB","version":"2"},"extensions":[{"name":"ext","version":"2","rules":[{"id":"b.one"}]}]},
		 "results":[{"ruleIndex":0,"level":"note","message":{"text":"y"},
		   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.go"},"region":{"startLine":2}}}]}]}]}`
	svc, store, _ := newService(t)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted != 2 {
		t.Fatalf("both runs must be ingested, got %+v", result)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	tools := map[string]bool{}
	for _, f := range stored {
		tools[f.Provenance.ToolName] = true
	}
	if !tools["toolA"] || !tools["toolB"] {
		t.Fatalf("each run's tool must be recorded, got %+v", tools)
	}
}

func TestUnsupportedVersionIsRefused(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	if _, err := ingest(t, svc, `{"version":"1.0.0","runs":[]}`); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a non-2.1 document must be refused, got %v", err)
	}
	if _, err := ingest(t, svc, `not json`); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a non-json document must be refused, got %v", err)
	}
}

type recordingAttributor struct {
	validated  shared.ID
	asset      shared.ID
	provenance shared.ID
	ids        []shared.ID
	targets    []attackpath.FindingTarget
	err        error
	recordErr  error
}

func (a *recordingAttributor) ValidateAsset(_ context.Context, _ shared.ID, assetID shared.ID) error {
	a.validated = assetID
	return a.err
}

func (a *recordingAttributor) Record(_ context.Context, _ shared.ID, assetID, _, provenance shared.ID, confidence asset.EdgeConfidence, ids []shared.ID) error {
	if confidence != asset.EdgeObserved {
		return errors.New("unexpected confidence")
	}
	a.asset, a.provenance = assetID, provenance
	a.ids = append([]shared.ID(nil), ids...)
	return a.err
}

func (a *recordingAttributor) RecordTargets(_ context.Context, _ shared.ID, assetID, _, provenance shared.ID, confidence asset.EdgeConfidence, targets []attackpath.FindingTarget) error {
	if confidence != asset.EdgeObserved {
		return errors.New("unexpected confidence")
	}
	a.asset, a.provenance = assetID, provenance
	a.targets = append([]attackpath.FindingTarget(nil), targets...)
	return a.recordErr
}

func (a *recordingAttributor) InheritedAssetID(context.Context, shared.ID, []shared.ID) (shared.ID, error) {
	return "", nil
}

func TestIngestBindsImportedAndMatchedFindingsToDocumentDigest(t *testing.T) {
	t.Parallel()
	first := finding.Finding{ID: "first-party", EngagementID: "eng1", Severity: shared.SeverityLow, SourceLocation: &finding.SourceLocation{File: "src/app.go", StartLine: 42, EndLine: 42}}
	svc, store, _ := newService(t, first)
	attributor := &recordingAttributor{}
	svc.SetAttributor(attributor)
	result, err := svc.Ingest(context.Background(), IngestRequest{TenantID: "t1", EngagementID: "eng1", AssetID: "asset-1", Document: []byte(docWith(resultA)), Actor: "human:alice"})
	if err != nil || result.Accepted != 1 || result.Matched != 1 {
		t.Fatalf("ingest = %+v, %v", result, err)
	}
	stored, err := store.ListByEngagement(context.Background(), "t1", "eng1")
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
	if attributor.validated != "asset-1" || attributor.asset != "asset-1" || attributor.provenance != shared.ID(stored[0].Provenance.SourceDigest) {
		t.Fatalf("attribution = %#v, digest = %q", attributor, stored[0].Provenance.SourceDigest)
	}
	want := []attackpath.FindingTarget{{ID: stored[0].ID, Kind: attackpath.TargetImported}, {ID: "first-party", Kind: attackpath.TargetCanonical}}
	if len(attributor.targets) != len(want) || attributor.targets[0] != want[0] || attributor.targets[1] != want[1] {
		t.Fatalf("bound targets = %#v, want %#v", attributor.targets, want)
	}
}

func TestIngestRetryRepairsTypedBindings(t *testing.T) {
	svc, store, audit := newService(t)
	attributor := &recordingAttributor{recordErr: errors.New("binding unavailable")}
	svc.SetAttributor(attributor)
	req := IngestRequest{TenantID: "t1", EngagementID: "eng1", AssetID: "asset-1", Document: []byte(docWith(resultA)), Actor: "human:alice"}
	first, err := svc.Ingest(context.Background(), req)
	var partial *ports.PartialWriteError
	if !errors.As(err, &partial) || first.Accepted != 1 || len(partial.IDs) != 1 {
		t.Fatalf("first ingest = %+v, %v", first, err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("binding failure must audit persisted import once, got %#v", audit.entries)
	}
	entry := audit.entries[0]
	if entry.Action != "finding.imported" || entry.Target != "eng1" || entry.Metadata["accepted"] != "1" || entry.Metadata["deduplicated"] != "0" || entry.Metadata["refused"] != "0" || entry.Metadata["source_digest"] == "" || len(entry.Metadata) != 4 {
		t.Fatalf("import audit = %#v", entry)
	}
	attributor.recordErr = nil
	second, err := svc.Ingest(context.Background(), req)
	if err != nil || second.Deduped != 1 || len(attributor.targets) != 1 || attributor.targets[0].Kind != attackpath.TargetImported {
		t.Fatalf("retry = %+v, %v, targets=%+v", second, err, attributor.targets)
	}
	if len(audit.entries) != 2 || audit.entries[1].Action != "finding.imported.deduplicated" {
		t.Fatalf("retry audit = %#v", audit.entries)
	}
	stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
	if len(stored) != 1 || stored[0].ID != partial.IDs[0] {
		t.Fatalf("stored = %+v, want canonical id %s", stored, partial.IDs[0])
	}
}

func TestIngestWithoutAssetReportsCoverageGap(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t)
	result, err := ingest(t, svc, docWith(resultA))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Coverage) == 0 || result.Coverage[0].Detail != "asset attribution was not supplied: imported findings cannot enter attack paths" {
		t.Fatalf("coverage = %#v", result.Coverage)
	}
}

func TestIngestRejectsUnknownOrWrongTenantAsset(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"unknown", "wrong-tenant"} {
		t.Run(name, func(t *testing.T) {
			svc, store, _ := newService(t)
			svc.SetAttributor(&recordingAttributor{err: shared.ErrNotFound})
			_, err := svc.Ingest(context.Background(), IngestRequest{TenantID: "t1", EngagementID: "eng1", AssetID: "asset", Document: []byte(docWith(resultA)), Actor: "human:alice"})
			if !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("ingest error = %v, want not found", err)
			}
			stored, _ := store.ListByEngagement(context.Background(), "t1", "eng1")
			if len(stored) != 0 {
				t.Fatalf("rejected asset persisted findings: %#v", stored)
			}
		})
	}
}
