package docpublish

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	comparison "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	document "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	closureuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var artifactAt = time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)

type artifactEngagements struct {
	ports.EngagementRepository
	eng *engagement.Engagement
}

func (s artifactEngagements) GetByIDInTenant(_ context.Context, tenant, id shared.ID) (*engagement.Engagement, error) {
	if s.eng == nil || s.eng.TenantID != tenant || s.eng.ID != id {
		return nil, shared.ErrNotFound
	}
	return s.eng, nil
}

func (s artifactEngagements) GetByProjectID(_ context.Context, tenant, project shared.ID) (*engagement.Engagement, error) {
	if s.eng == nil || s.eng.TenantID != tenant || s.eng.ProjectID != project {
		return nil, shared.ErrNotFound
	}
	return s.eng, nil
}

type artifactInsights struct {
	insight ports.ReportInsight
	byID    map[shared.ID]ports.ReportInsight
}

func (s artifactInsights) ReportInsight(_ context.Context, id shared.ID) (ports.ReportInsight, error) {
	if insight, ok := s.byID[id]; ok {
		return insight, nil
	}
	return s.insight, nil
}

type artifactReports struct{ head string }

func (r artifactReports) BuildEngagementPublication(context.Context, shared.ID, shared.ID) (ports.EngagementReportPublication, error) {
	pdf := []byte("%PDF-engagement")
	return ports.EngagementReportPublication{
		Document: ports.ReportDocument{Title: "Q4 assessment", Sections: []ports.ReportSection{{Heading: "Summary", Paragraphs: []string{"Stored assessment summary."}, Table: &ports.ReportTable{Headers: []string{"Severity", "Count"}, Rows: [][]string{{"high", "1"}}}}}},
		PDF:      pdf, Digest: artifactBytesDigest(pdf), EvidenceHead: r.head, GeneratedAt: artifactAt, HighestSeverity: shared.SeverityHigh,
	}, nil
}

type artifactClosures struct {
	ports.AssessmentClosureRepository
	cycle    *assessmentcycle.AssessmentCycle
	manifest *closuredom.Manifest
	members  []assessmentcycle.Member
}

func (s artifactClosures) ListMembers(_ context.Context, tenant, cycle shared.ID) ([]assessmentcycle.Member, error) {
	if s.cycle == nil || s.cycle.TenantID != tenant || s.cycle.ID != cycle {
		return nil, shared.ErrNotFound
	}
	return append([]assessmentcycle.Member(nil), s.members...), nil
}

func (s artifactClosures) GetCycle(_ context.Context, tenant, id shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	if s.cycle == nil || s.cycle.TenantID != tenant || s.cycle.ID != id {
		return nil, shared.ErrNotFound
	}
	return s.cycle, nil
}

func (s artifactClosures) GetActiveClosureManifest(_ context.Context, tenant, cycle shared.ID) (*closuredom.Manifest, error) {
	if s.manifest == nil || s.manifest.TenantID != tenant || s.manifest.CycleID != cycle {
		return nil, shared.ErrNotFound
	}
	return s.manifest, nil
}

type artifactClosureRenderer struct {
	artifact ports.AssessmentClosureReportArtifact
}

func (s artifactClosureRenderer) Render(context.Context, shared.ID, shared.ID, shared.ID) (ports.AssessmentClosureReportArtifact, error) {
	return s.artifact, nil
}

type artifactQuality struct{ summary ports.ProjectQualitySummary }

func (s artifactQuality) ReadProjectQualitySummary(_ context.Context, _ shared.ID, project shared.ID) (ports.ProjectQualitySummary, error) {
	if project != s.summary.ProjectID {
		return ports.ProjectQualitySummary{}, shared.ErrNotFound
	}
	return s.summary, nil
}

type artifactProjector struct{}

func (artifactProjector) RenderDocumentArtifact(_ context.Context, artifact ports.DocumentArtifact) ([]byte, error) {
	return append([]byte("%PDF-projection:"), []byte(artifact.Title)...), nil
}

type capturingArtifactProjector struct{ input ports.DocumentArtifact }

func (p *capturingArtifactProjector) RenderDocumentArtifact(_ context.Context, artifact ports.DocumentArtifact) ([]byte, error) {
	p.input = artifact
	return append([]byte("%PDF-projection:"), []byte(artifact.Title)...), nil
}

type artifactEvidence struct {
	items []ports.EvidenceArtifact
	data  map[string][]byte
	err   error
}

func (s artifactEvidence) ListArtifacts(context.Context, shared.ID) ([]ports.EvidenceArtifact, error) {
	return append([]ports.EvidenceArtifact(nil), s.items...), s.err
}

func (s artifactEvidence) ArtifactBytes(_ context.Context, _ shared.ID, hash string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if data, ok := s.data[hash]; ok {
		return append([]byte(nil), data...), nil
	}
	return nil, shared.ErrNotFound
}

func newArtifactBuilder(t *testing.T, insight ports.ReportInsight) *ArtifactBuilder {
	t.Helper()
	tenant, project, cycleID := shared.ID("tenant-a"), shared.ID("project-a"), shared.ID("cycle-a")
	eng := &engagement.Engagement{ID: "engagement-a", TenantID: tenant, ProjectID: project, Name: "Q4 assessment", Audit: shared.Audit{CreatedAt: artifactAt, UpdatedAt: artifactAt}}
	sealed := artifactAt
	manifest := &closuredom.Manifest{TenantID: tenant, CycleID: cycleID, ID: "manifest-a", FinalAssessmentID: eng.ID, SealedAt: &sealed}
	closureContent := []byte(`{"report_hash":"report-hash","report":{"cycle":{"id":"cycle-a","version":2},"initial_snapshot":{"content_hash":"initial-hash"},"final_snapshot":{"content_hash":"final-hash"},"comparison":{"content_hash":"comparison-hash"},"manifest":{"id":"manifest-a","content_hash":"manifest-hash"}}}`)
	closureHash := artifactBytesDigest(closureContent)
	closures := artifactClosures{cycle: &assessmentcycle.AssessmentCycle{TenantID: tenant, ID: cycleID, ProjectID: project, Name: "Quarterly closure"}, manifest: manifest, members: []assessmentcycle.Member{{TenantID: tenant, CycleID: cycleID, AssessmentID: eng.ID}}}
	builder, err := NewArtifactBuilder(
		artifactEngagements{eng: eng}, artifactReports{head: insight.EvidenceHead},
		closures, closures,
		artifactClosureRenderer{artifact: ports.AssessmentClosureReportArtifact{TenantID: tenant, CycleID: cycleID, ManifestID: "manifest-a", ContentHash: closureHash, Content: closureContent, GeneratedAt: artifactAt}},
		artifactQuality{summary: ports.ProjectQualitySummary{TenantID: tenant, ProjectID: project, Title: "Quality summary", Paragraphs: []string{"Stored analysis summary."}, SourceRevision: "analysis:analysis-a", EvidenceHead: strings.Repeat("b", 64), GeneratedAt: artifactAt, IntegrityVerified: true}},
		artifactProjector{},
	)
	if err != nil {
		t.Fatalf("new builder: %v", err)
	}
	builder.SetEvidenceIntegrityProvider(artifactInsights{insight: insight})
	return builder
}

func documentTarget(kind document.SourceKind, ref string, scope document.Scope, id shared.ID) document.Target {
	return document.Target{IntegrationID: "integration-a", SourceKind: kind, SourceRef: ref, Scope: scope, ScopeID: id, Container: "SYN"}
}

func TestArtifactBuilderBuildsEveryStoredSourceDeterministically(t *testing.T) {
	builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: strings.Repeat("a", 64), HasScan: true, ScanTime: artifactAt})
	tenant := shared.ID("tenant-a")
	tests := []struct {
		name   string
		target document.Target
		want   string
	}{
		{"engagement", documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a"), "report:" + artifactBytesDigest([]byte("%PDF-engagement"))},
		{"closure", documentTarget(document.AssessmentClosureReport, AssessmentClosureSourceRef("cycle-a"), document.Project, "project-a"), "closure:manifest-a:" + artifactBytesDigest([]byte(`{"report_hash":"report-hash","report":{"cycle":{"id":"cycle-a","version":2},"initial_snapshot":{"content_hash":"initial-hash"},"final_snapshot":{"content_hash":"final-hash"},"comparison":{"content_hash":"comparison-hash"},"manifest":{"id":"manifest-a","content_hash":"manifest-hash"}}}`))},
		{"quality", documentTarget(document.ProjectQualitySummary, ProjectQualitySourceRef("project-a"), document.Project, "project-a"), "analysis:analysis-a"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first, err := builder.BuildDocumentArtifact(context.Background(), tenant, test.target)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			second, err := builder.BuildDocumentArtifact(context.Background(), tenant, test.target)
			if err != nil {
				t.Fatalf("repeat build: %v", err)
			}
			if first.SourceRevision != test.want || len(first.PDF) == 0 || first.GeneratedAt != artifactAt {
				t.Fatalf("unexpected artifact: %+v", first)
			}
			if first.EvidenceHead != strings.Repeat("a", 64) {
				t.Fatalf("artifact must retain its actual verified evidence head: %+v", first)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("stored source must be deterministic\nfirst=%+v\nsecond=%+v", first, second)
			}
			scheduled, err := builder.BuildSourceArtifact(context.Background(), tenant, test.target.Source())
			if err != nil {
				t.Fatalf("build scheduled artifact: %v", err)
			}
			if !reflect.DeepEqual(first, scheduled) {
				t.Fatalf("target and source artifact differ\ntarget=%+v\nsource=%+v", first, scheduled)
			}
		})
	}
}

func TestArtifactBuilderProjectsStoredClosureResultsIntoPDF(t *testing.T) {
	insight := ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: strings.Repeat("a", 64)}
	builder := newArtifactBuilder(t, insight)
	payload := closureuc.ClosureReportPayload{
		SchemaVersion: 1, RendererVersion: "assessment-cycle-report-v1", GeneratedAt: artifactAt,
		Cycle:           closureuc.ClosureReportCycle{ID: "cycle-a", Version: 2, ManifestVersion: 3, RootAssessmentID: "root-a", FinalAssessmentID: "engagement-a"},
		InitialSnapshot: closureuc.ClosureReportSnapshot{ID: "initial-a", ContentHash: "initial-hash"},
		FinalSnapshot:   closureuc.ClosureReportSnapshot{ID: "final-a", ContentHash: "final-hash"},
		Comparison: closureuc.ClosureReportComparison{ID: "comparison-a", ContentHash: "comparison-hash", Summary: comparison.Summary{
			BaselineCount: 12, CurrentCount: 9, FixedCount: 5, NewCount: 2, ReopenedCount: 1,
			BaselineRisk: 900, CurrentRisk: 640, NewRisk: 180, ReopenedRisk: 75,
			BaselineSeverity: comparison.SeverityCounts{Critical: 2, High: 3, Medium: 4, Low: 2, Info: 1},
			CurrentSeverity:  comparison.SeverityCounts{Critical: 1, High: 2, Medium: 4, Low: 1, Info: 1},
		}},
		DecisionReferences: []closuredom.Reference{{Kind: "closure_decision", ID: "decision-a", Version: 1}},
		CoverageDecisions: closuredom.CoverageDecisions{
			Initial: []closuredom.CoverageDecision{{SnapshotID: "initial-a", DimensionID: "runtime", State: assessmentsnapshot.CoverageComplete}, {SnapshotID: "initial-a", DimensionID: "identity", State: assessmentsnapshot.CoveragePartial, ReasonCode: "limited_access", Waived: true}},
			Final:   []closuredom.CoverageDecision{{SnapshotID: "final-a", DimensionID: "runtime", State: assessmentsnapshot.CoverageComplete}},
		},
		ScopeProfileChanges: []closuredom.ScopeProfileChange{{AssessmentID: "engagement-a", Kind: "scope_change", Summary: "Stored scope change"}},
		NonFinalBranches:    []closuredom.BranchState{{AssessmentID: "branch-a", RelationshipVersion: 4, Archived: true}},
		Manifest:            closureuc.ClosureReportManifest{ID: "manifest-a", ContentHash: "manifest-hash", Reason: "all required controls reviewed", OverrideReason: "approved exception"},
	}
	content, err := json.Marshal(closureuc.ClosureReportDocument{ReportHash: "stored-closure-hash", Report: payload})
	if err != nil {
		t.Fatalf("marshal closure fixture: %v", err)
	}
	builder.closurePDF = artifactClosureRenderer{artifact: ports.AssessmentClosureReportArtifact{TenantID: "tenant-a", CycleID: "cycle-a", ManifestID: "manifest-a", ContentHash: artifactBytesDigest(content), Content: content, GeneratedAt: artifactAt}}
	projector := &capturingArtifactProjector{}
	builder.projector = projector

	artifact, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", documentTarget(document.AssessmentClosureReport, AssessmentClosureSourceRef("cycle-a"), document.Project, "project-a"))
	if err != nil {
		t.Fatalf("build closure artifact: %v", err)
	}
	paragraphs := strings.Join(artifact.Paragraphs, "\n")
	for _, want := range []string{
		"Baseline findings: 12; current findings: 9; fixed findings: 5; new findings: 2; reopened findings: 1.",
		"Baseline risk: 900; current risk: 640; new risk: 180; reopened risk: 75.",
		"Current severity: critical=1, high=2, medium=4, low=1, info=1, unknown=0.",
		"Initial coverage decisions: 2 (complete=1, partial=1; reason-coded=1; waived=1).",
		"Closure reason: all required controls reviewed",
		"Closure override reason: approved exception",
		"Non-final branch assessment branch-a: relationship version 4; archived=true.",
	} {
		if !strings.Contains(paragraphs, want) {
			t.Fatalf("closure projection missing %q:\n%s", want, paragraphs)
		}
	}
	if !reflect.DeepEqual(projector.input.Paragraphs, artifact.Paragraphs) {
		t.Fatalf("closure PDF projector did not receive stored result projection\ninput=%#v\nartifact=%#v", projector.input.Paragraphs, artifact.Paragraphs)
	}
}

func TestArtifactBuilderBlocksBrokenClosureAndQualityEvidenceChains(t *testing.T) {
	tenant := shared.ID("tenant-a")
	broken := ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: false, EvidenceHead: strings.Repeat("c", 64)}
	for _, test := range []struct {
		name   string
		target document.Target
	}{
		{name: "closure", target: documentTarget(document.AssessmentClosureReport, AssessmentClosureSourceRef("cycle-a"), document.Project, "project-a")},
		{name: "quality", target: documentTarget(document.ProjectQualitySummary, ProjectQualitySourceRef("project-a"), document.Project, "project-a")},
	} {
		t.Run(test.name, func(t *testing.T) {
			builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: strings.Repeat("a", 64)})
			builder.SetEvidenceIntegrityProvider(artifactInsights{insight: broken})
			_, err := builder.BuildDocumentArtifact(context.Background(), tenant, test.target)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("broken evidence chain must block artifact, got %v", err)
			}
		})
	}
}

func TestArtifactBuilderRejectsCrossTenantAndIntegrityFailure(t *testing.T) {
	target := documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a")
	t.Run("cross tenant", func(t *testing.T) {
		builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: "head", HasScan: true, ScanTime: artifactAt})
		_, err := builder.BuildDocumentArtifact(context.Background(), "tenant-b", target)
		if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("cross-tenant source must be hidden, got %v", err)
		}
	})
	t.Run("tampered evidence", func(t *testing.T) {
		builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: false, EvidenceHead: "head", HasScan: true, ScanTime: artifactAt})
		_, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", target)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("tampered evidence must block build, got %v", err)
		}
	})
}

func TestArtifactBuilderRejectsClosureOutsideProjectScope(t *testing.T) {
	builder := newArtifactBuilder(t, ports.ReportInsight{})
	target := documentTarget(document.AssessmentClosureReport, AssessmentClosureSourceRef("cycle-a"), document.Project, "other-project")
	_, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", target)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-project closure must be hidden, got %v", err)
	}
}

func TestArtifactBuilderUsesActualEvidenceHeadAndVerifiedAttachments(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00}
	hash := artifactBytesDigest(png)
	builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true})
	builder.SetEvidenceProvider(artifactEvidence{
		items: []ports.EvidenceArtifact{{Filename: "capture.PNG", SHA256: hash, Size: len(png)}},
		data:  map[string][]byte{hash: png},
	})
	target := documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a")
	artifact, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", target)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if artifact.EvidenceHead != "" {
		t.Fatalf("invented evidence head: %q", artifact.EvidenceHead)
	}
	if len(artifact.Images) != 1 || artifact.Images[0].Name != "evidence-"+hash+".png" || artifact.Images[0].MediaType != "image/png" || !reflect.DeepEqual(artifact.Images[0].Data, png) {
		t.Fatalf("verified attachment = %+v", artifact.Images)
	}
	if !strings.Contains(strings.Join(artifact.Paragraphs, "\n"), "no verified evidence-chain head") {
		t.Fatalf("missing no-head disclosure: %#v", artifact.Paragraphs)
	}
}

func TestArtifactBuilderBlocksTamperedClaimedEvidenceImage(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00}
	builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: strings.Repeat("a", 64)})
	builder.SetEvidenceProvider(artifactEvidence{
		items: []ports.EvidenceArtifact{{Filename: "capture.png", SHA256: strings.Repeat("b", 64), Size: len(png)}},
		data:  map[string][]byte{strings.Repeat("b", 64): png},
	})
	target := documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a")
	if _, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", target); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered image was accepted: %v", err)
	}
}

func TestNormalizeArtifactMatchesConfluenceTitleAndImageLimits(t *testing.T) {
	base := ports.DocumentArtifact{
		Title:          strings.Repeat("a", 255),
		Paragraphs:     []string{"stored summary"},
		PDF:            []byte("%PDF-test"),
		EvidenceHead:   strings.Repeat("a", 64),
		SourceRevision: "analysis:a",
		GeneratedAt:    artifactAt,
	}
	if _, err := normalizeArtifact(base); err != nil {
		t.Fatalf("255-byte title rejected: %v", err)
	}
	tooLongTitle := base
	tooLongTitle.Title = strings.Repeat("a", 256)
	if _, err := normalizeArtifact(tooLongTitle); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("256-byte title accepted: %v", err)
	}
	gif := base
	gif.Images = []ports.DocumentImage{{Name: "evidence.gif", MediaType: "image/gif", Data: []byte("GIF89a")}}
	if _, err := normalizeArtifact(gif); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("GIF accepted though provider rejects it: %v", err)
	}
}

type largeStoredPublication struct{}

func (largeStoredPublication) BuildEngagementPublication(ctx context.Context, tenant, id shared.ID) (ports.EngagementReportPublication, error) {
	publication, err := (artifactReports{}).BuildEngagementPublication(ctx, tenant, id)
	facts := make([]string, 101)
	for i := range facts {
		facts[i] = "Stored assessment fact"
	}
	publication.Document.Sections = []ports.ReportSection{{Paragraphs: facts}}
	return publication, err
}

func TestEngagementProjectionRetainsEvidenceAndOmissionWithinParagraphBound(t *testing.T) {
	builder := newArtifactBuilder(t, ports.ReportInsight{})
	builder.reports = largeStoredPublication{}
	target := documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a")
	artifact, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", target)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Paragraphs) != maxArtifactParagraphs || !strings.HasPrefix(artifact.Paragraphs[len(artifact.Paragraphs)-2], "Evidence-chain head:") || !strings.Contains(artifact.Paragraphs[len(artifact.Paragraphs)-1], "omitted 3 structured facts") {
		t.Fatalf("bounded disclosure lost: %v", artifact.Paragraphs)
	}
}

func TestStructuredReportTablesProjectReadableLabelledFacts(t *testing.T) {
	paragraphs, omitted := projectEngagementFacts(ports.ReportDocument{Sections: []ports.ReportSection{{Table: &ports.ReportTable{Headers: []string{"Mức độ", "Số lượng"}, Rows: [][]string{{"cao", "2"}}}}}})
	if omitted != 0 || len(paragraphs) != 1 || paragraphs[0] != "Mức độ: cao; Số lượng: 2" {
		t.Fatalf("facts=%v omitted=%d", paragraphs, omitted)
	}
}
