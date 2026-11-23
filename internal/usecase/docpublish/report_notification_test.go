package docpublish

import (
	"encoding/json"
	"strings"
	"testing"

	document "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestArtifactBuilderBuildsWithoutPublicationCapture(t *testing.T) {
	builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: strings.Repeat("a", 64), HasScan: true, ScanTime: artifactAt})
	target := documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a")
	first, err := builder.BuildDocumentArtifact(t.Context(), "tenant-a", target)
	if err != nil {
		t.Fatalf("build first artifact: %v", err)
	}
	second, err := builder.BuildDocumentArtifact(t.Context(), "tenant-a", target)
	if err != nil {
		t.Fatalf("build second artifact: %v", err)
	}
	if artifactBytesDigest(first.PDF) != artifactBytesDigest(second.PDF) {
		t.Fatalf("pure report builds must keep the sealed PDF stable")
	}
}

func TestReportGeneratedRecordUsesStoredPDFIdentity(t *testing.T) {
	artifact := ports.DocumentArtifact{Title: "Báo cáo", Paragraphs: []string{"fact"}, PDF: []byte("%PDF-1.7\\nsealed"), SourceRevision: "revision", GeneratedAt: artifactAt}
	record, err := reportGeneratedRecord("tenant-a", document.Source{SourceKind: document.EngagementReport, SourceRef: EngagementSourceRef("engagement-a"), Scope: document.Engagement, ScopeID: "engagement-a"}, artifact)
	if err != nil {
		t.Fatalf("build record: %v", err)
	}
	hash := artifactBytesDigest(artifact.PDF)
	if record.EventType != notification.EventReportGenerated || record.SourceID != "engagement_report:"+hash || record.SubjectID != hash || record.EngagementID != "engagement-a" {
		t.Fatalf("record does not identify the stored PDF: %+v", record)
	}
	var data map[string]any
	if err := json.Unmarshal(record.Data, &data); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if data["content_hash"] != hash || data["report_kind"] != "engagement_report" {
		t.Fatalf("record payload = %v", data)
	}
}

func TestReportGeneratedRecordCarriesOnlyTypedSourceNavigationFacts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		source    document.Source
		artifact  ports.DocumentArtifact
		dataKey   string
		wantValue string
	}{
		{
			name: "assessment cycle", source: document.Source{SourceKind: document.AssessmentClosureReport, SourceRef: AssessmentClosureSourceRef("cycle-a"), Scope: document.Project, ScopeID: "project-a"},
			artifact: ports.DocumentArtifact{Title: "Closure", Paragraphs: []string{"fact"}, PDF: []byte("closure"), SourceRevision: "sealed", GeneratedAt: artifactAt, CycleID: "cycle-a"}, dataKey: "cycle_id", wantValue: "cycle-a",
		},
		{
			name: "project quality", source: document.Source{SourceKind: document.ProjectQualitySummary, SourceRef: ProjectQualitySourceRef("project-a"), Scope: document.Project, ScopeID: "project-a"},
			artifact: ports.DocumentArtifact{Title: "Quality", Paragraphs: []string{"fact"}, PDF: []byte("quality"), SourceRevision: "sealed", GeneratedAt: artifactAt, ProjectKey: "payments-api"}, dataKey: "project_key", wantValue: "payments-api",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record, err := reportGeneratedRecord("tenant-a", tc.source, tc.artifact)
			if err != nil {
				t.Fatal(err)
			}
			var data map[string]any
			if err := json.Unmarshal(record.Data, &data); err != nil {
				t.Fatal(err)
			}
			if data[tc.dataKey] != tc.wantValue {
				t.Fatalf("data=%v, want %s=%q", data, tc.dataKey, tc.wantValue)
			}
		})
	}
}
