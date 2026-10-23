package docpublish

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	document "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recordingOutbox struct {
	records []notification.SourceRecord
	err     error
}

func (o *recordingOutbox) Append(_ context.Context, record notification.SourceRecord) error {
	if o.err != nil {
		return o.err
	}
	o.records = append(o.records, record)
	return nil
}

var _ ports.NotificationOutbox = (*recordingOutbox)(nil)

// TestArtifactBuilderCapturesReportGenerated pins the producer half of
// report.generated: one record per sealed report, keyed by the report kind and
// its content digest so a rebuild of the same content cannot announce it twice.
func TestArtifactBuilderCapturesReportGenerated(t *testing.T) {
	insight := ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: strings.Repeat("a", 64), HasScan: true, ScanTime: artifactAt}
	for _, tc := range []struct {
		name         string
		target       document.Target
		wantKind     string
		wantEngaged  shared.ID
		wantPDFBytes string
	}{
		{"engagement", documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a"), "engagement_report", "engagement-a", "%PDF-engagement"},
		{"quality", documentTarget(document.ProjectQualitySummary, ProjectQualitySourceRef("project-a"), document.Project, "project-a"), "project_quality_summary", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := newArtifactBuilder(t, insight)
			outbox := &recordingOutbox{}
			builder.SetNotifications(outbox)
			artifact, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", tc.target)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if _, err = builder.BuildDocumentArtifact(context.Background(), "tenant-a", tc.target); err != nil {
				t.Fatalf("rebuild: %v", err)
			}
			if len(outbox.records) != 2 {
				t.Fatalf("every build appends its record for the outbox to deduplicate, got %d", len(outbox.records))
			}
			first, second := outbox.records[0], outbox.records[1]
			if first.SourceID != second.SourceID || first.SourceKind != second.SourceKind {
				t.Fatalf("the same sealed report must reuse its key: %q then %q", first.SourceID, second.SourceID)
			}
			hash := artifactBytesDigest(artifact.PDF)
			if first.SourceKind != "report" || first.SourceID != tc.wantKind+":"+hash {
				t.Fatalf("source key = %s/%s", first.SourceKind, first.SourceID)
			}
			if first.EventType != notification.EventReportGenerated || first.SubjectKind != "report" || first.SubjectID != hash {
				t.Fatalf("record = %+v", first)
			}
			if first.EngagementID != tc.wantEngaged {
				t.Fatalf("engagement = %q, want %q", first.EngagementID, tc.wantEngaged)
			}
			if first.OccurredAt != artifactAt {
				t.Fatalf("occurred_at = %v, want the seal time %v", first.OccurredAt, artifactAt)
			}
			var data map[string]any
			if err = json.Unmarshal(first.Data, &data); err != nil {
				t.Fatalf("decode data: %v", err)
			}
			if data["report_kind"] != tc.wantKind || data["content_hash"] != hash || data["report_id"] != hash {
				t.Fatalf("data = %v", data)
			}
			if _, ok := data["finding_count"]; ok {
				t.Fatalf("a producer that cannot count findings must omit the field: %v", data)
			}
		})
	}
}

func TestArtifactBuilderWithoutNotificationsStillBuilds(t *testing.T) {
	builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: strings.Repeat("a", 64), HasScan: true, ScanTime: artifactAt})
	if _, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a")); err != nil {
		t.Fatalf("build without an outbox: %v", err)
	}
}

// TestArtifactBuilderFailsWhenTheOutboxFails keeps the capture inside the
// producer's own failure path: a report that cannot be announced is not handed
// to a publisher as if it had been.
func TestArtifactBuilderFailsWhenTheOutboxFails(t *testing.T) {
	builder := newArtifactBuilder(t, ports.ReportInsight{EvidenceCount: 1, EvidenceIntact: true, EvidenceHead: strings.Repeat("a", 64), HasScan: true, ScanTime: artifactAt})
	builder.SetNotifications(&recordingOutbox{err: shared.ErrConflict})
	if _, err := builder.BuildDocumentArtifact(context.Background(), "tenant-a", documentTarget(document.EngagementReport, EngagementSourceRef("engagement-a"), document.Engagement, "engagement-a")); err == nil {
		t.Fatalf("a failed append must fail the build")
	}
}
