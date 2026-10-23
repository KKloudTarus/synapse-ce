package notification

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ReportGeneratedKind names the report a producer sealed. The values match the
// document source kinds, so one report has one name wherever it is generated.
type ReportGeneratedKind string

const (
	ReportKindEngagement       ReportGeneratedKind = "engagement_report"
	ReportKindAssessmentCycle  ReportGeneratedKind = "assessment_closure_report"
	ReportKindProjectQuality   ReportGeneratedKind = "project_quality_summary"
	reportGeneratedTitle                           = "Report generated"
	reportGeneratedSummary                         = "A report artifact was sealed from stored data."
	maxReportGeneratedTitleLen                     = 255
)

// ReportGenerated describes one sealed report artifact.
type ReportGenerated struct {
	TenantID     shared.ID
	Kind         ReportGeneratedKind
	EngagementID shared.ID
	Severity     shared.Severity
	// Title is the report's own title. It is scrubbed and bounded here.
	Title string
	// ContentHash is the digest of the sealed content. It is the idempotency key:
	// rebuilding the same report, and releasing it later, append one record.
	ContentHash string
	GeneratedAt time.Time
	// FindingCount is the number of findings the report covers. A report whose
	// producer cannot count them leaves it negative and the variable stays empty.
	FindingCount int
}

// ReportGeneratedRecord builds the outbox record for one sealed report. Every
// producer uses it, so the event payload and the idempotency key never drift
// between the engagement path and the assessment-cycle path.
func (r ReportGenerated) ReportGeneratedRecord() (SourceRecord, error) {
	if r.TenantID.IsZero() {
		return SourceRecord{}, fmt.Errorf("%w: report notification tenant is required", shared.ErrValidation)
	}
	if r.Kind == "" || r.ContentHash == "" || r.GeneratedAt.IsZero() {
		return SourceRecord{}, fmt.Errorf("%w: report notification needs a kind, a content hash and a seal time", shared.ErrValidation)
	}
	occurredAt := r.GeneratedAt.UTC()
	title := ScrubPersonalText(r.Title, maxReportGeneratedTitleLen)
	data := map[string]any{
		"title": reportGeneratedTitle, "summary": reportGeneratedSummary,
		"report_id": r.ContentHash, "report_kind": string(r.Kind), "content_hash": r.ContentHash,
		"generated_at": occurredAt.Format(time.RFC3339),
	}
	vars := map[string]string{
		"event_type": string(EventReportGenerated), "event_label": reportGeneratedLabel(),
		"occurred_at": occurredAt.Format(time.RFC3339), "generated_at": occurredAt.Format(time.RFC3339),
		"title": reportGeneratedTitle, "summary": reportGeneratedSummary,
		"severity": string(r.Severity), "report_kind": string(r.Kind), "content_hash": r.ContentHash,
	}
	if title != "" {
		data["report_title"] = title
		vars["report_title"] = title
	}
	if !r.EngagementID.IsZero() {
		data["engagement_id"] = r.EngagementID.String()
	}
	if r.FindingCount >= 0 {
		data["finding_count"] = r.FindingCount
		vars["finding_count"] = fmt.Sprintf("%d", r.FindingCount)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return SourceRecord{}, fmt.Errorf("encode report notification data: %w", err)
	}
	return SnapshotSourceRecord(SourceRecord{
		TenantID: r.TenantID, SourceKind: "report", SourceID: string(r.Kind) + ":" + r.ContentHash,
		EventType: EventReportGenerated, EngagementID: r.EngagementID, Severity: r.Severity,
		OccurredAt: occurredAt, Data: raw, SubjectKind: "report", SubjectID: r.ContentHash,
	}, vars)
}

func reportGeneratedLabel() string {
	if spec, ok := LookupEvent(EventReportGenerated); ok {
		return spec.Label
	}
	return reportGeneratedTitle
}
