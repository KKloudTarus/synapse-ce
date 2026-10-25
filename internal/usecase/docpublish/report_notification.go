package docpublish

import (
	"fmt"

	document "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// reportGeneratedRecord derives the idempotent source record from the artifact
// that the caller just stored. The PDF digest is the established document
// publication content identity; command payload digests include destination
// state and must not become notification source keys.
func reportGeneratedRecord(tenant shared.ID, source document.Source, artifact ports.DocumentArtifact) (notification.SourceRecord, error) {
	if err := source.Validate(); err != nil {
		return notification.SourceRecord{}, err
	}
	generated := notification.ReportGenerated{
		TenantID: tenant, Kind: notification.ReportGeneratedKind(source.SourceKind), Severity: artifact.Severity,
		Title: artifact.Title, ContentHash: artifactBytesDigest(artifact.PDF), GeneratedAt: artifact.GeneratedAt,
		FindingCount: -1,
	}
	switch source.SourceKind {
	case document.EngagementReport:
		generated.EngagementID = source.ScopeID
	case document.AssessmentClosureReport:
		generated.CycleID = artifact.CycleID
	case document.ProjectQualitySummary:
		generated.ProjectKey = artifact.ProjectKey
	}
	record, err := generated.ReportGeneratedRecord()
	if err != nil {
		return notification.SourceRecord{}, fmt.Errorf("build report notification: %w", err)
	}
	return record, nil
}
