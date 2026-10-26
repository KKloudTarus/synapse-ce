package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DocumentImage is a verified raster attachment carried with a document artifact.
// Providers must treat Name and MediaType as metadata, never as executable content.
type DocumentImage struct {
	Name      string
	MediaType string
	Data      []byte
}

// DocumentArtifact is an immutable, stored-source publication input.  PDF contains
// the downloadable artifact; Paragraphs and Images are the independently bounded
// page projection.  SourceRevision identifies the stored source state that produced
// it, while SourceRef on docpublish.Target remains stable across revisions.
type DocumentArtifact struct {
	Severity       shared.Severity
	Title          string
	Paragraphs     []string
	PDF            []byte
	EvidenceHead   string
	SourceRevision string
	GeneratedAt    time.Time
	Images         []DocumentImage
	// CycleID is the validated assessment-cycle identifier for a closure artifact.
	CycleID    shared.ID `json:"cycle_id,omitempty"`
	ProjectKey string    `json:"project_key,omitempty"`
}

// EngagementReportPublication is the stored, deterministic report projection
// shared by remote publication and scheduled PDF delivery. Document retains
// structured facts so callers never need to parse rendered prose.
type EngagementReportPublication struct {
	Document        ReportDocument
	PDF             []byte
	Digest          string
	EvidenceHead    string
	GeneratedAt     time.Time
	HighestSeverity shared.Severity
}

// DocumentArtifactSource builds a tenant-scoped artifact from the stored source
// named by target. It performs no remote write.
type DocumentArtifactSource interface {
	BuildDocumentArtifact(context.Context, shared.ID, docpublish.Target) (DocumentArtifact, error)
}

// DocumentScheduledArtifactSource builds the same bounded stored-source
// artifact for a governed delivery that has no remote document target, such as
// a scheduled PDF email.
type DocumentScheduledArtifactSource interface {
	BuildSourceArtifact(context.Context, shared.ID, docpublish.Source) (DocumentArtifact, error)
}

// DocumentArtifactPDFRenderer renders a bounded, already-sanitized projection to
// PDF. The renderer is supplied by composition so artifact construction never
// depends on an infrastructure package.
type DocumentArtifactPDFRenderer interface {
	RenderDocumentArtifact(context.Context, DocumentArtifact) ([]byte, error)
}

// ProjectQualitySummary is the stored, selected analysis projected for document
// publication. IntegrityVerified is deliberately explicit: callers must not turn
// an unavailable or failed source-integrity check into a publishable summary.
type ProjectQualitySummary struct {
	TenantID          shared.ID
	ProjectID         shared.ID
	ProjectKey        string `json:"project_key,omitempty"`
	Title             string
	Paragraphs        []string
	Images            []DocumentImage
	EvidenceHead      string
	SourceRevision    string
	GeneratedAt       time.Time
	IntegrityVerified bool
}

// ProjectQualitySummaryReader reads the selected, tenant-scoped analysis summary.
// Composition adapts projectuc.Service.Overview plus its immutable analysis store
// to this deliberately small publication-facing view.
type ProjectQualitySummaryReader interface {
	ReadProjectQualitySummary(context.Context, shared.ID, shared.ID) (ProjectQualitySummary, error)
}
