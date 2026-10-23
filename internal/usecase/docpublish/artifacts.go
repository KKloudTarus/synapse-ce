// Package docpublish builds bounded publication artifacts from tenant-scoped,
// stored sources. Remote document writes deliberately live elsewhere.
package docpublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	document "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	closureuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxArtifactPDFBytes        = 10 << 20
	maxArtifactImages          = 10
	maxArtifactImageBytes      = 10 << 20
	maxArtifactTextBytes       = 64 << 10
	maxArtifactParagraphs      = 100
	maxArtifactParagraphBytes  = 4 << 10
	maxArtifactTitleBytes      = 255
	maxArtifactRevisionBytes   = 512
	maxArtifactEvidenceHeadLen = 128
)

type engagementReportGenerator interface {
	BuildEngagementPublication(context.Context, shared.ID, shared.ID) (ports.EngagementReportPublication, error)
}

type closureReportRenderer interface {
	Render(context.Context, shared.ID, shared.ID, shared.ID) (ports.AssessmentClosureReportArtifact, error)
}

type assessmentCycleReader interface {
	GetCycle(context.Context, shared.ID, shared.ID) (*assessmentcycle.AssessmentCycle, error)
	ListMembers(context.Context, shared.ID, shared.ID) ([]assessmentcycle.Member, error)
}

// ArtifactBuilder combines source-specific read ports with the existing report
// renderer. It does not own a document provider, a write intent, or any remote
// credentials.
type ArtifactBuilder struct {
	engagements ports.EngagementRepository
	reports     engagementReportGenerator
	closures    ports.AssessmentClosureRepository
	cycles      assessmentCycleReader
	closurePDF  closureReportRenderer
	quality     ports.ProjectQualitySummaryReader
	projector   ports.DocumentArtifactPDFRenderer
	evidence    ports.ReportEvidenceProvider
	integrity   ports.ReportInsightProvider
	events      ports.NotificationOutbox
}

// NewArtifactBuilder requires every closed source dependency. Keeping these
// interfaces narrow lets composition reuse report.Service, ClosureReportService,
// and a small adapter around projectuc.Service.Overview without importing any
// infrastructure package into this use case.
func NewArtifactBuilder(
	engagements ports.EngagementRepository,
	reports engagementReportGenerator,
	closures ports.AssessmentClosureRepository,
	cycles assessmentCycleReader,
	closurePDF closureReportRenderer,
	quality ports.ProjectQualitySummaryReader,
	projector ports.DocumentArtifactPDFRenderer,
) (*ArtifactBuilder, error) {
	if engagements == nil || reports == nil || closures == nil || cycles == nil || closurePDF == nil || quality == nil || projector == nil {
		return nil, fmt.Errorf("%w: document artifact dependencies are required", shared.ErrValidation)
	}
	return &ArtifactBuilder{
		engagements: engagements, reports: reports, closures: closures, cycles: cycles,
		closurePDF: closurePDF, quality: quality, projector: projector,
	}, nil
}

// SetEvidenceProvider enables verified raster attachments for engagement
// artifacts. It is optional to preserve existing report-only composition; when
// present, each selected attachment is re-read and hash-checked before it can
// reach a remote publisher.
func (b *ArtifactBuilder) SetEvidenceProvider(provider ports.ReportEvidenceProvider) {
	b.evidence = provider
}

// SetNotifications enables the report.generated capture. It is optional so a
// composition without notifications keeps building artifacts. The outbox row is
// keyed by the sealed content, so rebuilding the same report appends once.
func (b *ArtifactBuilder) SetNotifications(outbox ports.NotificationOutbox) {
	b.events = outbox
}

// SetEvidenceIntegrityProvider enables evidence-chain checks for document
// sources whose report renderer does not already perform that check. Callers
// must provide the stored report insight provider used by the report service.
func (b *ArtifactBuilder) SetEvidenceIntegrityProvider(provider ports.ReportInsightProvider) {
	b.integrity = provider
}

var _ ports.DocumentArtifactSource = (*ArtifactBuilder)(nil)
var _ ports.DocumentScheduledArtifactSource = (*ArtifactBuilder)(nil)

// EngagementSourceRef returns the stable source identity for one engagement.
// It intentionally contains no content hash or generated timestamp.
func EngagementSourceRef(id shared.ID) string { return "engagement:" + id.String() }

// AssessmentClosureSourceRef returns the stable source identity for one assessment
// cycle. The active sealed manifest is recorded in SourceRevision, not here.
func AssessmentClosureSourceRef(id shared.ID) string { return "assessment-cycle:" + id.String() }

// ProjectQualitySourceRef returns the stable source identity for one project.
// The selected analysis is recorded in SourceRevision, not here.
func ProjectQualitySourceRef(id shared.ID) string { return "project:" + id.String() }

// BuildDocumentArtifact resolves exactly the stored source addressed by target.
// It fails before any remote action if tenant ownership, source identity, or source
// integrity cannot be proven.
func (b *ArtifactBuilder) BuildDocumentArtifact(ctx context.Context, tenant shared.ID, target document.Target) (ports.DocumentArtifact, error) {
	if err := target.Validate(); err != nil {
		return ports.DocumentArtifact{}, err
	}
	return b.BuildSourceArtifact(ctx, tenant, target.Source())
}

// BuildSourceArtifact resolves exactly the stored source addressed by source.
// It has no provider, target integration, or remote container dependency, so
// the same verified artifact can safely feed scheduled PDF delivery.
func (b *ArtifactBuilder) BuildSourceArtifact(ctx context.Context, tenant shared.ID, source document.Source) (ports.DocumentArtifact, error) {
	if tenant.IsZero() {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: document artifact tenant is required", shared.ErrValidation)
	}
	if err := source.Validate(); err != nil {
		return ports.DocumentArtifact{}, err
	}
	var (
		artifact ports.DocumentArtifact
		err      error
	)
	switch source.SourceKind {
	case document.EngagementReport:
		artifact, err = b.buildEngagement(ctx, tenant, source)
	case document.AssessmentClosureReport:
		artifact, err = b.buildClosure(ctx, tenant, source)
	case document.ProjectQualitySummary:
		artifact, err = b.buildQuality(ctx, tenant, source)
	default:
		return ports.DocumentArtifact{}, fmt.Errorf("%w: unsupported document source", shared.ErrValidation)
	}
	if err != nil {
		return ports.DocumentArtifact{}, err
	}
	if err = b.captureReportGenerated(ctx, tenant, source, artifact); err != nil {
		return ports.DocumentArtifact{}, err
	}
	return artifact, nil
}

// captureReportGenerated appends report.generated for one sealed artifact. The
// source key is the report kind and the content digest, so a rebuild of the same
// content and a later release of it append one record, and a changed report
// appends its own.
func (b *ArtifactBuilder) captureReportGenerated(ctx context.Context, tenant shared.ID, source document.Source, artifact ports.DocumentArtifact) error {
	if b.events == nil {
		return nil
	}
	generated := notification.ReportGenerated{
		TenantID: tenant, Kind: notification.ReportGeneratedKind(source.SourceKind), Severity: artifact.Severity,
		Title: artifact.Title, ContentHash: artifactBytesDigest(artifact.PDF), GeneratedAt: artifact.GeneratedAt,
		FindingCount: -1,
	}
	if source.SourceKind == document.EngagementReport {
		generated.EngagementID = source.ScopeID
	}
	record, err := generated.ReportGeneratedRecord()
	if err != nil {
		return err
	}
	if err = b.events.Append(ctx, record); err != nil {
		return fmt.Errorf("append report notification: %w", err)
	}
	return nil
}

func (b *ArtifactBuilder) buildEngagement(ctx context.Context, tenant shared.ID, source document.Source) (ports.DocumentArtifact, error) {
	if source.SourceRef != EngagementSourceRef(source.ScopeID) {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: engagement document source_ref must identify its engagement", shared.ErrValidation)
	}
	eng, err := b.engagements.GetByIDInTenant(ctx, tenant, source.ScopeID)
	if err != nil {
		return ports.DocumentArtifact{}, fmt.Errorf("read engagement document source: %w", err)
	}
	if eng == nil || eng.ID != source.ScopeID || eng.TenantID != tenant {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: engagement document source ownership mismatch", shared.ErrNotFound)
	}
	publication, err := b.reports.BuildEngagementPublication(ctx, tenant, source.ScopeID)
	if err != nil {
		return ports.DocumentArtifact{}, fmt.Errorf("render engagement document: %w", err)
	}
	if publication.Digest != artifactBytesDigest(publication.PDF) {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: engagement report integrity seal mismatch", shared.ErrValidation)
	}
	if publication.GeneratedAt.IsZero() {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: engagement report source snapshot mismatch", shared.ErrValidation)
	}
	evidenceHead := strings.TrimSpace(publication.EvidenceHead)
	images, omitted, err := b.engagementImages(ctx, source.ScopeID)
	if err != nil {
		return ports.DocumentArtifact{}, err
	}
	paragraphs, projectedOmitted := projectEngagementFacts(publication.Document)
	if len(paragraphs) == 0 {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: engagement report has no structured facts", shared.ErrValidation)
	}
	if evidenceHead == "" {
		paragraphs = append(paragraphs, "Evidence-chain head: none (no verified evidence-chain head is available).")
	} else {
		paragraphs = append(paragraphs, "Evidence-chain head: "+evidenceHead)
	}
	if omitted > 0 || projectedOmitted > 0 {
		paragraphs = append(paragraphs, fmt.Sprintf("Bounded publication omitted %d structured facts and %d evidence attachments.", projectedOmitted, omitted))
	}
	artifact := ports.DocumentArtifact{
		Severity:       publication.HighestSeverity,
		Title:          boundedArtifactTitle("Security assessment report: " + strings.TrimSpace(publication.Document.Title)),
		Paragraphs:     paragraphs,
		PDF:            publication.PDF,
		EvidenceHead:   evidenceHead,
		SourceRevision: "report:" + strings.TrimSpace(publication.Digest),
		GeneratedAt:    publication.GeneratedAt.UTC(),
		Images:         images,
	}
	return normalizeArtifact(artifact)
}

func projectEngagementFacts(document ports.ReportDocument) ([]string, int) {
	paragraphs := make([]string, 0, maxArtifactParagraphs)
	omitted := 0
	textBytes := 0
	appendFact := func(value string) {
		value = boundedArtifactParagraph(value)
		if value == "" {
			return
		}
		if len(paragraphs) >= maxArtifactParagraphs-2 {
			omitted++
			return
		}
		// Leave room for the evidence/omission disclosures appended by the caller.
		if textBytes+len(value) > maxArtifactTextBytes-1024 {
			omitted++
			return
		}
		paragraphs = append(paragraphs, value)
		textBytes += len(value)
	}
	for _, section := range document.Sections {
		if heading := strings.TrimSpace(section.Heading); heading != "" {
			appendFact(heading)
		}
		for _, paragraph := range section.Paragraphs {
			appendFact(paragraph)
		}
		if section.Table == nil {
			continue
		}
		for _, row := range section.Table.Rows {
			cells := make([]string, 0, len(row))
			for column, value := range row {
				if column < len(section.Table.Headers) && strings.TrimSpace(section.Table.Headers[column]) != "" {
					cells = append(cells, section.Table.Headers[column]+": "+value)
				} else {
					cells = append(cells, value)
				}
			}
			appendFact(strings.Join(cells, "; "))
		}
	}
	return paragraphs, omitted
}

func boundedArtifactTitle(value string) string {
	return boundedArtifactText(value, maxArtifactTitleBytes)
}

func boundedArtifactParagraph(value string) string {
	return boundedArtifactText(value, maxArtifactParagraphBytes)
}

func boundedArtifactText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	suffix := "…"
	cut := limit - len(suffix)
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	if cut <= 0 {
		return ""
	}
	return value[:cut] + suffix
}

// engagementImages only consumes records that claim a supported raster suffix.
// A selected record must have a valid declared hash and re-readable matching
// bytes; otherwise publication stops before any remote upload. Other evidence is
// deliberately not fetched into a document artifact.
func (b *ArtifactBuilder) engagementImages(ctx context.Context, engagementID shared.ID) ([]ports.DocumentImage, int, error) {
	if b.evidence == nil {
		return nil, 0, nil
	}
	artifacts, err := b.evidence.ListArtifacts(ctx, engagementID)
	if err != nil {
		return nil, 0, fmt.Errorf("list engagement evidence attachments: %w", err)
	}
	images := make([]ports.DocumentImage, 0, min(len(artifacts), maxArtifactImages))
	total, omitted := 0, 0
	for _, artifact := range artifacts {
		if !claimedDocumentImage(artifact.Filename) {
			continue
		}
		if artifact.Size > maxArtifactImageBytes || len(images) >= maxArtifactImages {
			omitted++
			continue
		}
		hash := strings.TrimSpace(artifact.SHA256)
		if !validArtifactHash(hash) {
			return nil, 0, fmt.Errorf("%w: evidence attachment has invalid digest", shared.ErrValidation)
		}
		data, err := b.evidence.ArtifactBytes(ctx, engagementID, hash)
		if err != nil {
			return nil, 0, fmt.Errorf("read evidence attachment: %w", err)
		}
		if len(data) > maxArtifactImageBytes {
			omitted++
			continue
		}
		if artifact.Size >= 0 && len(data) != artifact.Size {
			return nil, 0, fmt.Errorf("%w: evidence attachment size mismatch", shared.ErrValidation)
		}
		if artifactBytesDigest(data) != hash {
			return nil, 0, fmt.Errorf("%w: evidence attachment digest mismatch", shared.ErrValidation)
		}
		mediaType, ok := documentImageMediaType(data)
		if !ok {
			return nil, 0, fmt.Errorf("%w: claimed evidence image is not PNG or JPEG", shared.ErrValidation)
		}
		if total+len(data) > maxArtifactImageBytes {
			omitted++
			continue
		}
		extension := ".png"
		if mediaType == "image/jpeg" {
			extension = ".jpg"
		}
		images = append(images, ports.DocumentImage{Name: "evidence-" + hash + extension, MediaType: mediaType, Data: append([]byte(nil), data...)})
		total += len(data)
	}
	return images, omitted, nil
}

func claimedDocumentImage(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg")
}

func (b *ArtifactBuilder) buildClosure(ctx context.Context, tenant shared.ID, source document.Source) (ports.DocumentArtifact, error) {
	if !strings.HasPrefix(source.SourceRef, "assessment-cycle:") || strings.TrimPrefix(source.SourceRef, "assessment-cycle:") == "" {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: assessment closure source_ref must identify its cycle", shared.ErrValidation)
	}
	return b.buildClosureByProjectScope(ctx, tenant, source)
}

// buildClosureByProjectScope finds the cycle named in SourceRef only through the
// stable identifier. The store has no GetCycle-by-project operation, so callers
// provide the cycle ID after the prefix; this keeps source.ScopeID as its required
// project scope while avoiding a tenant-wide scan.
func (b *ArtifactBuilder) buildClosureByProjectScope(ctx context.Context, tenant shared.ID, source document.Source) (ports.DocumentArtifact, error) {
	cycleID := shared.ID(strings.TrimPrefix(source.SourceRef, "assessment-cycle:"))
	if cycleID.IsZero() {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: assessment cycle source_ref is required", shared.ErrValidation)
	}
	cycle, err := b.cycles.GetCycle(ctx, tenant, cycleID)
	if err != nil {
		return ports.DocumentArtifact{}, fmt.Errorf("read assessment cycle document source: %w", err)
	}
	if cycle == nil || cycle.TenantID != tenant || cycle.ID != cycleID || cycle.ProjectID != source.ScopeID {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: assessment cycle is outside document project scope", shared.ErrNotFound)
	}
	manifest, err := b.closures.GetActiveClosureManifest(ctx, tenant, cycleID)
	if err != nil {
		return ports.DocumentArtifact{}, fmt.Errorf("read active closure manifest: %w", err)
	}
	if manifest == nil || manifest.TenantID != tenant || manifest.CycleID != cycleID || manifest.SealedAt == nil || manifest.ID.IsZero() {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: active closure manifest is not sealed", shared.ErrValidation)
	}
	finalHead, evidenceParagraphs, err := b.closureEvidence(ctx, tenant, cycleID, manifest.FinalAssessmentID)
	if err != nil {
		return ports.DocumentArtifact{}, err
	}
	stored, err := b.closurePDF.Render(ctx, tenant, cycleID, manifest.ID)
	if err != nil {
		return ports.DocumentArtifact{}, fmt.Errorf("render verified closure report: %w", err)
	}
	if stored.TenantID != tenant || stored.CycleID != cycleID || stored.ManifestID != manifest.ID || len(stored.Content) == 0 || stored.ContentHash == "" || stored.ContentHash != artifactBytesDigest(stored.Content) {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: rendered closure report ownership or integrity mismatch", shared.ErrValidation)
	}
	paragraphs, err := closureParagraphs(stored.Content)
	if err != nil {
		return ports.DocumentArtifact{}, err
	}
	paragraphs = append(paragraphs, evidenceParagraphs...)
	projection := ports.DocumentArtifact{
		Title:          "Assessment closure report: " + strings.TrimSpace(cycle.Name),
		Paragraphs:     paragraphs,
		EvidenceHead:   finalHead,
		SourceRevision: "closure:" + manifest.ID.String() + ":" + strings.TrimSpace(stored.ContentHash),
		GeneratedAt:    stored.GeneratedAt.UTC(),
	}
	pdf, err := b.projector.RenderDocumentArtifact(ctx, projection)
	if err != nil {
		return ports.DocumentArtifact{}, fmt.Errorf("render closure PDF projection: %w", err)
	}
	projection.PDF = pdf
	return normalizeArtifact(projection)
}

func (b *ArtifactBuilder) closureEvidence(ctx context.Context, tenant, cycleID, finalAssessmentID shared.ID) (string, []string, error) {
	if b.integrity == nil {
		return "", nil, fmt.Errorf("%w: closure evidence integrity provider is required", shared.ErrValidation)
	}
	if finalAssessmentID.IsZero() {
		return "", nil, fmt.Errorf("%w: closure final assessment is required", shared.ErrValidation)
	}
	members, err := b.cycles.ListMembers(ctx, tenant, cycleID)
	if err != nil {
		return "", nil, fmt.Errorf("list closure assessment members: %w", err)
	}
	if len(members) == 0 || len(members) > 1000 {
		return "", nil, fmt.Errorf("%w: closure assessment membership is unavailable or exceeds bounds", shared.ErrValidation)
	}
	finalFound := false
	finalHead := ""
	headLines := make([]string, 0, min(len(members), 12))
	omittedHeads := 0
	for _, member := range members {
		if member.TenantID != tenant || member.CycleID != cycleID || member.AssessmentID.IsZero() {
			return "", nil, fmt.Errorf("%w: closure assessment membership ownership mismatch", shared.ErrValidation)
		}
		insight, err := b.integrity.ReportInsight(ctx, member.AssessmentID)
		if err != nil {
			return "", nil, fmt.Errorf("read closure assessment evidence: %w", err)
		}
		if insight.EvidenceCount > 0 && !insight.EvidenceIntact {
			return "", nil, fmt.Errorf("%w: evidence chain verification failed – document blocked", shared.ErrValidation)
		}
		head := strings.TrimSpace(insight.EvidenceHead)
		if head != "" && !validArtifactHash(head) {
			return "", nil, fmt.Errorf("%w: closure evidence chain head is invalid", shared.ErrValidation)
		}
		if member.AssessmentID == finalAssessmentID {
			finalFound, finalHead = true, head
			continue
		}
		if head == "" {
			continue
		}
		if len(headLines) < 10 {
			headLines = append(headLines, "Verified evidence-chain head for assessment "+member.AssessmentID.String()+": "+head)
		} else {
			omittedHeads++
		}
	}
	if !finalFound {
		return "", nil, fmt.Errorf("%w: closure final assessment is not a cycle member", shared.ErrValidation)
	}
	paragraphs := []string{fmt.Sprintf("Verified evidence chains for %d closure assessments.", len(members))}
	if finalHead == "" {
		paragraphs = append(paragraphs, "Final assessment evidence-chain head: none (no verified evidence-chain head is available).")
	} else {
		paragraphs = append(paragraphs, "Final assessment evidence-chain head: "+finalHead)
	}
	paragraphs = append(paragraphs, headLines...)
	if omittedHeads > 0 {
		paragraphs = append(paragraphs, fmt.Sprintf("Additional verified evidence-chain heads omitted from this bounded projection: %d.", omittedHeads))
	}
	return finalHead, paragraphs, nil
}

func artifactBytesDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (b *ArtifactBuilder) buildQuality(ctx context.Context, tenant shared.ID, source document.Source) (ports.DocumentArtifact, error) {
	if source.SourceRef != ProjectQualitySourceRef(source.ScopeID) {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: project quality source_ref must identify its project", shared.ErrValidation)
	}
	summary, err := b.quality.ReadProjectQualitySummary(ctx, tenant, source.ScopeID)
	if err != nil {
		return ports.DocumentArtifact{}, fmt.Errorf("read project quality document source: %w", err)
	}
	if summary.TenantID != tenant || summary.ProjectID != source.ScopeID || !summary.IntegrityVerified {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: project quality source ownership or integrity mismatch", shared.ErrValidation)
	}
	evidenceHead, err := b.projectQualityEvidence(ctx, tenant, source.ScopeID)
	if err != nil {
		return ports.DocumentArtifact{}, err
	}
	projection := ports.DocumentArtifact{
		Title:          summary.Title,
		Paragraphs:     append([]string(nil), summary.Paragraphs...),
		EvidenceHead:   evidenceHead,
		SourceRevision: summary.SourceRevision,
		GeneratedAt:    summary.GeneratedAt.UTC(),
		Images:         cloneImages(summary.Images),
	}
	pdf, err := b.projector.RenderDocumentArtifact(ctx, projection)
	if err != nil {
		return ports.DocumentArtifact{}, fmt.Errorf("render project quality PDF projection: %w", err)
	}
	projection.PDF = pdf
	return normalizeArtifact(projection)
}

func (b *ArtifactBuilder) projectQualityEvidence(ctx context.Context, tenant, projectID shared.ID) (string, error) {
	if b.integrity == nil {
		return "", fmt.Errorf("%w: project quality evidence integrity provider is required", shared.ErrValidation)
	}
	eng, err := b.engagements.GetByProjectID(ctx, tenant, projectID)
	if err != nil {
		return "", fmt.Errorf("read project quality evidence context: %w", err)
	}
	if eng == nil || eng.TenantID != tenant || eng.ProjectID != projectID || eng.ID.IsZero() {
		return "", fmt.Errorf("%w: project quality evidence context ownership mismatch", shared.ErrNotFound)
	}
	insight, err := b.integrity.ReportInsight(ctx, eng.ID)
	if err != nil {
		return "", fmt.Errorf("read project quality evidence: %w", err)
	}
	if insight.EvidenceCount > 0 && !insight.EvidenceIntact {
		return "", fmt.Errorf("%w: evidence chain verification failed – document blocked", shared.ErrValidation)
	}
	head := strings.TrimSpace(insight.EvidenceHead)
	if head != "" && !validArtifactHash(head) {
		return "", fmt.Errorf("%w: project quality evidence chain head is invalid", shared.ErrValidation)
	}
	return head, nil
}

func closureParagraphs(content []byte) ([]string, error) {
	var document closureuc.ClosureReportDocument
	if err := json.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("%w: invalid stored closure report JSON", shared.ErrValidation)
	}
	if strings.TrimSpace(document.ReportHash) == "" || strings.TrimSpace(document.Report.Cycle.ID) == "" || strings.TrimSpace(document.Report.Manifest.ID) == "" || strings.TrimSpace(document.Report.Manifest.ContentHash) == "" {
		return nil, fmt.Errorf("%w: incomplete stored closure report", shared.ErrValidation)
	}
	return projectClosureFacts(document), nil
}

// projectClosureFacts renders only typed fields from the stored, sealed closure
// payload. It deliberately does not query live findings or generate prose: the
// comparison and closure decisions are exactly those captured at seal time.
func projectClosureFacts(document closureuc.ClosureReportDocument) []string {
	const (
		maxClosureFacts     = maxArtifactParagraphs - 16
		maxClosureFactBytes = maxArtifactTextBytes / 2
	)
	paragraphs := make([]string, 0, 32)
	omitted, textBytes := 0, 0
	appendFact := func(value string) {
		value = boundedArtifactParagraph(value)
		if value == "" {
			return
		}
		if len(paragraphs) >= maxClosureFacts || textBytes+len(value) > maxClosureFactBytes {
			omitted++
			return
		}
		paragraphs = append(paragraphs, value)
		textBytes += len(value)
	}
	report := document.Report
	summary := report.Comparison.Summary
	appendFact("This closure report is projected from a verified sealed JSON artifact.")
	appendFact("Assessment cycle: " + report.Cycle.ID)
	appendFact(fmt.Sprintf("Cycle version: %d", report.Cycle.Version))
	appendFact("Manifest: " + report.Manifest.ID)
	appendFact("Manifest content hash: " + report.Manifest.ContentHash)
	appendFact("Initial snapshot hash: " + report.InitialSnapshot.ContentHash)
	appendFact("Final snapshot hash: " + report.FinalSnapshot.ContentHash)
	appendFact("Comparison hash: " + report.Comparison.ContentHash)
	appendFact("Closure report hash: " + document.ReportHash)
	appendFact(fmt.Sprintf("Baseline findings: %d; current findings: %d; fixed findings: %d; new findings: %d; reopened findings: %d.", summary.BaselineCount, summary.CurrentCount, summary.FixedCount, summary.NewCount, summary.ReopenedCount))
	appendFact(fmt.Sprintf("Baseline risk: %d; current risk: %d; new risk: %d; reopened risk: %d.", summary.BaselineRisk, summary.CurrentRisk, summary.NewRisk, summary.ReopenedRisk))
	appendFact(fmt.Sprintf("Baseline severity: critical=%d, high=%d, medium=%d, low=%d, info=%d, unknown=%d.", summary.BaselineSeverity.Critical, summary.BaselineSeverity.High, summary.BaselineSeverity.Medium, summary.BaselineSeverity.Low, summary.BaselineSeverity.Info, summary.BaselineSeverity.Unknown))
	appendFact(fmt.Sprintf("Current severity: critical=%d, high=%d, medium=%d, low=%d, info=%d, unknown=%d.", summary.CurrentSeverity.Critical, summary.CurrentSeverity.High, summary.CurrentSeverity.Medium, summary.CurrentSeverity.Low, summary.CurrentSeverity.Info, summary.CurrentSeverity.Unknown))
	appendFact(fmt.Sprintf("Closure decision references: %d; scope profile changes: %d.", len(report.DecisionReferences), len(report.ScopeProfileChanges)))
	appendCoverageFacts(appendFact, "Initial", report.CoverageDecisions.Initial)
	appendCoverageFacts(appendFact, "Final", report.CoverageDecisions.Final)
	if reason := strings.TrimSpace(report.Manifest.Reason); reason != "" {
		appendFact("Closure reason: " + reason)
	}
	if override := strings.TrimSpace(report.Manifest.OverrideReason); override != "" {
		appendFact("Closure override reason: " + override)
	}
	appendFact(fmt.Sprintf("Non-final branches: %d.", len(report.NonFinalBranches)))
	for index, branch := range report.NonFinalBranches {
		if index >= 10 {
			omitted += len(report.NonFinalBranches) - index
			break
		}
		appendFact(fmt.Sprintf("Non-final branch assessment %s: relationship version %d; archived=%t.", branch.AssessmentID, branch.RelationshipVersion, branch.Archived))
	}
	if omitted > 0 {
		appendFact(fmt.Sprintf("Bounded closure projection omitted %d facts.", omitted))
	}
	return paragraphs
}

func appendCoverageFacts(appendFact func(string), label string, decisions []closuredom.CoverageDecision) {
	if len(decisions) == 0 {
		appendFact(label + " coverage decisions: none.")
		return
	}
	states := make(map[string]int)
	reasoned, waived := 0, 0
	for _, decision := range decisions {
		states[string(decision.State)]++
		if strings.TrimSpace(decision.ReasonCode) != "" {
			reasoned++
		}
		if decision.Waived {
			waived++
		}
	}
	keys := make([]string, 0, len(states))
	for state := range states {
		keys = append(keys, state)
	}
	sort.Strings(keys)
	stateCounts := make([]string, 0, len(keys))
	for _, state := range keys {
		stateCounts = append(stateCounts, fmt.Sprintf("%s=%d", state, states[state]))
	}
	appendFact(fmt.Sprintf("%s coverage decisions: %d (%s; reason-coded=%d; waived=%d).", label, len(decisions), strings.Join(stateCounts, ", "), reasoned, waived))
}

// validateArtifact is shared with release admission. It validates the same bounds
// after an artifact crosses a port, even though this builder already normalizes its
// own output.
func validateArtifact(artifact ports.DocumentArtifact) error {
	_, err := normalizeArtifact(artifact)
	return err
}

func normalizeArtifact(artifact ports.DocumentArtifact) (ports.DocumentArtifact, error) {
	artifact.Paragraphs = append([]string(nil), artifact.Paragraphs...)
	artifact.Images = cloneImages(artifact.Images)
	artifact.PDF = append([]byte(nil), artifact.PDF...)
	artifact.Title = strings.TrimSpace(artifact.Title)
	artifact.EvidenceHead = strings.TrimSpace(artifact.EvidenceHead)
	artifact.SourceRevision = strings.TrimSpace(artifact.SourceRevision)
	if !validArtifactText(artifact.Title, maxArtifactTitleBytes) || (artifact.Severity != "" && !artifact.Severity.Valid()) || artifact.GeneratedAt.IsZero() || !validArtifactText(artifact.SourceRevision, maxArtifactRevisionBytes) || len(artifact.PDF) == 0 || len(artifact.PDF) > maxArtifactPDFBytes || !bytes.HasPrefix(artifact.PDF, []byte("%PDF-")) || (artifact.EvidenceHead != "" && !validArtifactHash(artifact.EvidenceHead)) {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: invalid document artifact metadata or PDF bounds", shared.ErrValidation)
	}
	if len(artifact.Paragraphs) > maxArtifactParagraphs || len(artifact.Images) > maxArtifactImages {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: document artifact exceeds item bounds", shared.ErrValidation)
	}
	textBytes := 0
	for i, paragraph := range artifact.Paragraphs {
		artifact.Paragraphs[i] = strings.TrimSpace(paragraph)
		if !validArtifactText(artifact.Paragraphs[i], maxArtifactParagraphBytes) {
			return ports.DocumentArtifact{}, fmt.Errorf("%w: invalid document artifact paragraph", shared.ErrValidation)
		}
		textBytes += len(artifact.Paragraphs[i])
	}
	if textBytes > maxArtifactTextBytes {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: document artifact text exceeds bounds", shared.ErrValidation)
	}
	imageBytes := 0
	for i := range artifact.Images {
		image := &artifact.Images[i]
		image.Name = strings.TrimSpace(image.Name)
		image.MediaType = strings.TrimSpace(image.MediaType)
		if !validArtifactText(image.Name, 255) || len(image.Data) == 0 || len(image.Data) > maxArtifactImageBytes || !validArtifactImage(image.MediaType, image.Data) {
			return ports.DocumentArtifact{}, fmt.Errorf("%w: invalid document artifact image", shared.ErrValidation)
		}
		imageBytes += len(image.Data)
		image.Data = append([]byte(nil), image.Data...)
	}
	if imageBytes > maxArtifactImageBytes {
		return ports.DocumentArtifact{}, fmt.Errorf("%w: document artifact images exceed bounds", shared.ErrValidation)
	}
	artifact.GeneratedAt = artifact.GeneratedAt.UTC()
	return artifact, nil
}

func validArtifactText(value string, max int) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsRune(value, 0) && len(value) <= max
}

func validArtifactHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validArtifactImage(mediaType string, data []byte) bool {
	actual, ok := documentImageMediaType(data)
	return ok && mediaType == actual
}

func documentImageMediaType(data []byte) (string, bool) {
	switch {
	case bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}):
		return "image/png", bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return "image/jpeg", len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff
	default:
		return "", false
	}
}

func cloneImages(images []ports.DocumentImage) []ports.DocumentImage {
	out := make([]ports.DocumentImage, len(images))
	for i, image := range images {
		out[i] = image
		out[i].Data = append([]byte(nil), image.Data...)
	}
	return out
}
