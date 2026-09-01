package assessmentcycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	CodeClosureReferenceMissing  = "closure_reference_missing"
	CodeClosureReferenceTampered = "closure_reference_integrity_failed"
)

type AssessmentClosureReportJob struct {
	TenantID        shared.ID `json:"tenant_id"`
	CycleID         shared.ID `json:"cycle_id"`
	ManifestID      shared.ID `json:"manifest_id"`
	ManifestHash    string    `json:"manifest_hash"`
	RendererVersion string    `json:"renderer_contract_version"`
}

type ClosureReportService struct {
	closures    ports.AssessmentClosureRepository
	reports     ports.AssessmentClosureReportStore
	snapshots   ports.AssessmentSnapshotRepository
	comparisons ports.AssessmentComparisonRepository
	audit       ports.AuditLogger
	observer    ports.AssessmentClosureReportObserver
}

func NewClosureReportService(closures ports.AssessmentClosureRepository, reports ports.AssessmentClosureReportStore, snapshots ports.AssessmentSnapshotRepository, comparisons ports.AssessmentComparisonRepository, audit ports.AuditLogger) (*ClosureReportService, error) {
	if closures == nil || reports == nil || snapshots == nil || comparisons == nil || audit == nil {
		return nil, fmt.Errorf("%w: closure report dependencies are required", shared.ErrValidation)
	}
	return &ClosureReportService{closures: closures, reports: reports, snapshots: snapshots, comparisons: comparisons, audit: audit, observer: noopClosureReportObserver{}}, nil
}

func (service *ClosureReportService) SetObserver(observer ports.AssessmentClosureReportObserver) {
	if observer != nil {
		service.observer = observer
	}
}

type ClosureReportCycle struct {
	ID                string `json:"id"`
	Version           int64  `json:"version"`
	ManifestVersion   int64  `json:"manifest_version"`
	RootAssessmentID  string `json:"root_assessment_id"`
	FinalAssessmentID string `json:"final_assessment_id"`
}

type ClosureReportSnapshot struct {
	ID          string `json:"id"`
	ContentHash string `json:"content_hash"`
}

type ClosureReportComparison struct {
	ID          string         `json:"id"`
	ContentHash string         `json:"content_hash"`
	Summary     cmpdom.Summary `json:"summary"`
}

type ClosureReportManifest struct {
	ID                      string    `json:"id"`
	CanonicalInputHash      string    `json:"canonical_input_hash"`
	ContentHash             string    `json:"content_hash"`
	PolicyVersion           string    `json:"policy_version"`
	AlgorithmVersion        string    `json:"algorithm_version"`
	FingerprintVersion      string    `json:"fingerprint_version"`
	RiskVersion             string    `json:"risk_version"`
	RendererContractVersion string    `json:"renderer_contract_version"`
	Reason                  string    `json:"reason"`
	OverrideReason          string    `json:"override_reason,omitempty"`
	AsOfAt                  time.Time `json:"as_of_at"`
	CreatedAt               time.Time `json:"created_at"`
	CreatedBy               string    `json:"created_by"`
}

type ClosureReportPayload struct {
	SchemaVersion       int                             `json:"schema_version"`
	RendererVersion     string                          `json:"renderer_contract_version"`
	GeneratedAt         time.Time                       `json:"generated_at"`
	Cycle               ClosureReportCycle              `json:"cycle"`
	Path                []closuredom.PathMember         `json:"path"`
	InitialSnapshot     ClosureReportSnapshot           `json:"initial_snapshot"`
	FinalSnapshot       ClosureReportSnapshot           `json:"final_snapshot"`
	Comparison          ClosureReportComparison         `json:"comparison"`
	DecisionReferences  []closuredom.Reference          `json:"decision_references"`
	CoverageDecisions   closuredom.CoverageDecisions    `json:"coverage_decisions"`
	ScopeProfileChanges []closuredom.ScopeProfileChange `json:"scope_profile_changes"`
	OverrideBlockerIDs  []string                        `json:"override_blocker_ids"`
	NonFinalBranches    []closuredom.BranchState        `json:"non_final_branches"`
	Manifest            ClosureReportManifest           `json:"manifest"`
}

type ClosureReportDocument struct {
	ReportHash string               `json:"report_hash"`
	Report     ClosureReportPayload `json:"report"`
}

func (service *ClosureReportService) Render(ctx context.Context, tenantID, cycleID, manifestID shared.ID) (ports.AssessmentClosureReportArtifact, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	manifest, err := service.closures.GetClosureManifest(ctx, tenantID, cycleID, manifestID)
	if err != nil {
		service.observer.ObserveAssessmentClosureReport("failed", "manifest_read")
		return ports.AssessmentClosureReportArtifact{}, err
	}
	initialSnapshot, err := service.snapshots.Get(ctx, tenantID, manifest.InitialSnapshotID)
	if err != nil {
		return ports.AssessmentClosureReportArtifact{}, service.referenceError(ctx, tenantID, manifest, CodeClosureReferenceMissing, err)
	}
	finalSnapshot, err := service.snapshots.Get(ctx, tenantID, manifest.FinalSnapshotID)
	if err != nil {
		return ports.AssessmentClosureReportArtifact{}, service.referenceError(ctx, tenantID, manifest, CodeClosureReferenceMissing, err)
	}
	comparison, err := service.comparisons.Get(ctx, tenantID, manifest.ComparisonID)
	if err != nil {
		return ports.AssessmentClosureReportArtifact{}, service.referenceError(ctx, tenantID, manifest, CodeClosureReferenceMissing, err)
	}
	if !closureSnapshotMatches(initialSnapshot, manifest, true) || !closureSnapshotMatches(finalSnapshot, manifest, false) || !closureComparisonMatches(comparison, manifest) {
		return ports.AssessmentClosureReportArtifact{}, service.referenceError(ctx, tenantID, manifest, CodeClosureReferenceTampered, shared.ErrConflict)
	}
	if manifest.SealedAt == nil {
		return ports.AssessmentClosureReportArtifact{}, service.referenceError(ctx, tenantID, manifest, CodeClosureReferenceTampered, shared.ErrConflict)
	}
	if cached, err := service.reports.GetClosureReport(ctx, tenantID, cycleID, manifestID, manifest.RendererContractVersion); err == nil {
		if err := service.recordGeneratedAudit(ctx, manifest, cached, false); err != nil {
			service.observer.ObserveAssessmentClosureReport("failed", "audit")
			return ports.AssessmentClosureReportArtifact{}, err
		}
		service.observer.ObserveAssessmentClosureReport("cached", "none")
		return cached, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		service.observer.ObserveAssessmentClosureReport("failed", "artifact_read")
		return ports.AssessmentClosureReportArtifact{}, err
	}
	payload := ClosureReportPayload{
		SchemaVersion: 1, RendererVersion: manifest.RendererContractVersion, GeneratedAt: manifest.SealedAt.UTC().Truncate(time.Microsecond),
		Cycle:              ClosureReportCycle{ID: manifest.CycleID.String(), Version: manifest.CycleVersion, ManifestVersion: manifest.ManifestVersion, RootAssessmentID: manifest.RootAssessmentID.String(), FinalAssessmentID: manifest.FinalAssessmentID.String()},
		Path:               manifest.Path,
		InitialSnapshot:    ClosureReportSnapshot{ID: manifest.InitialSnapshotID.String(), ContentHash: manifest.InitialSnapshotHash},
		FinalSnapshot:      ClosureReportSnapshot{ID: manifest.FinalSnapshotID.String(), ContentHash: manifest.FinalSnapshotHash},
		Comparison:         ClosureReportComparison{ID: manifest.ComparisonID.String(), ContentHash: manifest.ComparisonHash, Summary: comparison.Summary},
		DecisionReferences: manifest.References, CoverageDecisions: manifest.CoverageDecisions, ScopeProfileChanges: manifest.ScopeProfileChanges,
		OverrideBlockerIDs: manifest.OverrideBlockerIDs, NonFinalBranches: manifest.NonFinalBranches,
		Manifest: ClosureReportManifest{
			ID: manifest.ID.String(), CanonicalInputHash: manifest.CanonicalInputHash, ContentHash: manifest.ContentHash,
			PolicyVersion: manifest.PolicyVersion, AlgorithmVersion: manifest.AlgorithmVersion, FingerprintVersion: manifest.FingerprintVersion, RiskVersion: manifest.RiskVersion,
			RendererContractVersion: manifest.RendererContractVersion, Reason: manifest.Reason, OverrideReason: manifest.OverrideReason,
			AsOfAt: manifest.AsOfAt, CreatedAt: manifest.CreatedAt, CreatedBy: manifest.CreatedBy,
		},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		service.observer.ObserveAssessmentClosureReport("failed", "render")
		return ports.AssessmentClosureReportArtifact{}, fmt.Errorf("marshal closure report payload: %w", err)
	}
	reportDigest := sha256.Sum256(payloadBytes)
	content, err := json.Marshal(ClosureReportDocument{ReportHash: hex.EncodeToString(reportDigest[:]), Report: payload})
	if err != nil {
		service.observer.ObserveAssessmentClosureReport("failed", "render")
		return ports.AssessmentClosureReportArtifact{}, fmt.Errorf("marshal closure report document: %w", err)
	}
	contentDigest := sha256.Sum256(content)
	artifact := ports.AssessmentClosureReportArtifact{
		TenantID: tenantID, CycleID: cycleID, ManifestID: manifestID, RendererContractVersion: manifest.RendererContractVersion,
		ContentHash: hex.EncodeToString(contentDigest[:]), Content: content, GeneratedAt: payload.GeneratedAt,
	}
	stored, created, err := service.reports.SaveClosureReport(ctx, artifact)
	if err != nil {
		service.observer.ObserveAssessmentClosureReport("failed", "artifact_write")
		return ports.AssessmentClosureReportArtifact{}, err
	}
	if err := service.recordGeneratedAudit(ctx, manifest, stored, created); err != nil {
		service.observer.ObserveAssessmentClosureReport("failed", "audit")
		return ports.AssessmentClosureReportArtifact{}, err
	}
	if created {
		service.observer.ObserveAssessmentClosureReport("generated", "none")
	} else {
		service.observer.ObserveAssessmentClosureReport("cached", "none")
	}
	return stored, nil
}

func (service *ClosureReportService) recordGeneratedAudit(ctx context.Context, manifest *closuredom.Manifest, artifact ports.AssessmentClosureReportArtifact, created bool) error {
	entry := ports.AuditEntry{Actor: "system:assessment-cycle-report", Action: "assessment_cycle.report_generated", Target: manifest.ID.String(), Metadata: map[string]string{
		"tenant_id": artifact.TenantID.String(), "cycle_id": artifact.CycleID.String(), "renderer_version": artifact.RendererContractVersion, "content_hash": artifact.ContentHash,
		"idempotency_key": "assessment-cycle-report:" + manifest.ID.String() + ":" + artifact.RendererContractVersion,
	}, At: artifact.GeneratedAt}
	if idempotent, ok := service.audit.(ports.IdempotentAuditLogger); ok {
		return idempotent.RecordOnce(ctx, entry)
	}
	if created {
		return service.audit.Record(ctx, entry)
	}
	return nil
}

func (service *ClosureReportService) HandleJob(ctx context.Context, job ports.QueuedJob) error {
	var payload AssessmentClosureReportJob
	decoder := json.NewDecoder(bytes.NewReader(job.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		service.observer.ObserveAssessmentClosureReport("failed", "invalid_job")
		return fmt.Errorf("decode assessment closure report job: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		service.observer.ObserveAssessmentClosureReport("failed", "invalid_job")
		return fmt.Errorf("decode assessment closure report job: trailing data")
	}
	if payload.TenantID != job.TenantID || payload.TenantID.IsZero() || payload.CycleID.IsZero() || payload.ManifestID.IsZero() || payload.ManifestHash == "" || payload.RendererVersion == "" {
		service.observer.ObserveAssessmentClosureReport("failed", "invalid_job")
		return fmt.Errorf("%w: assessment closure report job identity is invalid", shared.ErrValidation)
	}
	manifest, err := service.closures.GetClosureManifest(ctx, payload.TenantID, payload.CycleID, payload.ManifestID)
	if err != nil {
		return err
	}
	if manifest.ContentHash != payload.ManifestHash || manifest.RendererContractVersion != payload.RendererVersion {
		return service.referenceError(ctx, payload.TenantID, manifest, CodeClosureReferenceTampered, shared.ErrConflict)
	}
	_, err = service.Render(ctx, payload.TenantID, payload.CycleID, payload.ManifestID)
	return err
}

func (service *ClosureReportService) referenceError(ctx context.Context, tenantID shared.ID, manifest *closuredom.Manifest, code string, cause error) error {
	service.observer.ObserveAssessmentClosureReport("failed", code)
	_ = service.audit.Record(ctx, ports.AuditEntry{Actor: "system:assessment-cycle-report", Action: "assessment_cycle.report_reference_failed", Target: manifest.ID.String(), Metadata: map[string]string{
		"tenant_id": tenantID.String(), "cycle_id": manifest.CycleID.String(), "reason_code": code,
	}, At: time.Now().UTC()})
	return &APIError{Code: code, Cause: cause}
}

type noopClosureReportObserver struct{}

func (noopClosureReportObserver) ObserveAssessmentClosureReport(string, string) {}

func closureSnapshotMatches(snapshot *assessmentsnapshot.Snapshot, manifest *closuredom.Manifest, initial bool) bool {
	if snapshot == nil || snapshot.TenantID != manifest.TenantID || snapshot.CycleID != manifest.CycleID ||
		(snapshot.Lifecycle != assessmentsnapshot.LifecycleFinalized && snapshot.Lifecycle != assessmentsnapshot.LifecycleSuperseded) {
		return false
	}
	if initial {
		return snapshot.ID == manifest.InitialSnapshotID && snapshot.AssessmentID == manifest.RootAssessmentID && snapshot.ContentHash == manifest.InitialSnapshotHash
	}
	return snapshot.ID == manifest.FinalSnapshotID && snapshot.AssessmentID == manifest.FinalAssessmentID && snapshot.ContentHash == manifest.FinalSnapshotHash
}

func closureComparisonMatches(comparison cmpdom.Comparison, manifest *closuredom.Manifest) bool {
	return comparison.TenantID == manifest.TenantID && comparison.CycleID == manifest.CycleID && comparison.ID == manifest.ComparisonID &&
		comparison.BaselineSnapshotID == manifest.InitialSnapshotID && comparison.CurrentSnapshotID == manifest.FinalSnapshotID && comparison.Mode == cmpdom.ModeLifecycle &&
		(comparison.Status == cmpdom.StatusComplete || comparison.Status == cmpdom.StatusSuperseded) && comparison.ContentHash == manifest.ComparisonHash &&
		comparison.Summary.ComparisonID == comparison.ID && comparison.Summary.BaselineSnapshotID == comparison.BaselineSnapshotID && comparison.Summary.CurrentSnapshotID == comparison.CurrentSnapshotID
}

func (service *APIService) GetClosureReport(ctx context.Context, tenantID, cycleID, manifestID shared.ID) (ports.AssessmentClosureReportArtifact, error) {
	if service.closure == nil || service.closure.reporter == nil {
		return ports.AssessmentClosureReportArtifact{}, &APIError{Code: CodeClosureWorkflowDisabled, Cause: shared.ErrValidation}
	}
	return service.closure.reporter.Render(ctx, shared.TenantOrDefault(tenantID), cycleID, manifestID)
}

func (service *APIService) SetClosureReportObserver(observer ports.AssessmentClosureReportObserver) {
	if service.closure != nil && service.closure.reporter != nil {
		service.closure.reporter.SetObserver(observer)
	}
}
