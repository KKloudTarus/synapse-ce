package assessmentcycle

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	CodeClosurePreviewStale     = "closure_preview_stale"
	CodeReopenPreviewStale      = "reopen_preview_stale"
	CodeCycleVersionConflict    = "cycle_version_conflict"
	CodeClosureBlocked          = "closure_blocked"
	CodeClosureReasonRequired   = "closure_reason_required"
	CodeReopenReasonRequired    = "reopen_reason_required"
	CodeClosureWorkflowDisabled = "closure_workflow_unavailable"

	closurePreviewTTL = 5 * time.Minute
)

const AssessmentClosureReportJobKind = "assessment_cycle_report"

type closureSupport struct {
	store       ports.AssessmentClosureRepository
	snapshots   ports.AssessmentSnapshotRepository
	comparisons ports.AssessmentComparisonRepository
	queue       ports.JobQueue
	reporter    *ClosureReportService
	tokenKey    []byte
}

func (service *APIService) SetClosureDependencies(store ports.AssessmentClosureRepository, snapshots ports.AssessmentSnapshotRepository, comparisons ports.AssessmentComparisonRepository, queue ports.JobQueue, tokenKey []byte) error {
	if store == nil || snapshots == nil || comparisons == nil || queue == nil || service.audit == nil || len(tokenKey) < 32 {
		return fmt.Errorf("%w: closure store, immutable artifacts, queue, audit, and a 32-byte token key are required", shared.ErrValidation)
	}
	reports, ok := store.(ports.AssessmentClosureReportStore)
	if !ok {
		return fmt.Errorf("%w: closure store does not support immutable report artifacts", shared.ErrValidation)
	}
	reporter, err := NewClosureReportService(store, reports, snapshots, comparisons, service.audit)
	if err != nil {
		return err
	}
	service.closure = &closureSupport{store: store, snapshots: snapshots, comparisons: comparisons, queue: queue, reporter: reporter, tokenKey: append([]byte(nil), tokenKey...)}
	return nil
}

type ClosurePreviewInput struct {
	TenantID           shared.ID
	Actor              string
	CycleID            shared.ID
	Reason             string
	OverrideBlockerIDs []string
	OverrideReason     string
}

type ClosurePreview struct {
	CycleID             string                          `json:"cycle_id"`
	CycleVersion        int64                           `json:"cycle_version"`
	ManifestVersion     int64                           `json:"manifest_version"`
	FinalAssessmentID   string                          `json:"final_assessment_id"`
	Path                []closuredom.PathMember         `json:"path"`
	NonFinalBranches    []closuredom.BranchState        `json:"non_final_branches"`
	InitialSnapshotID   string                          `json:"initial_snapshot_id,omitempty"`
	FinalSnapshotID     string                          `json:"final_snapshot_id,omitempty"`
	ComparisonID        string                          `json:"comparison_id,omitempty"`
	Policy              closuredom.PolicyResult         `json:"policy"`
	References          []closuredom.Reference          `json:"references"`
	ScopeProfileChanges []closuredom.ScopeProfileChange `json:"scope_profile_changes"`
	RendererVersion     string                          `json:"renderer_contract_version"`
	ExpiresAt           time.Time                       `json:"expires_at,omitempty"`
	PreviewToken        string                          `json:"preview_token,omitempty"`
}

type ClosureCommitInput struct {
	Request            RetainedRequest
	CycleID            shared.ID
	ExpectedVersion    int64
	PreviewToken       string
	Reason             string
	OverrideBlockerIDs []string
	OverrideReason     string
}

type ClosureCommitResult struct {
	Cycle       CycleView           `json:"cycle"`
	Manifest    ClosureManifestView `json:"manifest"`
	ReportJobID string              `json:"report_job_id"`
}

type ReopenPreviewInput struct {
	TenantID shared.ID
	Actor    string
	CycleID  shared.ID
}

type ReopenPreview struct {
	CycleID      string              `json:"cycle_id"`
	CycleVersion int64               `json:"cycle_version"`
	Manifest     ClosureManifestView `json:"manifest"`
	Impact       string              `json:"impact"`
	ExpiresAt    time.Time           `json:"expires_at,omitempty"`
	PreviewToken string              `json:"preview_token,omitempty"`
}

type ReopenCommitInput struct {
	Request         RetainedRequest
	CycleID         shared.ID
	ExpectedVersion int64
	PreviewToken    string
	Reason          string
}

type ReopenCommitResult struct {
	Cycle              CycleView           `json:"cycle"`
	SupersededManifest ClosureManifestView `json:"superseded_manifest"`
}

type ClosureManifestView struct {
	ID                      string                          `json:"id"`
	CycleID                 string                          `json:"cycle_id"`
	ManifestVersion         int64                           `json:"manifest_version"`
	Lifecycle               closuredom.Lifecycle            `json:"lifecycle"`
	CycleVersion            int64                           `json:"cycle_version"`
	RootAssessmentID        string                          `json:"root_assessment_id"`
	FinalAssessmentID       string                          `json:"final_assessment_id"`
	InitialSnapshotID       string                          `json:"initial_snapshot_id"`
	FinalSnapshotID         string                          `json:"final_snapshot_id"`
	ComparisonID            string                          `json:"comparison_id"`
	InitialSnapshotHash     string                          `json:"initial_snapshot_hash"`
	FinalSnapshotHash       string                          `json:"final_snapshot_hash"`
	ComparisonHash          string                          `json:"comparison_hash"`
	CanonicalInputHash      string                          `json:"canonical_input_hash"`
	ContentHash             string                          `json:"content_hash"`
	PolicyVersion           string                          `json:"policy_version"`
	AlgorithmVersion        string                          `json:"algorithm_version"`
	FingerprintVersion      string                          `json:"fingerprint_version"`
	RiskVersion             string                          `json:"risk_version"`
	RendererContractVersion string                          `json:"renderer_contract_version"`
	CoverageDecisions       closuredom.CoverageDecisions    `json:"coverage_decisions"`
	ScopeProfileChanges     []closuredom.ScopeProfileChange `json:"scope_profile_changes"`
	OverrideBlockerIDs      []string                        `json:"override_blocker_ids"`
	NonFinalBranches        []closuredom.BranchState        `json:"non_final_branches"`
	Path                    []closuredom.PathMember         `json:"path"`
	References              []closuredom.Reference          `json:"references"`
	Reason                  string                          `json:"reason"`
	OverrideReason          string                          `json:"override_reason,omitempty"`
	AsOfAt                  time.Time                       `json:"as_of_at"`
	CreatedAt               time.Time                       `json:"created_at"`
	CreatedBy               string                          `json:"created_by"`
	SealedAt                *time.Time                      `json:"sealed_at,omitempty"`
	SealedBy                string                          `json:"sealed_by,omitempty"`
	SupersededAt            *time.Time                      `json:"superseded_at,omitempty"`
}

type closurePreviewState struct {
	cycle           *cycledom.AssessmentCycle
	initialSnapshot *assessmentsnapshot.Snapshot
	finalSnapshot   *assessmentsnapshot.Snapshot
	comparison      *cmpdom.Comparison
	path            []closuredom.PathMember
	branches        []closuredom.BranchState
	references      []closuredom.Reference
	scopeChanges    []closuredom.ScopeProfileChange
	policy          closuredom.PolicyResult
	manifestVersion int64
	bindingHash     string
}

type closureBinding struct {
	CycleID             shared.ID                       `json:"cycle_id"`
	CycleVersion        int64                           `json:"cycle_version"`
	RootAssessmentID    shared.ID                       `json:"root_assessment_id"`
	FinalAssessmentID   shared.ID                       `json:"final_assessment_id"`
	ManifestVersion     int64                           `json:"manifest_version"`
	Path                []closuredom.PathMember         `json:"path"`
	NonFinalBranches    []closuredom.BranchState        `json:"non_final_branches"`
	InitialSnapshotID   shared.ID                       `json:"initial_snapshot_id"`
	InitialSnapshotHash string                          `json:"initial_snapshot_hash"`
	FinalSnapshotID     shared.ID                       `json:"final_snapshot_id"`
	FinalSnapshotHash   string                          `json:"final_snapshot_hash"`
	ComparisonID        shared.ID                       `json:"comparison_id"`
	ComparisonHash      string                          `json:"comparison_hash"`
	ComparisonVersion   int64                           `json:"comparison_version"`
	Policy              closuredom.PolicyResult         `json:"policy"`
	References          []closuredom.Reference          `json:"references"`
	ScopeProfileChanges []closuredom.ScopeProfileChange `json:"scope_profile_changes"`
	ReasonHash          string                          `json:"reason_hash"`
	OverrideReasonHash  string                          `json:"override_reason_hash"`
}

type closurePreviewToken struct {
	Kind            string    `json:"kind"`
	TenantID        shared.ID `json:"tenant_id"`
	Actor           string    `json:"actor"`
	CycleID         shared.ID `json:"cycle_id"`
	CycleVersion    int64     `json:"cycle_version"`
	ManifestVersion int64     `json:"manifest_version"`
	BindingHash     string    `json:"binding_hash"`
	AsOfAt          time.Time `json:"as_of_at"`
	Nonce           string    `json:"nonce"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (service *APIService) PreviewClosure(ctx context.Context, input ClosurePreviewInput) (ClosurePreview, error) {
	if service.closure == nil {
		return ClosurePreview{}, &APIError{Code: CodeClosureWorkflowDisabled, Cause: shared.ErrValidation}
	}
	input.TenantID, input.Actor = shared.TenantOrDefault(input.TenantID), strings.TrimSpace(input.Actor)
	input.Reason, input.OverrideReason = strings.TrimSpace(input.Reason), strings.TrimSpace(input.OverrideReason)
	input.OverrideBlockerIDs = canonicalClosureStrings(input.OverrideBlockerIDs)
	if input.TenantID.IsZero() || input.CycleID.IsZero() || input.Actor == "" || !safeClosureText(input.Reason) || !safeClosureText(input.OverrideReason) {
		return ClosurePreview{}, fmt.Errorf("%w: closure preview ownership or reason is invalid", shared.ErrValidation)
	}
	asOfAt := service.clock.Now().UTC().Truncate(time.Microsecond)
	state, err := service.buildClosurePreviewState(ctx, input.TenantID, input.CycleID, input.Reason, input.OverrideBlockerIDs, input.OverrideReason, asOfAt)
	if err != nil {
		return ClosurePreview{}, err
	}
	preview := projectClosurePreview(state)
	if !state.policy.CommitAllowed {
		return preview, nil
	}
	if input.Reason == "" {
		preview.Policy.Blockers = append(preview.Policy.Blockers, closuredom.Blocker{ID: "closure:reason_required", Code: CodeClosureReasonRequired, Message: "Closure reason is required."})
		preview.Policy.CommitAllowed = false
		return preview, nil
	}
	expiresAt := asOfAt.Add(closurePreviewTTL)
	nonce, err := randomClosureNonce()
	if err != nil {
		return ClosurePreview{}, err
	}
	token, err := service.signClosurePreview(closurePreviewToken{
		Kind: "closure", TenantID: input.TenantID, Actor: input.Actor, CycleID: input.CycleID, CycleVersion: state.cycle.Version,
		ManifestVersion: state.manifestVersion, BindingHash: state.bindingHash, AsOfAt: asOfAt, Nonce: nonce, ExpiresAt: expiresAt,
	})
	if err != nil {
		return ClosurePreview{}, err
	}
	preview.ExpiresAt, preview.PreviewToken = expiresAt, token
	return preview, nil
}

func (service *APIService) CommitClosure(ctx context.Context, input ClosureCommitInput) (RetainedResponse, error) {
	if service.closure == nil {
		return RetainedResponse{}, &APIError{Code: CodeClosureWorkflowDisabled, Cause: shared.ErrValidation}
	}
	input.Reason, input.OverrideReason = strings.TrimSpace(input.Reason), strings.TrimSpace(input.OverrideReason)
	input.OverrideBlockerIDs = canonicalClosureStrings(input.OverrideBlockerIDs)
	if input.CycleID.IsZero() || input.ExpectedVersion < 1 || strings.TrimSpace(input.PreviewToken) == "" {
		return RetainedResponse{}, &APIError{Code: CodeClosurePreviewStale, Cause: shared.ErrConflict}
	}
	if input.Reason == "" || !safeClosureText(input.Reason) || !safeClosureText(input.OverrideReason) {
		return RetainedResponse{}, &APIError{Code: CodeClosureReasonRequired, Cause: shared.ErrValidation}
	}
	tokenHash := sha256.Sum256([]byte(input.PreviewToken))
	canonical := struct {
		CycleID            shared.ID `json:"cycle_id"`
		ExpectedVersion    int64     `json:"expected_version"`
		PreviewTokenHash   string    `json:"preview_token_hash"`
		Reason             string    `json:"reason"`
		OverrideBlockerIDs []string  `json:"override_blocker_ids"`
		OverrideReason     string    `json:"override_reason"`
	}{input.CycleID, input.ExpectedVersion, hex.EncodeToString(tokenHash[:]), input.Reason, input.OverrideBlockerIDs, input.OverrideReason}
	return service.executeRetained(ctx, input.Request, canonical, func(txCtx context.Context) (int, any, error) {
		token, err := service.verifyClosurePreview(input.PreviewToken, "closure", CodeClosurePreviewStale)
		if err != nil {
			return 0, nil, err
		}
		tenantID, actor := shared.TenantOrDefault(input.Request.TenantID), strings.TrimSpace(input.Request.Actor)
		if token.TenantID != tenantID || token.Actor != actor || token.CycleID != input.CycleID {
			return 0, nil, &APIError{Code: CodeClosurePreviewStale, Cause: shared.ErrConflict}
		}
		if token.CycleVersion != input.ExpectedVersion {
			return 0, nil, &APIError{Code: CodeCycleVersionConflict, Cause: shared.ErrConflict}
		}
		now := service.clock.Now().UTC().Truncate(time.Microsecond)
		if !now.Before(token.ExpiresAt) {
			return 0, nil, &APIError{Code: CodeClosurePreviewStale, Cause: shared.ErrConflict}
		}
		state, err := service.buildClosurePreviewState(txCtx, tenantID, input.CycleID, input.Reason, input.OverrideBlockerIDs, input.OverrideReason, token.AsOfAt)
		if err != nil {
			return 0, nil, err
		}
		if state.cycle.Version != input.ExpectedVersion {
			if state.cycle.Status == cycledom.StatusCompleted && !state.cycle.ActiveClosureManifestID.IsZero() {
				return 0, nil, &APIError{Code: CodeClosurePreviewStale, Cause: shared.ErrConflict}
			}
			return 0, nil, &APIError{Code: CodeCycleVersionConflict, Cause: shared.ErrConflict}
		}
		if !state.policy.CommitAllowed {
			return 0, nil, &APIError{Code: CodeClosureBlocked, Cause: shared.ErrConflict}
		}
		if state.bindingHash != token.BindingHash || state.manifestVersion != token.ManifestVersion || closureReferencesExpired(state.references, now) {
			return 0, nil, &APIError{Code: CodeClosurePreviewStale, Cause: shared.ErrConflict}
		}
		manifestID := service.cycles.ids.NewID()
		manifest, err := closuredom.NewManifest(manifestID, closuredom.ManifestInput{
			TenantID: tenantID, CycleID: state.cycle.ID, ManifestVersion: state.manifestVersion, CycleVersion: state.cycle.Version + 1,
			RootAssessmentID: state.cycle.RootAssessmentID, FinalAssessmentID: state.cycle.SelectedHeadAssessmentID,
			InitialSnapshot: state.initialSnapshot, FinalSnapshot: state.finalSnapshot, Comparison: state.comparison,
			CoverageDecisions: state.policy.CoverageDecisions, ScopeProfileChanges: state.scopeChanges, OverrideBlockerIDs: input.OverrideBlockerIDs,
			NonFinalBranches: state.branches, Path: state.path, References: state.references,
			Reason: input.Reason, OverrideReason: input.OverrideReason, AsOfAt: token.AsOfAt, CreatedAt: now, CreatedBy: actor,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := manifest.Seal(now, actor); err != nil {
			return 0, nil, err
		}
		cycle := *state.cycle
		if err := cycle.CompleteWithManifest(manifest.ID, input.ExpectedVersion, actor, now); err != nil {
			return 0, nil, mapClosureConflict(err)
		}
		if err := service.closure.store.CommitClosure(txCtx, ports.AssessmentClosureCommit{Manifest: manifest, Cycle: &cycle, ExpectedCycleVersion: input.ExpectedVersion}); err != nil {
			return 0, nil, mapClosureConflict(err)
		}
		if err := service.audit.Record(txCtx, ports.AuditEntry{Actor: actor, Action: "assessment_cycle.closed", Target: cycle.ID.String(), Metadata: map[string]string{
			"tenant_id": tenantID.String(), "manifest_id": manifest.ID.String(), "manifest_hash": manifest.ContentHash,
			"cycle_version": fmt.Sprintf("%d", cycle.Version), "idempotency_key": strings.TrimSpace(input.Request.IdempotencyKey),
		}, At: now}); err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(AssessmentClosureReportJob{
			TenantID: tenantID, CycleID: cycle.ID, ManifestID: manifest.ID, ManifestHash: manifest.ContentHash, RendererVersion: manifest.RendererContractVersion,
		})
		if err != nil {
			return 0, nil, err
		}
		reportJobID, err := service.closure.queue.Enqueue(txCtx, AssessmentClosureReportJobKind, payload)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ClosureCommitResult{Cycle: projectCycle(&cycle), Manifest: projectClosureManifest(manifest), ReportJobID: reportJobID}, nil
	}, noAssessmentCycleCompensation)
}

func (service *APIService) PreviewReopen(ctx context.Context, input ReopenPreviewInput) (ReopenPreview, error) {
	if service.closure == nil {
		return ReopenPreview{}, &APIError{Code: CodeClosureWorkflowDisabled, Cause: shared.ErrValidation}
	}
	tenantID, actor := shared.TenantOrDefault(input.TenantID), strings.TrimSpace(input.Actor)
	if tenantID.IsZero() || input.CycleID.IsZero() || actor == "" {
		return ReopenPreview{}, fmt.Errorf("%w: reopen preview ownership is required", shared.ErrValidation)
	}
	cycle, manifest, bindingHash, err := service.buildReopenState(ctx, tenantID, input.CycleID)
	if err != nil {
		return ReopenPreview{}, err
	}
	asOfAt := service.clock.Now().UTC().Truncate(time.Microsecond)
	expiresAt := asOfAt.Add(closurePreviewTTL)
	nonce, err := randomClosureNonce()
	if err != nil {
		return ReopenPreview{}, err
	}
	token, err := service.signClosurePreview(closurePreviewToken{
		Kind: "reopen", TenantID: tenantID, Actor: actor, CycleID: cycle.ID, CycleVersion: cycle.Version,
		ManifestVersion: manifest.ManifestVersion, BindingHash: bindingHash, AsOfAt: asOfAt, Nonce: nonce, ExpiresAt: expiresAt,
	})
	if err != nil {
		return ReopenPreview{}, err
	}
	return ReopenPreview{CycleID: cycle.ID.String(), CycleVersion: cycle.Version, Manifest: projectClosureManifest(manifest), Impact: "The active manifest remains immutable and becomes superseded; the Cycle returns to open.", ExpiresAt: expiresAt, PreviewToken: token}, nil
}

func (service *APIService) CommitReopen(ctx context.Context, input ReopenCommitInput) (RetainedResponse, error) {
	if service.closure == nil {
		return RetainedResponse{}, &APIError{Code: CodeClosureWorkflowDisabled, Cause: shared.ErrValidation}
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if input.CycleID.IsZero() || input.ExpectedVersion < 1 || strings.TrimSpace(input.PreviewToken) == "" {
		return RetainedResponse{}, &APIError{Code: CodeReopenPreviewStale, Cause: shared.ErrConflict}
	}
	if input.Reason == "" || !safeClosureText(input.Reason) {
		return RetainedResponse{}, &APIError{Code: CodeReopenReasonRequired, Cause: shared.ErrValidation}
	}
	tokenHash := sha256.Sum256([]byte(input.PreviewToken))
	canonical := struct {
		CycleID          shared.ID `json:"cycle_id"`
		ExpectedVersion  int64     `json:"expected_version"`
		PreviewTokenHash string    `json:"preview_token_hash"`
		Reason           string    `json:"reason"`
	}{input.CycleID, input.ExpectedVersion, hex.EncodeToString(tokenHash[:]), input.Reason}
	return service.executeRetained(ctx, input.Request, canonical, func(txCtx context.Context) (int, any, error) {
		token, err := service.verifyClosurePreview(input.PreviewToken, "reopen", CodeReopenPreviewStale)
		if err != nil {
			return 0, nil, err
		}
		tenantID, actor := shared.TenantOrDefault(input.Request.TenantID), strings.TrimSpace(input.Request.Actor)
		if token.TenantID != tenantID || token.Actor != actor || token.CycleID != input.CycleID {
			return 0, nil, &APIError{Code: CodeReopenPreviewStale, Cause: shared.ErrConflict}
		}
		if token.CycleVersion != input.ExpectedVersion {
			return 0, nil, &APIError{Code: CodeCycleVersionConflict, Cause: shared.ErrConflict}
		}
		now := service.clock.Now().UTC().Truncate(time.Microsecond)
		if !now.Before(token.ExpiresAt) {
			return 0, nil, &APIError{Code: CodeReopenPreviewStale, Cause: shared.ErrConflict}
		}
		cycle, manifest, bindingHash, err := service.buildReopenState(txCtx, tenantID, input.CycleID)
		if err != nil {
			return 0, nil, err
		}
		if cycle.Version != input.ExpectedVersion {
			return 0, nil, &APIError{Code: CodeCycleVersionConflict, Cause: shared.ErrConflict}
		}
		if bindingHash != token.BindingHash || manifest.ManifestVersion != token.ManifestVersion {
			return 0, nil, &APIError{Code: CodeReopenPreviewStale, Cause: shared.ErrConflict}
		}
		superseded := *manifest
		if err := superseded.Supersede(now, ""); err != nil {
			return 0, nil, err
		}
		reopened := *cycle
		if err := reopened.ReopenFromManifest(input.ExpectedVersion, actor, now); err != nil {
			return 0, nil, mapClosureConflict(err)
		}
		if err := service.closure.store.ReopenClosure(txCtx, ports.AssessmentClosureReopen{Manifest: &superseded, Cycle: &reopened, ExpectedCycleVersion: input.ExpectedVersion}); err != nil {
			return 0, nil, mapClosureConflict(err)
		}
		reasonHash := sha256.Sum256([]byte(input.Reason))
		if err := service.audit.Record(txCtx, ports.AuditEntry{Actor: actor, Action: "assessment_cycle.reopened", Target: reopened.ID.String(), Metadata: map[string]string{
			"tenant_id": tenantID.String(), "manifest_id": superseded.ID.String(), "manifest_hash": superseded.ContentHash,
			"cycle_version": fmt.Sprintf("%d", reopened.Version), "reason_sha256": hex.EncodeToString(reasonHash[:]), "idempotency_key": strings.TrimSpace(input.Request.IdempotencyKey),
		}, At: now}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, ReopenCommitResult{Cycle: projectCycle(&reopened), SupersededManifest: projectClosureManifest(&superseded)}, nil
	}, noAssessmentCycleCompensation)
}

func (service *APIService) GetClosureManifest(ctx context.Context, tenantID, cycleID, manifestID shared.ID) (ClosureManifestView, error) {
	if service.closure == nil {
		return ClosureManifestView{}, &APIError{Code: CodeClosureWorkflowDisabled, Cause: shared.ErrValidation}
	}
	manifest, err := service.closure.store.GetClosureManifest(ctx, shared.TenantOrDefault(tenantID), cycleID, manifestID)
	if err != nil {
		return ClosureManifestView{}, err
	}
	return projectClosureManifest(manifest), nil
}

func (service *APIService) ListClosureManifests(ctx context.Context, tenantID, cycleID shared.ID) ([]ClosureManifestView, error) {
	if service.closure == nil {
		return nil, &APIError{Code: CodeClosureWorkflowDisabled, Cause: shared.ErrValidation}
	}
	manifests, err := service.closure.store.ListClosureManifests(ctx, shared.TenantOrDefault(tenantID), cycleID)
	if err != nil {
		return nil, err
	}
	views := make([]ClosureManifestView, 0, len(manifests))
	for index := range manifests {
		views = append(views, projectClosureManifest(&manifests[index]))
	}
	return views, nil
}

func (service *APIService) buildClosurePreviewState(ctx context.Context, tenantID, cycleID shared.ID, reason string, overrideIDs []string, overrideReason string, asOfAt time.Time) (closurePreviewState, error) {
	cycle, err := service.cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		return closurePreviewState{}, err
	}
	members, err := service.cycles.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		return closurePreviewState{}, err
	}
	path, branches, pathErr := closurePath(cycle, members)
	var rootAssessment, finalAssessment *engdom.Engagement
	rootAssessment, rootErr := service.engagements.Get(ctx, tenantID, cycle.RootAssessmentID)
	if rootErr != nil && !errors.Is(rootErr, shared.ErrNotFound) {
		return closurePreviewState{}, rootErr
	}
	finalStatus := engdom.Status("")
	if finalAssessment, err = service.engagements.Get(ctx, tenantID, cycle.SelectedHeadAssessmentID); err == nil {
		finalStatus = finalAssessment.Status
	} else if !errors.Is(err, shared.ErrNotFound) {
		return closurePreviewState{}, err
	}
	initialSnapshot, _, initialErr := service.closure.snapshots.GetDefault(ctx, tenantID, cycle.RootAssessmentID)
	if initialErr != nil && !errors.Is(initialErr, shared.ErrNotFound) {
		return closurePreviewState{}, initialErr
	}
	finalSnapshot, _, finalErr := service.closure.snapshots.GetDefault(ctx, tenantID, cycle.SelectedHeadAssessmentID)
	if finalErr != nil && !errors.Is(finalErr, shared.ErrNotFound) {
		return closurePreviewState{}, finalErr
	}
	comparison, err := service.findClosureComparison(ctx, tenantID, cycleID, initialSnapshot, finalSnapshot)
	if err != nil {
		return closurePreviewState{}, err
	}
	references := closureReferences(comparison)
	scopeChanges := closureScopeChanges(rootAssessment, finalAssessment)
	for index := range path {
		switch path[index].AssessmentID {
		case cycle.RootAssessmentID:
			if initialSnapshot != nil {
				path[index].SnapshotID = initialSnapshot.ID
			}
		case cycle.SelectedHeadAssessmentID:
			if finalSnapshot != nil {
				path[index].SnapshotID = finalSnapshot.ID
			}
		}
	}
	policy := closuredom.Evaluate(closuredom.PolicyInput{
		Cycle: cycle, FinalStatus: finalStatus, InitialSnapshot: initialSnapshot, FinalSnapshot: finalSnapshot, Comparison: comparison,
		References: references, AsOfAt: asOfAt, OverrideBlockerIDs: overrideIDs, OverrideReason: overrideReason,
	})
	if pathErr != nil {
		policy.Blockers = append(policy.Blockers, closuredom.Blocker{ID: "path:invalid", Code: "closure_path_invalid", Message: "Selected final Assessment does not have one valid root-to-final path."})
		policy.CommitAllowed = false
	}
	if rootAssessment == nil || finalAssessment == nil {
		policy.Blockers = append(policy.Blockers, closuredom.Blocker{ID: "assessment:path_member_missing", Code: "assessment_path_member_missing", Message: "Root or selected final Assessment is missing."})
		policy.CommitAllowed = false
	}
	if len(branches) > 0 {
		policy.Warnings = append(policy.Warnings, closuredom.Warning{Code: "non_final_branches_excluded", Message: "Non-final branches remain outside the frozen final path."})
	}
	manifestVersion, err := service.closure.store.NextManifestVersion(ctx, tenantID, cycleID)
	if err != nil {
		return closurePreviewState{}, err
	}
	state := closurePreviewState{
		cycle: cycle, initialSnapshot: initialSnapshot, finalSnapshot: finalSnapshot,
		comparison: comparison, path: path, branches: branches, references: references, scopeChanges: scopeChanges, policy: policy, manifestVersion: manifestVersion,
	}
	binding := closureBinding{
		CycleID: cycle.ID, CycleVersion: cycle.Version, RootAssessmentID: cycle.RootAssessmentID, FinalAssessmentID: cycle.SelectedHeadAssessmentID, ManifestVersion: manifestVersion,
		Path: path, NonFinalBranches: branches, Policy: policy, References: references, ScopeProfileChanges: scopeChanges, ReasonHash: closureTextHash(reason), OverrideReasonHash: closureTextHash(overrideReason),
	}
	if initialSnapshot != nil {
		binding.InitialSnapshotID, binding.InitialSnapshotHash = initialSnapshot.ID, initialSnapshot.ContentHash
	}
	if finalSnapshot != nil {
		binding.FinalSnapshotID, binding.FinalSnapshotHash = finalSnapshot.ID, finalSnapshot.ContentHash
	}
	if comparison != nil {
		binding.ComparisonID, binding.ComparisonHash, binding.ComparisonVersion = comparison.ID, comparison.ContentHash, comparison.Version
	}
	state.bindingHash, err = canonicalHash(binding)
	return state, err
}

func (service *APIService) findClosureComparison(ctx context.Context, tenantID, cycleID shared.ID, initialSnapshot, finalSnapshot *assessmentsnapshot.Snapshot) (*cmpdom.Comparison, error) {
	if initialSnapshot == nil || finalSnapshot == nil {
		return nil, nil
	}
	comparisons, err := service.closure.comparisons.ListMetadataByCycle(ctx, tenantID, cycleID)
	if err != nil {
		return nil, err
	}
	sort.Slice(comparisons, func(left, right int) bool {
		if comparisons[left].CreatedAt.Equal(comparisons[right].CreatedAt) {
			return comparisons[left].ID > comparisons[right].ID
		}
		return comparisons[left].CreatedAt.After(comparisons[right].CreatedAt)
	})
	for _, comparison := range comparisons {
		if comparison.BaselineSnapshotID == initialSnapshot.ID && comparison.CurrentSnapshotID == finalSnapshot.ID && comparison.Mode == cmpdom.ModeLifecycle && comparison.Status != cmpdom.StatusSuperseded {
			loaded, err := service.closure.comparisons.Get(ctx, tenantID, comparison.ID)
			if err != nil {
				return nil, err
			}
			return &loaded, nil
		}
	}
	return nil, nil
}

func (service *APIService) buildReopenState(ctx context.Context, tenantID, cycleID shared.ID) (*cycledom.AssessmentCycle, *closuredom.Manifest, string, error) {
	cycle, err := service.cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		return nil, nil, "", err
	}
	if cycle.Status == cycledom.StatusArchived {
		return nil, nil, "", &APIError{Code: CodeCycleArchived, Cause: cycledom.ErrCycleArchived}
	}
	if cycle.Status != cycledom.StatusCompleted || cycle.ActiveClosureManifestID.IsZero() {
		return nil, nil, "", &APIError{Code: CodeReopenPreviewStale, Cause: shared.ErrConflict}
	}
	manifest, err := service.closure.store.GetActiveClosureManifest(ctx, tenantID, cycleID)
	if err != nil {
		return nil, nil, "", err
	}
	bindingHash, err := canonicalHash(struct {
		CycleID             shared.ID `json:"cycle_id"`
		CycleVersion        int64     `json:"cycle_version"`
		SelectedHead        shared.ID `json:"selected_head"`
		ManifestID          shared.ID `json:"manifest_id"`
		ManifestVersion     int64     `json:"manifest_version"`
		ManifestContentHash string    `json:"manifest_content_hash"`
	}{cycle.ID, cycle.Version, cycle.SelectedHeadAssessmentID, manifest.ID, manifest.ManifestVersion, manifest.ContentHash})
	return cycle, manifest, bindingHash, err
}

func closurePath(cycle *cycledom.AssessmentCycle, members []cycledom.Member) ([]closuredom.PathMember, []closuredom.BranchState, error) {
	byID := make(map[shared.ID]cycledom.Member, len(members))
	for _, member := range members {
		byID[member.AssessmentID] = member
	}
	var reverse []cycledom.Member
	seen := map[shared.ID]struct{}{}
	current := cycle.SelectedHeadAssessmentID
	for {
		member, exists := byID[current]
		if !exists || member.IsArchived() {
			return nil, closureBranches(members, nil), fmt.Errorf("invalid final path")
		}
		if _, duplicate := seen[current]; duplicate {
			return nil, closureBranches(members, nil), fmt.Errorf("cyclic final path")
		}
		seen[current] = struct{}{}
		reverse = append(reverse, member)
		if current == cycle.RootAssessmentID {
			break
		}
		if member.PredecessorAssessmentID.IsZero() {
			return nil, closureBranches(members, nil), fmt.Errorf("disconnected final path")
		}
		current = member.PredecessorAssessmentID
	}
	path := make([]closuredom.PathMember, len(reverse))
	pathIDs := make(map[shared.ID]struct{}, len(reverse))
	for index := range reverse {
		member := reverse[len(reverse)-1-index]
		path[index] = closuredom.PathMember{PathPosition: index, AssessmentID: member.AssessmentID, AssessmentType: member.AssessmentType, RetestNumber: member.RetestNumber, RelationshipVersion: member.RelationshipVersion}
		pathIDs[member.AssessmentID] = struct{}{}
	}
	return path, closureBranches(members, pathIDs), nil
}

func closureBranches(members []cycledom.Member, pathIDs map[shared.ID]struct{}) []closuredom.BranchState {
	var branches []closuredom.BranchState
	for _, member := range members {
		if _, onPath := pathIDs[member.AssessmentID]; onPath {
			continue
		}
		branches = append(branches, closuredom.BranchState{AssessmentID: member.AssessmentID, RelationshipVersion: member.RelationshipVersion, Archived: member.IsArchived()})
	}
	sort.Slice(branches, func(left, right int) bool { return branches[left].AssessmentID < branches[right].AssessmentID })
	return branches
}

func closureReferences(comparison *cmpdom.Comparison) []closuredom.Reference {
	if comparison == nil {
		return nil
	}
	seen := map[shared.ID]struct{}{}
	var references []closuredom.Reference
	for _, item := range comparison.Items {
		if item.VerificationID.IsZero() {
			continue
		}
		if _, exists := seen[item.VerificationID]; exists {
			continue
		}
		seen[item.VerificationID] = struct{}{}
		metadata, _ := json.Marshal(struct {
			State      string `json:"state"`
			Remediated bool   `json:"remediated"`
		}{item.VerificationState, item.VerificationState == "remediated"})
		digest := sha256.Sum256(metadata)
		references = append(references, closuredom.Reference{Kind: "verification", ID: item.VerificationID, Version: 1, ContentHash: hex.EncodeToString(digest[:]), Metadata: metadata})
	}
	sort.Slice(references, func(left, right int) bool { return references[left].ID < references[right].ID })
	return references
}

func projectClosurePreview(state closurePreviewState) ClosurePreview {
	preview := ClosurePreview{
		CycleID: state.cycle.ID.String(), CycleVersion: state.cycle.Version, ManifestVersion: state.manifestVersion,
		FinalAssessmentID: state.cycle.SelectedHeadAssessmentID.String(), Path: state.path, NonFinalBranches: state.branches,
		Policy: state.policy, References: state.references, ScopeProfileChanges: state.scopeChanges, RendererVersion: closuredom.RendererContractVersionV1,
	}
	if state.initialSnapshot != nil {
		preview.InitialSnapshotID = state.initialSnapshot.ID.String()
	}
	if state.finalSnapshot != nil {
		preview.FinalSnapshotID = state.finalSnapshot.ID.String()
	}
	if state.comparison != nil {
		preview.ComparisonID = state.comparison.ID.String()
	}
	return preview
}

func projectClosureManifest(manifest *closuredom.Manifest) ClosureManifestView {
	if manifest == nil {
		return ClosureManifestView{}
	}
	return ClosureManifestView{
		ID: manifest.ID.String(), CycleID: manifest.CycleID.String(), ManifestVersion: manifest.ManifestVersion, Lifecycle: manifest.Lifecycle, CycleVersion: manifest.CycleVersion,
		RootAssessmentID: manifest.RootAssessmentID.String(), FinalAssessmentID: manifest.FinalAssessmentID.String(), InitialSnapshotID: manifest.InitialSnapshotID.String(), FinalSnapshotID: manifest.FinalSnapshotID.String(), ComparisonID: manifest.ComparisonID.String(),
		InitialSnapshotHash: manifest.InitialSnapshotHash, FinalSnapshotHash: manifest.FinalSnapshotHash, ComparisonHash: manifest.ComparisonHash, CanonicalInputHash: manifest.CanonicalInputHash, ContentHash: manifest.ContentHash,
		PolicyVersion: manifest.PolicyVersion, AlgorithmVersion: manifest.AlgorithmVersion, FingerprintVersion: manifest.FingerprintVersion, RiskVersion: manifest.RiskVersion, RendererContractVersion: manifest.RendererContractVersion,
		CoverageDecisions: manifest.CoverageDecisions, ScopeProfileChanges: manifest.ScopeProfileChanges, OverrideBlockerIDs: manifest.OverrideBlockerIDs, NonFinalBranches: manifest.NonFinalBranches, Path: manifest.Path, References: manifest.References,
		Reason: manifest.Reason, OverrideReason: manifest.OverrideReason, AsOfAt: manifest.AsOfAt, CreatedAt: manifest.CreatedAt, CreatedBy: manifest.CreatedBy, SealedAt: manifest.SealedAt, SealedBy: manifest.SealedBy, SupersededAt: manifest.SupersededAt,
	}
}

func (service *APIService) signClosurePreview(payload closurePreviewToken) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal closure preview token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, service.closure.tokenKey)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (service *APIService) verifyClosurePreview(token, kind, staleCode string) (closurePreviewToken, error) {
	if len(token) > 16*1024 {
		return closurePreviewToken{}, &APIError{Code: staleCode, Cause: shared.ErrConflict}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return closurePreviewToken{}, &APIError{Code: staleCode, Cause: shared.ErrConflict}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return closurePreviewToken{}, &APIError{Code: staleCode, Cause: shared.ErrConflict}
	}
	mac := hmac.New(sha256.New, service.closure.tokenKey)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return closurePreviewToken{}, &APIError{Code: staleCode, Cause: shared.ErrConflict}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return closurePreviewToken{}, &APIError{Code: staleCode, Cause: shared.ErrConflict}
	}
	var payload closurePreviewToken
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Kind != kind || payload.TenantID.IsZero() || payload.Actor == "" || payload.CycleID.IsZero() || payload.CycleVersion < 1 || payload.ManifestVersion < 1 || payload.BindingHash == "" || payload.Nonce == "" || payload.AsOfAt.IsZero() || payload.ExpiresAt.IsZero() {
		return closurePreviewToken{}, &APIError{Code: staleCode, Cause: shared.ErrConflict}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return closurePreviewToken{}, &APIError{Code: staleCode, Cause: shared.ErrConflict}
	}
	return payload, nil
}

func randomClosureNonce() (string, error) {
	value := make([]byte, 24)
	if _, err := cryptorand.Read(value); err != nil {
		return "", fmt.Errorf("generate closure preview nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func closureScopeChanges(root, final *engdom.Engagement) []closuredom.ScopeProfileChange {
	if root == nil || final == nil {
		return nil
	}
	rootHash, rootErr := canonicalHash(root.Scope)
	finalHash, finalErr := canonicalHash(final.Scope)
	if rootErr != nil || finalErr != nil || rootHash == finalHash {
		return nil
	}
	return []closuredom.ScopeProfileChange{{AssessmentID: final.ID, Kind: "scope", Summary: "Scope differs from the root Assessment."}}
}

func closureReferencesExpired(references []closuredom.Reference, at time.Time) bool {
	for _, reference := range references {
		if reference.ExpiresAt != nil && !at.Before(*reference.ExpiresAt) {
			return true
		}
	}
	return false
}

func canonicalClosureStrings(values []string) []string {
	unique := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			unique[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func safeClosureText(value string) bool {
	if len(value) > 4096 {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"password=", "passwd=", "api_key", "apikey", "access_token", "authorization:", "bearer ", "private_key", "client_secret"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func closureTextHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func mapClosureConflict(err error) error {
	if errors.Is(err, shared.ErrConflict) {
		return &APIError{Code: CodeCycleVersionConflict, Cause: err}
	}
	return err
}

func noAssessmentCycleCompensation(context.Context) error { return nil }
