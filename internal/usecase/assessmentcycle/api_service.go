package assessmentcycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"

	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	CodeIdempotencyKeyRequired     = "idempotency_key_required"
	CodeIdempotencyBodyMismatch    = "idempotency_body_mismatch"
	CodeIdempotencyRequestPending  = "idempotency_request_in_progress"
	CodeCycleReopenRequired        = "cycle_reopen_required"
	CodeCycleArchived              = "cycle_archived"
	CodeHiddenProjectContext       = "hidden_project_context_ineligible"
	CodeInvalidCursor              = "invalid_cursor"
	CodeInvalidFilter              = "invalid_filter"
	CodeInvalidPageSize            = "invalid_page_size"
	CodeInvalidScopeStrategy       = "invalid_scope_strategy"
	CodeInvalidProfileStrategy     = "invalid_profile_strategy"
	WarningAuthorizationNotCopied  = "authorization_not_inherited"
	WarningRoENotCopied            = "roe_not_inherited"
	WarningScannerProfileNotCopied = "scanner_profile_not_inherited"
)

type APIError struct {
	Code  string
	Cause error
}

func (err *APIError) Error() string { return err.Code }
func (err *APIError) Unwrap() error { return err.Cause }

func ErrorCode(err error) string {
	var coded *APIError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ""
}

type APIService struct {
	cycles              *Service
	cycleList           ports.AssessmentCycleListRepository
	requests            ports.AssessmentCycleRequestStore
	engagements         *enguc.Service
	tx                  ports.TenantTransactionRunner
	clock               ports.Clock
	audit               ports.AuditLogger
	relationshipChanges *relationshipChangeSupport
	closure             *closureSupport
}

func NewAPIService(cycles *Service, cycleList ports.AssessmentCycleListRepository, requests ports.AssessmentCycleRequestStore, engagements *enguc.Service, tx ports.TenantTransactionRunner, clock ports.Clock, audit ports.AuditLogger) (*APIService, error) {
	if cycles == nil || cycleList == nil || requests == nil || engagements == nil || tx == nil || clock == nil {
		return nil, fmt.Errorf("%w: assessment cycle API dependencies are required", shared.ErrValidation)
	}
	return &APIService{cycles: cycles, cycleList: cycleList, requests: requests, engagements: engagements, tx: tx, clock: clock, audit: audit}, nil
}

type RetainedRequest struct {
	TenantID       shared.ID
	Actor          string
	Route          string
	IdempotencyKey string
}

type RetainedResponse struct {
	StatusCode int
	Body       []byte
	Replayed   bool
}

type SourceUpload struct {
	Filename string
	Size     int64
	SHA256   string
	Reader   io.Reader
}

type CreateInitialAssessmentInput struct {
	Request    RetainedRequest
	Engagement enguc.CreateInput
	Source     *SourceUpload
}

func (service *APIService) CreateInitialAssessment(ctx context.Context, input CreateInitialAssessmentInput) (RetainedResponse, error) {
	var compensate func(context.Context) error
	canonical := struct {
		Engagement enguc.CreateInput `json:"engagement"`
		Source     *struct {
			Filename string `json:"filename"`
			Size     int64  `json:"size"`
			SHA256   string `json:"sha256"`
		} `json:"source,omitempty"`
	}{Engagement: input.Engagement}
	if input.Source != nil {
		canonical.Source = &struct {
			Filename string `json:"filename"`
			Size     int64  `json:"size"`
			SHA256   string `json:"sha256"`
		}{Filename: input.Source.Filename, Size: input.Source.Size, SHA256: input.Source.SHA256}
	}
	return service.executeRetained(ctx, input.Request, canonical, func(txCtx context.Context) (int, any, error) {
		engagementInput := input.Engagement
		engagementInput.TenantID = shared.TenantOrDefault(input.Request.TenantID)
		engagementInput.CreatedBy = strings.TrimSpace(input.Request.Actor)
		var (
			assessment *engdom.Engagement
			err        error
		)
		if input.Source == nil {
			assessment, err = service.engagements.Create(txCtx, engagementInput)
		} else {
			if input.Source.Reader == nil {
				return 0, nil, &APIError{Code: "source_upload_required", Cause: shared.ErrValidation}
			}
			assessment, _, err = service.engagements.CreateFromSourcePackage(txCtx, engagementInput, input.Source.Filename, input.Source.Size, input.Source.SHA256, input.Source.Reader)
		}
		if err != nil {
			return 0, nil, err
		}
		boundary := cycledom.BoundaryStandalone
		if !assessment.BusinessAssetID.IsZero() {
			boundary = cycledom.BoundaryAsset
		}
		cycle, _, err := service.cycles.CreateInitialCycle(txCtx, CreateInitialCycleInput{
			TenantID: assessment.TenantID, Name: assessment.Name, BoundaryKind: boundary,
			BusinessAssetID: assessment.BusinessAssetID, RootAssessmentID: assessment.ID, Actor: input.Request.Actor,
		})
		if err != nil {
			return 0, nil, errors.Join(err, service.engagements.CompensateCreate(context.WithoutCancel(txCtx), assessment.TenantID, assessment.ID))
		}
		compensate = func(cleanupCtx context.Context) error {
			return errors.Join(
				service.cycles.compensateInitialCreate(cleanupCtx, assessment.TenantID, cycle.ID),
				service.engagements.CompensateCreate(cleanupCtx, assessment.TenantID, assessment.ID),
			)
		}
		service.record(txCtx, input.Request, "assessment_cycle.api_initial_created", cycle.ID, map[string]string{
			"assessment_id": assessment.ID.String(), "cycle_version": strconv.FormatInt(cycle.Version, 10),
		})
		return 201, assessment, nil
	}, func(cleanupCtx context.Context) error {
		if compensate == nil {
			return nil
		}
		return compensate(cleanupCtx)
	})
}

type CreateRetestAssessmentInput struct {
	Request                 RetainedRequest
	AssessmentID            shared.ID
	Name                    string
	PredecessorAssessmentID shared.ID
	ScopeStrategy           string
	ProfileStrategy         string
	AuthorizedFrom          *time.Time
	AuthorizedTo            *time.Time
	Timezone                string
	RoE                     *engdom.RoE
}

type InheritanceDiff struct {
	Scope          string `json:"scope"`
	Authorization  string `json:"authorization"`
	RoE            string `json:"roe"`
	ScannerProfile string `json:"scanner_profile"`
}

type CreateRetestResponse struct {
	Engagement      *engdom.Engagement `json:"engagement"`
	Cycle           CycleView          `json:"cycle"`
	Member          MemberView         `json:"member"`
	InheritanceDiff InheritanceDiff    `json:"inheritance_diff"`
	Warnings        []string           `json:"warnings"`
}

func (service *APIService) CreateRetestAssessment(ctx context.Context, input CreateRetestAssessmentInput) (RetainedResponse, error) {
	var compensate func(context.Context) error
	canonical := struct {
		AssessmentID            shared.ID   `json:"assessment_id"`
		Name                    string      `json:"name,omitempty"`
		PredecessorAssessmentID shared.ID   `json:"predecessor_assessment_id,omitempty"`
		ScopeStrategy           string      `json:"scope_strategy,omitempty"`
		ProfileStrategy         string      `json:"profile_strategy,omitempty"`
		AuthorizedFrom          *time.Time  `json:"authorized_from,omitempty"`
		AuthorizedTo            *time.Time  `json:"authorized_to,omitempty"`
		Timezone                string      `json:"timezone,omitempty"`
		RoE                     *engdom.RoE `json:"roe,omitempty"`
	}{input.AssessmentID, input.Name, input.PredecessorAssessmentID, input.ScopeStrategy, input.ProfileStrategy, input.AuthorizedFrom, input.AuthorizedTo, input.Timezone, input.RoE}
	return service.executeRetained(ctx, input.Request, canonical, func(txCtx context.Context) (int, any, error) {
		tenantID := shared.TenantOrDefault(input.Request.TenantID)
		cycle, err := service.cycles.GetCycleByAssessment(txCtx, tenantID, input.AssessmentID)
		if err != nil {
			return 0, nil, err
		}
		if cycle.Status == cycledom.StatusCompleted {
			return 0, nil, &APIError{Code: CodeCycleReopenRequired, Cause: cycledom.ErrCycleReopenRequired}
		}
		if cycle.Status == cycledom.StatusArchived {
			return 0, nil, &APIError{Code: CodeCycleArchived, Cause: cycledom.ErrCycleArchived}
		}
		originalCycle := *cycle
		if !cycle.ProjectID.IsZero() || cycle.BoundaryKind == cycledom.BoundaryProject || cycle.BoundaryKind == cycledom.BoundaryAssetProject {
			return 0, nil, &APIError{Code: CodeHiddenProjectContext, Cause: cycledom.ErrHiddenProjectContext}
		}
		source, err := service.engagements.Get(txCtx, tenantID, input.AssessmentID)
		if err != nil {
			return 0, nil, err
		}
		scopeStrategy := strings.TrimSpace(input.ScopeStrategy)
		if scopeStrategy == "" {
			scopeStrategy = "copy"
		}
		var inScope, outOfScope []engdom.Target
		switch scopeStrategy {
		case "copy":
			inScope = append([]engdom.Target(nil), source.Scope.InScope...)
			outOfScope = append([]engdom.Target(nil), source.Scope.OutOfScope...)
		case "empty":
		default:
			return 0, nil, &APIError{Code: CodeInvalidScopeStrategy, Cause: shared.ErrValidation}
		}
		profileStrategy := strings.TrimSpace(input.ProfileStrategy)
		if profileStrategy == "" {
			profileStrategy = "none"
		}
		if profileStrategy != "none" {
			return 0, nil, &APIError{Code: CodeInvalidProfileStrategy, Cause: shared.ErrValidation}
		}
		name := strings.TrimSpace(input.Name)
		if name == "" {
			name = source.Name + " Re-test"
		}
		assessment, err := service.engagements.Create(txCtx, enguc.CreateInput{
			TenantID: tenantID, BusinessAssetID: cycle.BusinessAssetID, CreatedBy: input.Request.Actor,
			Name: name, Client: source.Client, InScope: inScope, OutOfScope: outOfScope,
			AuthorizedFrom: input.AuthorizedFrom, AuthorizedTo: input.AuthorizedTo, Timezone: input.Timezone,
			RoE: input.RoE, RequiresExplicitExecutionAuthorization: true,
		})
		if err != nil {
			return 0, nil, err
		}
		member, err := service.cycles.CreateRetest(txCtx, CreateRetestInput{
			TenantID: tenantID, CycleID: cycle.ID, PredecessorAssessmentID: input.PredecessorAssessmentID,
			NewAssessmentID: assessment.ID, Actor: input.Request.Actor,
		})
		if err != nil {
			return 0, nil, errors.Join(mapRetestError(err), service.engagements.CompensateCreate(context.WithoutCancel(txCtx), tenantID, assessment.ID))
		}
		compensate = func(cleanupCtx context.Context) error {
			return errors.Join(
				service.cycles.compensateCycleMutation(cleanupCtx, &originalCycle, assessment.ID),
				service.engagements.CompensateCreate(cleanupCtx, tenantID, assessment.ID),
			)
		}
		updatedCycle, err := service.cycles.GetCycle(txCtx, tenantID, cycle.ID)
		if err != nil {
			return 0, nil, err
		}
		warnings := []string{WarningAuthorizationNotCopied, WarningRoENotCopied, WarningScannerProfileNotCopied}
		if input.AuthorizedFrom != nil || input.AuthorizedTo != nil {
			warnings = removeWarning(warnings, WarningAuthorizationNotCopied)
		}
		if input.RoE != nil {
			warnings = removeWarning(warnings, WarningRoENotCopied)
		}
		service.record(txCtx, input.Request, "assessment_cycle.api_retest_created", cycle.ID, map[string]string{
			"assessment_id": assessment.ID.String(), "predecessor_id": member.PredecessorAssessmentID.String(),
			"retest_number": strconv.Itoa(member.RetestNumber), "cycle_version": strconv.FormatInt(updatedCycle.Version, 10),
		})
		return 201, CreateRetestResponse{
			Engagement: assessment, Cycle: projectCycle(updatedCycle), Member: projectMember(*member),
			InheritanceDiff: InheritanceDiff{Scope: scopeStrategy, Authorization: "explicit_only", RoE: "explicit_only", ScannerProfile: profileStrategy},
			Warnings:        warnings,
		}, nil
	}, func(cleanupCtx context.Context) error {
		if compensate == nil {
			return nil
		}
		return compensate(cleanupCtx)
	})
}

type MemberView struct {
	AssessmentID            string     `json:"assessment_id"`
	AssessmentType          string     `json:"assessment_type"`
	PredecessorAssessmentID string     `json:"predecessor_assessment_id,omitempty"`
	RetestNumber            int        `json:"retest_number"`
	RelationshipVersion     int64      `json:"relationship_version"`
	CreatedAt               time.Time  `json:"created_at"`
	CreatedBy               string     `json:"created_by"`
	ArchivedAt              *time.Time `json:"archived_at,omitempty"`
}

type CycleView struct {
	ID                        string                `json:"id"`
	Name                      string                `json:"name"`
	BoundaryKind              cycledom.BoundaryKind `json:"boundary_kind"`
	BusinessAssetID           string                `json:"business_asset_id,omitempty"`
	ProjectID                 string                `json:"project_id,omitempty"`
	Status                    cycledom.Status       `json:"status"`
	RootAssessmentID          string                `json:"root_assessment_id"`
	SelectedHeadAssessmentID  string                `json:"selected_head_assessment_id"`
	ActiveClosureManifestID   string                `json:"active_closure_manifest_id,omitempty"`
	ActiveClosureCycleVersion int64                 `json:"active_closure_cycle_version,omitempty"`
	NextRetestNumber          int                   `json:"next_retest_number"`
	Version                   int64                 `json:"version"`
	CreatedAt                 time.Time             `json:"created_at"`
	UpdatedAt                 time.Time             `json:"updated_at"`
	CreatedBy                 string                `json:"created_by"`
	UpdatedBy                 string                `json:"updated_by"`
}

type CycleDetail struct {
	Cycle       CycleView    `json:"cycle"`
	Members     []MemberView `json:"members"`
	BranchHeads []MemberView `json:"branch_heads"`
}

type LifecycleView struct {
	AssessmentID string `json:"assessment_id"`
	CycleDetail
}

func (service *APIService) GetLifecycle(ctx context.Context, tenantID, assessmentID shared.ID) (LifecycleView, error) {
	cycle, err := service.cycles.GetCycleByAssessment(ctx, tenantID, assessmentID)
	if err != nil {
		return LifecycleView{}, err
	}
	detail, err := service.cycleDetail(ctx, tenantID, cycle)
	return LifecycleView{AssessmentID: assessmentID.String(), CycleDetail: detail}, err
}

func (service *APIService) GetCycle(ctx context.Context, tenantID, cycleID shared.ID) (CycleDetail, error) {
	cycle, err := service.cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		return CycleDetail{}, err
	}
	return service.cycleDetail(ctx, tenantID, cycle)
}

type ListCyclesInput struct {
	TenantID         shared.ID
	Status           cycledom.Status
	BoundaryKind     cycledom.BoundaryKind
	AssessmentStatus engdom.Status
	SelectedHeadID   shared.ID
	AssessmentType   cycledom.AssessmentType
	ProducerKind     string
	FindingKind      string
	ReviewState      string
	ChangePresence   cmpdom.Presence
	ChangeSeverity   shared.Severity
	ScanStaleness    string
	Search           string
	Cursor           string
	Limit            int
}

type CycleSummary struct {
	CycleView
	MemberCount             int             `json:"member_count"`
	ActiveBranchCount       int             `json:"active_branch_count"`
	LatestAssessmentID      string          `json:"latest_assessment_id,omitempty"`
	LatestRetestNumber      int             `json:"latest_retest_number"`
	Members                 []MemberView    `json:"members"`
	MembersNextCursor       string          `json:"members_next_cursor,omitempty"`
	RootSnapshotID          string          `json:"root_snapshot_id,omitempty"`
	CurrentSnapshotID       string          `json:"current_snapshot_id,omitempty"`
	ComparisonID            string          `json:"comparison_id,omitempty"`
	ComparisonStatus        string          `json:"comparison_status,omitempty"`
	ComparisonSummary       *cmpdom.Summary `json:"comparison_summary,omitempty"`
	ActiveClosureManifestID string          `json:"active_closure_manifest_id,omitempty"`
	SelectedHeadLastScanAt  *time.Time      `json:"selected_head_last_scan_at,omitempty"`
	ScanStaleness           string          `json:"scan_staleness"`
}

type CyclePage struct {
	Items                 []CycleSummary               `json:"items"`
	NextCursor            string                       `json:"next_cursor,omitempty"`
	MigrationPending      []MigrationPendingAssessment `json:"migration_pending"`
	MigrationPendingTotal int                          `json:"migration_pending_total"`
}

type MigrationPendingAssessment struct {
	AssessmentID    string                `json:"assessment_id"`
	Name            string                `json:"name"`
	Status          string                `json:"status"`
	BoundaryKind    cycledom.BoundaryKind `json:"boundary_kind"`
	BusinessAssetID string                `json:"business_asset_id,omitempty"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

type ListCycleMembersInput struct {
	TenantID shared.ID
	CycleID  shared.ID
	Cursor   string
	Limit    int
}

type CycleMemberPage struct {
	Items      []MemberView `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

func (service *APIService) ListCycles(ctx context.Context, input ListCyclesInput) (CyclePage, error) {
	limit := input.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return CyclePage{}, &APIError{Code: CodeInvalidPageSize, Cause: shared.ErrValidation}
	}
	if input.Status != "" && !input.Status.Valid() {
		return CyclePage{}, fmt.Errorf("%w: invalid assessment cycle status", shared.ErrValidation)
	}
	if input.BoundaryKind != "" && !input.BoundaryKind.Valid() {
		return CyclePage{}, fmt.Errorf("%w: invalid assessment cycle boundary", shared.ErrValidation)
	}
	if err := normalizeCycleListFilters(&input); err != nil {
		return CyclePage{}, err
	}
	updatedAt, cycleID, err := decodeCycleCursor(input.Cursor)
	if err != nil {
		return CyclePage{}, &APIError{Code: CodeInvalidCursor, Cause: shared.ErrValidation}
	}
	query := ports.AssessmentCycleListQuery{
		TenantID: input.TenantID, Status: input.Status, BoundaryKind: input.BoundaryKind, AssessmentStatus: input.AssessmentStatus,
		SelectedHeadID: input.SelectedHeadID, AssessmentType: input.AssessmentType, ProducerKind: input.ProducerKind, FindingKind: input.FindingKind,
		ReviewState: input.ReviewState, ChangePresence: input.ChangePresence, ChangeSeverity: input.ChangeSeverity,
		ScanStaleness: input.ScanStaleness, ScanStaleBefore: service.clock.Now().UTC().Add(-24 * time.Hour), Search: input.Search,
		AfterUpdatedAt: updatedAt, AfterCycleID: cycleID, Limit: limit + 1, MemberLimit: 10,
	}
	records, err := service.cycleList.ListCycles(ctx, query)
	if err != nil {
		return CyclePage{}, err
	}
	page := CyclePage{Items: make([]CycleSummary, 0, min(limit, len(records))), MigrationPending: make([]MigrationPendingAssessment, 0)}
	for _, record := range records[:min(limit, len(records))] {
		summary := CycleSummary{
			CycleView: projectCycle(&record.Cycle), MemberCount: record.MemberCount, ActiveBranchCount: record.ActiveBranchCount,
			LatestAssessmentID: record.LatestAssessmentID.String(), LatestRetestNumber: record.LatestRetestNumber,
			Members: make([]MemberView, 0, len(record.Members)), RootSnapshotID: record.RootSnapshotID.String(), CurrentSnapshotID: record.CurrentSnapshotID.String(),
			ComparisonID: record.ComparisonID.String(), ComparisonStatus: string(record.ComparisonStatus), ActiveClosureManifestID: record.ActiveManifestID.String(),
			SelectedHeadLastScanAt: record.SelectedHeadScanAt, ScanStaleness: record.ScanStaleness,
		}
		for _, member := range record.Members {
			summary.Members = append(summary.Members, projectMember(member))
		}
		if record.MembersHaveMore && len(record.Members) > 0 {
			last := record.Members[len(record.Members)-1]
			summary.MembersNextCursor = encodeCycleMemberCursor(last.RetestNumber, last.AssessmentID)
		}
		if !record.ComparisonID.IsZero() {
			comparisonSummary := record.ComparisonSummary
			summary.ComparisonSummary = &comparisonSummary
		}
		page.Items = append(page.Items, summary)
	}
	if len(records) > limit {
		last := records[limit-1].Cycle
		page.NextCursor = encodeCycleCursor(last.UpdatedAt, last.ID)
	}
	query.Limit = min(limit, 100)
	pending, pendingTotal, err := service.cycleList.ListMigrationPendingAssessments(ctx, query)
	if err != nil {
		return CyclePage{}, err
	}
	page.MigrationPendingTotal = pendingTotal
	for _, record := range pending {
		page.MigrationPending = append(page.MigrationPending, MigrationPendingAssessment{
			AssessmentID: record.AssessmentID.String(), Name: record.Name, Status: record.Status, BoundaryKind: record.BoundaryKind,
			BusinessAssetID: record.BusinessAssetID.String(), UpdatedAt: record.UpdatedAt,
		})
	}
	return page, nil
}

func normalizeCycleListFilters(input *ListCyclesInput) error {
	if input.AssessmentStatus != "" && !input.AssessmentStatus.Valid() {
		return invalidCycleListFilter("assessment_status")
	}
	if input.AssessmentType != "" && !input.AssessmentType.Valid() {
		return invalidCycleListFilter("assessment_type")
	}
	if input.ChangePresence != "" && input.ChangePresence != cmpdom.PresenceNew && input.ChangePresence != cmpdom.PresenceReopened {
		return invalidCycleListFilter("change_presence")
	}
	if input.ChangeSeverity != "" && input.ChangeSeverity != shared.SeverityCritical && input.ChangeSeverity != shared.SeverityHigh {
		return invalidCycleListFilter("change_severity")
	}
	if input.ReviewState != "" && input.ReviewState != "needs_review" && input.ReviewState != "verified" && input.ReviewState != "clear" {
		return invalidCycleListFilter("review_state")
	}
	if input.ScanStaleness != "" && input.ScanStaleness != "fresh" && input.ScanStaleness != "stale" && input.ScanStaleness != "missing" {
		return invalidCycleListFilter("scan_staleness")
	}
	for name, value := range map[string]*string{
		"producer": &input.ProducerKind, "finding_kind": &input.FindingKind, "q": &input.Search,
	} {
		*value = strings.TrimSpace(*value)
		if len(*value) > 256 || strings.ContainsFunc(*value, unicode.IsControl) {
			return invalidCycleListFilter(name)
		}
	}
	input.SelectedHeadID = shared.ID(strings.TrimSpace(input.SelectedHeadID.String()))
	if len(input.SelectedHeadID) > 256 || strings.ContainsFunc(input.SelectedHeadID.String(), unicode.IsControl) {
		return invalidCycleListFilter("selected_head_assessment_id")
	}
	return nil
}

func invalidCycleListFilter(name string) error {
	return &APIError{Code: CodeInvalidFilter, Cause: fmt.Errorf("%w: invalid %s filter", shared.ErrValidation, name)}
}

func (service *APIService) ListCycleMembers(ctx context.Context, input ListCycleMembersInput) (CycleMemberPage, error) {
	limit := input.Limit
	if limit == 0 {
		limit = 25
	}
	if limit < 1 || limit > 100 {
		return CycleMemberPage{}, &APIError{Code: CodeInvalidPageSize, Cause: shared.ErrValidation}
	}
	afterNumber, afterID, err := decodeCycleMemberCursor(input.Cursor)
	if err != nil {
		return CycleMemberPage{}, &APIError{Code: CodeInvalidCursor, Cause: shared.ErrValidation}
	}
	if _, err := service.cycles.GetCycle(ctx, input.TenantID, input.CycleID); err != nil {
		return CycleMemberPage{}, err
	}
	members, err := service.cycles.ListMembers(ctx, input.TenantID, input.CycleID)
	if err != nil {
		return CycleMemberPage{}, err
	}
	filtered := make([]cycledom.Member, 0, min(len(members), limit+1))
	for _, member := range members {
		if input.Cursor != "" && (member.RetestNumber < afterNumber || member.RetestNumber == afterNumber && member.AssessmentID <= afterID) {
			continue
		}
		filtered = append(filtered, member)
		if len(filtered) == limit+1 {
			break
		}
	}
	page := CycleMemberPage{Items: make([]MemberView, 0, min(limit, len(filtered)))}
	for _, member := range filtered[:min(limit, len(filtered))] {
		page.Items = append(page.Items, projectMember(member))
	}
	if len(filtered) > limit {
		last := filtered[limit-1]
		page.NextCursor = encodeCycleMemberCursor(last.RetestNumber, last.AssessmentID)
	}
	return page, nil
}

type ArchiveCycleRequest struct {
	Request         RetainedRequest
	CycleID         shared.ID
	ExpectedVersion int64
}

func (service *APIService) ArchiveCycle(ctx context.Context, input ArchiveCycleRequest) (RetainedResponse, error) {
	var compensate func(context.Context) error
	canonical := struct {
		CycleID         shared.ID `json:"cycle_id"`
		ExpectedVersion int64     `json:"expected_version"`
	}{input.CycleID, input.ExpectedVersion}
	return service.executeRetained(ctx, input.Request, canonical, func(txCtx context.Context) (int, any, error) {
		if input.ExpectedVersion < 1 {
			return 0, nil, &APIError{Code: "precondition_required", Cause: shared.ErrValidation}
		}
		originalCycle, err := service.cycles.GetCycle(txCtx, input.Request.TenantID, input.CycleID)
		if err != nil {
			return 0, nil, err
		}
		if err := service.cycles.ArchiveCycle(txCtx, ArchiveCycleInput{
			TenantID: input.Request.TenantID, CycleID: input.CycleID,
			ExpectedCycleVersion: input.ExpectedVersion, Actor: input.Request.Actor,
		}); err != nil {
			return 0, nil, err
		}
		compensate = func(cleanupCtx context.Context) error {
			return service.cycles.compensateCycleMutation(cleanupCtx, originalCycle, "")
		}
		detail, err := service.GetCycle(txCtx, input.Request.TenantID, input.CycleID)
		if err != nil {
			return 0, nil, err
		}
		service.record(txCtx, input.Request, "assessment_cycle.api_archived", input.CycleID, map[string]string{
			"previous_version": strconv.FormatInt(input.ExpectedVersion, 10), "cycle_version": strconv.FormatInt(detail.Cycle.Version, 10),
		})
		return 200, detail, nil
	}, func(cleanupCtx context.Context) error {
		if compensate == nil {
			return nil
		}
		return compensate(cleanupCtx)
	})
}

func (service *APIService) executeRetained(ctx context.Context, request RetainedRequest, canonical any, operation func(context.Context) (int, any, error), compensate func(context.Context) error) (RetainedResponse, error) {
	scope := ports.AssessmentCycleRequestScope{
		TenantID: shared.TenantOrDefault(request.TenantID), Actor: strings.TrimSpace(request.Actor),
		Route: strings.TrimSpace(request.Route), IdempotencyKey: strings.TrimSpace(request.IdempotencyKey),
	}
	if scope.Actor == "" || scope.Route == "" {
		return RetainedResponse{}, fmt.Errorf("%w: actor and route are required", shared.ErrValidation)
	}
	if scope.IdempotencyKey == "" || len(scope.IdempotencyKey) > 128 {
		return RetainedResponse{}, &APIError{Code: CodeIdempotencyKeyRequired, Cause: shared.ErrValidation}
	}
	requestHash, err := canonicalHash(canonical)
	if err != nil {
		return RetainedResponse{}, err
	}
	var response RetainedResponse
	createdReservation := false
	err = service.tx.Run(ctx, scope.TenantID, func(txCtx context.Context) error {
		stored, created, err := service.requests.BeginAssessmentCycleRequest(txCtx, ports.AssessmentCycleRequest{
			Scope: scope, RequestHash: requestHash, CreatedAt: service.clock.Now().UTC(),
		})
		if err != nil {
			return err
		}
		createdReservation = created
		if !created {
			if stored.RequestHash != requestHash {
				return &APIError{Code: CodeIdempotencyBodyMismatch, Cause: shared.ErrConflict}
			}
			if stored.CompletedAt == nil || stored.StatusCode == 0 || len(stored.ResponseBody) == 0 {
				return &APIError{Code: CodeIdempotencyRequestPending, Cause: shared.ErrConflict}
			}
			response = RetainedResponse{StatusCode: stored.StatusCode, Body: append([]byte(nil), stored.ResponseBody...), Replayed: true}
			return nil
		}
		statusCode, value, err := operation(txCtx)
		if err != nil {
			return errors.Join(err, compensate(context.WithoutCancel(txCtx)))
		}
		body, err := json.Marshal(value)
		if err != nil {
			return errors.Join(fmt.Errorf("marshal assessment cycle response: %w", err), compensate(context.WithoutCancel(txCtx)))
		}
		if err := service.requests.CompleteAssessmentCycleRequest(txCtx, scope, requestHash, statusCode, body, service.clock.Now().UTC()); err != nil {
			return errors.Join(err, compensate(context.WithoutCancel(txCtx)))
		}
		response = RetainedResponse{StatusCode: statusCode, Body: body}
		return nil
	})
	if err != nil && createdReservation {
		_ = service.requests.AbortAssessmentCycleRequest(context.WithoutCancel(ctx), scope, requestHash)
	}
	return response, err
}

func (service *APIService) cycleDetail(ctx context.Context, tenantID shared.ID, cycle *cycledom.AssessmentCycle) (CycleDetail, error) {
	members, err := service.cycles.ListMembers(ctx, tenantID, cycle.ID)
	if err != nil {
		return CycleDetail{}, err
	}
	detail := CycleDetail{Cycle: projectCycle(cycle), Members: make([]MemberView, 0, len(members))}
	for _, member := range members {
		detail.Members = append(detail.Members, projectMember(member))
	}
	for _, member := range cycledom.DeriveBranchHeads(members) {
		detail.BranchHeads = append(detail.BranchHeads, projectMember(member))
	}
	return detail, nil
}

func (service *APIService) record(ctx context.Context, request RetainedRequest, action string, target shared.ID, metadata map[string]string) {
	if service.audit == nil {
		return
	}
	metadata["tenant_id"] = shared.TenantOrDefault(request.TenantID).String()
	metadata["idempotency_key"] = strings.TrimSpace(request.IdempotencyKey)
	_ = service.audit.Record(ctx, ports.AuditEntry{Actor: strings.TrimSpace(request.Actor), Action: action, Target: target.String(), Metadata: metadata, At: service.clock.Now().UTC()})
}

func projectCycle(cycle *cycledom.AssessmentCycle) CycleView {
	return CycleView{
		ID: cycle.ID.String(), Name: cycle.Name, BoundaryKind: cycle.BoundaryKind,
		BusinessAssetID: cycle.BusinessAssetID.String(), ProjectID: cycle.ProjectID.String(), Status: cycle.Status,
		RootAssessmentID: cycle.RootAssessmentID.String(), SelectedHeadAssessmentID: cycle.SelectedHeadAssessmentID.String(),
		ActiveClosureManifestID: cycle.ActiveClosureManifestID.String(), ActiveClosureCycleVersion: cycle.ActiveClosureCycleVersion,
		NextRetestNumber: cycle.NextRetestNumber, Version: cycle.Version, CreatedAt: cycle.CreatedAt, UpdatedAt: cycle.UpdatedAt,
		CreatedBy: cycle.CreatedBy, UpdatedBy: cycle.UpdatedBy,
	}
}

func projectMember(member cycledom.Member) MemberView {
	return MemberView{
		AssessmentID: member.AssessmentID.String(), AssessmentType: string(member.AssessmentType),
		PredecessorAssessmentID: member.PredecessorAssessmentID.String(), RetestNumber: member.RetestNumber,
		RelationshipVersion: member.RelationshipVersion, CreatedAt: member.CreatedAt, CreatedBy: member.CreatedBy, ArchivedAt: member.ArchivedAt,
	}
}

func mapRetestError(err error) error {
	switch {
	case errors.Is(err, cycledom.ErrCycleReopenRequired):
		return &APIError{Code: CodeCycleReopenRequired, Cause: err}
	case errors.Is(err, cycledom.ErrCycleArchived):
		return &APIError{Code: CodeCycleArchived, Cause: err}
	case errors.Is(err, cycledom.ErrHiddenProjectContext):
		return &APIError{Code: CodeHiddenProjectContext, Cause: err}
	default:
		return err
	}
}

func removeWarning(warnings []string, value string) []string {
	for index, warning := range warnings {
		if warning == value {
			return append(warnings[:index], warnings[index+1:]...)
		}
	}
	return warnings
}

func canonicalHash(value any) (string, error) {
	// ponytail: request schemas contain no maps or floats; use a full RFC 8785 encoder if either is added.
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", fmt.Errorf("canonicalize assessment cycle request: %w", err)
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")))
	return hex.EncodeToString(sum[:]), nil
}

type cycleCursor struct {
	UpdatedAt time.Time `json:"updated_at"`
	CycleID   shared.ID `json:"cycle_id"`
}

type cycleMemberCursor struct {
	RetestNumber int       `json:"retest_number"`
	AssessmentID shared.ID `json:"assessment_id"`
}

func encodeCycleCursor(updatedAt time.Time, cycleID shared.ID) string {
	encoded, _ := json.Marshal(cycleCursor{UpdatedAt: updatedAt.UTC(), CycleID: cycleID})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeCycleCursor(cursor string) (time.Time, shared.ID, error) {
	if strings.TrimSpace(cursor) == "" {
		return time.Time{}, "", nil
	}
	if len(cursor) > 684 {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(raw) > 512 {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	var decoded cycleCursor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil || decoded.UpdatedAt.IsZero() || decoded.CycleID.IsZero() {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	return decoded.UpdatedAt.UTC(), decoded.CycleID, nil
}

func encodeCycleMemberCursor(retestNumber int, assessmentID shared.ID) string {
	encoded, _ := json.Marshal(cycleMemberCursor{RetestNumber: retestNumber, AssessmentID: assessmentID})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeCycleMemberCursor(cursor string) (int, shared.ID, error) {
	if strings.TrimSpace(cursor) == "" {
		return -1, "", nil
	}
	if len(cursor) > 684 {
		return 0, "", fmt.Errorf("invalid cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(raw) > 512 {
		return 0, "", fmt.Errorf("invalid cursor")
	}
	var decoded cycleMemberCursor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil || decoded.RetestNumber < 0 || decoded.AssessmentID.IsZero() {
		return 0, "", fmt.Errorf("invalid cursor")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return 0, "", fmt.Errorf("invalid cursor")
	}
	return decoded.RetestNumber, decoded.AssessmentID, nil
}
