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
	"sort"
	"strings"
	"time"

	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	cmpuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	RelationshipCommandReparent   = "reparent_within_cycle"
	RelationshipCommandSelectHead = "select_head"

	CodeRelationshipUnsupportedCommand = "relationship_command_unsupported"
	CodeRelationshipPreviewStale       = "relationship_preview_stale"
	CodeRelationshipPreviewExpired     = "relationship_preview_expired"
	CodeRelationshipPreviewInvalid     = "relationship_preview_invalid"
	CodeRelationshipLocked             = "relationship_change_locked"
	CodeRelationshipReasonRequired     = "relationship_reason_required"
	CodeRelationshipRecomputeFailed    = "relationship_recompute_failed"

	relationshipPreviewTTL = 5 * time.Minute
)

type relationshipChangeSupport struct {
	snapshots   ports.AssessmentSnapshotRepository
	comparisons ports.AssessmentComparisonRepository
	lineage     ports.FindingLineageRepository
	scanJobs    ports.ScanJobStore
	replacer    *cmpuc.Service
	tokenKey    []byte
}

func (service *APIService) SetRelationshipChangeDependencies(snapshots ports.AssessmentSnapshotRepository, comparisons ports.AssessmentComparisonRepository, lineage ports.FindingLineageRepository, scanJobs ports.ScanJobStore, replacer *cmpuc.Service, tokenKey []byte) error {
	if snapshots == nil || comparisons == nil || lineage == nil || scanJobs == nil || replacer == nil || len(tokenKey) < 32 {
		return fmt.Errorf("%w: relationship change dependencies and a 32-byte token key are required", shared.ErrValidation)
	}
	service.relationshipChanges = &relationshipChangeSupport{snapshots: snapshots, comparisons: comparisons, lineage: lineage, scanJobs: scanJobs, replacer: replacer, tokenKey: append([]byte(nil), tokenKey...)}
	return nil
}

type RelationshipChangeRequest struct {
	Command                    string    `json:"command"`
	AssessmentID               shared.ID `json:"assessment_id,omitempty"`
	NewPredecessorAssessmentID shared.ID `json:"new_predecessor_assessment_id,omitempty"`
	SelectedHeadAssessmentID   shared.ID `json:"selected_head_assessment_id,omitempty"`
}

type RelationshipImpact struct {
	MemberIDs     []string `json:"member_ids"`
	SnapshotIDs   []string `json:"snapshot_ids"`
	IdentityIDs   []string `json:"identity_ids"`
	ComparisonIDs []string `json:"comparison_ids"`
	ProjectionIDs []string `json:"projection_ids"`
}

type RelationshipPreview struct {
	CycleID                     string             `json:"cycle_id"`
	Command                     string             `json:"command"`
	AssessmentID                string             `json:"assessment_id,omitempty"`
	OldPredecessorAssessmentID  string             `json:"old_predecessor_assessment_id,omitempty"`
	NewPredecessorAssessmentID  string             `json:"new_predecessor_assessment_id,omitempty"`
	OldSelectedHeadAssessmentID string             `json:"old_selected_head_assessment_id"`
	NewSelectedHeadAssessmentID string             `json:"new_selected_head_assessment_id"`
	DescendantAssessmentIDs     []string           `json:"descendant_assessment_ids"`
	Impact                      RelationshipImpact `json:"impact"`
	Locks                       []string           `json:"locks"`
	ReasonRequired              bool               `json:"reason_required"`
	CommitAllowed               bool               `json:"commit_allowed"`
	CycleVersion                int64              `json:"cycle_version"`
	ExpiresAt                   time.Time          `json:"expires_at,omitempty"`
	PreviewToken                string             `json:"preview_token,omitempty"`
}

type RelationshipPreviewInput struct {
	TenantID shared.ID
	Actor    string
	CycleID  shared.ID
	Request  RelationshipChangeRequest
}

type RelationshipCommitInput struct {
	Request         RetainedRequest
	CycleID         shared.ID
	Change          RelationshipChangeRequest
	PreviewToken    string
	ExpectedVersion int64
	Reason          string
}

type RelationshipCommitResult struct {
	Cycle                    CycleView `json:"cycle"`
	ReplacedComparisonIDs    []string  `json:"replaced_comparison_ids"`
	ReplacementComparisonIDs []string  `json:"replacement_comparison_ids"`
}

type relationshipMemberVersion struct {
	AssessmentID shared.ID `json:"assessment_id"`
	Version      int64     `json:"version"`
}

type relationshipPreviewToken struct {
	TenantID       shared.ID                   `json:"tenant_id"`
	Actor          string                      `json:"actor"`
	CycleID        shared.ID                   `json:"cycle_id"`
	Command        string                      `json:"command"`
	RequestHash    string                      `json:"request_hash"`
	CycleVersion   int64                       `json:"cycle_version"`
	SelectedHead   shared.ID                   `json:"selected_head"`
	MemberVersions []relationshipMemberVersion `json:"member_versions"`
	Impact         RelationshipImpact          `json:"impact"`
	Nonce          string                      `json:"nonce"`
	ExpiresAt      time.Time                   `json:"expires_at"`
}

type relationshipPreviewState struct {
	preview        RelationshipPreview
	cycle          *cycledom.AssessmentCycle
	members        []cycledom.Member
	memberVersions []relationshipMemberVersion
	comparisons    []cmpdom.Comparison
}

func (service *APIService) PreviewRelationshipChange(ctx context.Context, input RelationshipPreviewInput) (RelationshipPreview, error) {
	if service.relationshipChanges == nil {
		return RelationshipPreview{}, fmt.Errorf("%w: relationship change workflow is unavailable", shared.ErrValidation)
	}
	input.TenantID, input.Actor = shared.TenantOrDefault(input.TenantID), strings.TrimSpace(input.Actor)
	if input.TenantID.IsZero() || input.CycleID.IsZero() || input.Actor == "" {
		return RelationshipPreview{}, fmt.Errorf("%w: relationship preview ownership is required", shared.ErrValidation)
	}
	state, err := service.buildRelationshipPreview(ctx, input.TenantID, input.Actor, input.CycleID, input.Request)
	if err != nil {
		return RelationshipPreview{}, err
	}
	if !state.preview.CommitAllowed {
		return state.preview, nil
	}
	requestHash, err := canonicalHash(input.Request)
	if err != nil {
		return RelationshipPreview{}, err
	}
	nonce := make([]byte, 24)
	if _, err := cryptorand.Read(nonce); err != nil {
		return RelationshipPreview{}, fmt.Errorf("generate relationship preview nonce: %w", err)
	}
	expiresAt := service.clock.Now().UTC().Add(relationshipPreviewTTL)
	token, err := signRelationshipPreview(service.relationshipChanges.tokenKey, relationshipPreviewToken{
		TenantID: input.TenantID, Actor: input.Actor, CycleID: input.CycleID, Command: input.Request.Command,
		RequestHash: requestHash, CycleVersion: state.cycle.Version, SelectedHead: state.cycle.SelectedHeadAssessmentID,
		MemberVersions: state.memberVersions, Impact: state.preview.Impact, Nonce: base64.RawURLEncoding.EncodeToString(nonce), ExpiresAt: expiresAt,
	})
	if err != nil {
		return RelationshipPreview{}, err
	}
	state.preview.ExpiresAt, state.preview.PreviewToken = expiresAt, token
	return state.preview, nil
}

func (service *APIService) CommitRelationshipChange(ctx context.Context, input RelationshipCommitInput) (RetainedResponse, error) {
	if service.relationshipChanges == nil {
		return RetainedResponse{}, fmt.Errorf("%w: relationship change workflow is unavailable", shared.ErrValidation)
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if input.CycleID.IsZero() || input.ExpectedVersion < 1 || strings.TrimSpace(input.PreviewToken) == "" {
		return RetainedResponse{}, &APIError{Code: CodeRelationshipPreviewInvalid, Cause: shared.ErrValidation}
	}
	if !safeRelationshipReason(input.Reason) {
		return RetainedResponse{}, &APIError{Code: CodeRelationshipReasonRequired, Cause: shared.ErrValidation}
	}
	tokenHash := sha256.Sum256([]byte(input.PreviewToken))
	canonical := struct {
		CycleID          shared.ID                 `json:"cycle_id"`
		Change           RelationshipChangeRequest `json:"change"`
		PreviewTokenHash string                    `json:"preview_token_hash"`
		ExpectedVersion  int64                     `json:"expected_version"`
		Reason           string                    `json:"reason"`
	}{input.CycleID, input.Change, hex.EncodeToString(tokenHash[:]), input.ExpectedVersion, input.Reason}
	var originalCycle *cycledom.AssessmentCycle
	var originalMember *cycledom.Member
	return service.executeRetained(ctx, input.Request, canonical, func(txCtx context.Context) (int, any, error) {
		token, err := verifyRelationshipPreview(service.relationshipChanges.tokenKey, input.PreviewToken)
		if err != nil {
			return 0, nil, err
		}
		tenantID, actor := shared.TenantOrDefault(input.Request.TenantID), strings.TrimSpace(input.Request.Actor)
		requestHash, err := canonicalHash(input.Change)
		if err != nil {
			return 0, nil, err
		}
		if token.TenantID != tenantID || token.Actor != actor || token.CycleID != input.CycleID || token.Command != input.Change.Command || token.RequestHash != requestHash || token.CycleVersion != input.ExpectedVersion {
			return 0, nil, &APIError{Code: CodeRelationshipPreviewStale, Cause: shared.ErrConflict}
		}
		if !service.clock.Now().UTC().Before(token.ExpiresAt) {
			return 0, nil, &APIError{Code: CodeRelationshipPreviewExpired, Cause: shared.ErrConflict}
		}
		currentCycle, err := service.cycles.GetCycle(txCtx, tenantID, input.CycleID)
		if err != nil {
			return 0, nil, err
		}
		currentMembers, err := service.cycles.ListMembers(txCtx, tenantID, input.CycleID)
		if err != nil {
			return 0, nil, err
		}
		currentVersions := make([]relationshipMemberVersion, 0, len(currentMembers))
		for _, member := range currentMembers {
			currentVersions = append(currentVersions, relationshipMemberVersion{AssessmentID: member.AssessmentID, Version: member.RelationshipVersion})
		}
		sort.Slice(currentVersions, func(left, right int) bool {
			return currentVersions[left].AssessmentID < currentVersions[right].AssessmentID
		})
		if currentCycle.Version != token.CycleVersion || currentCycle.SelectedHeadAssessmentID != token.SelectedHead || !equalRelationshipMemberVersions(token.MemberVersions, currentVersions) {
			return 0, nil, &APIError{Code: CodeRelationshipPreviewStale, Cause: shared.ErrConflict}
		}
		state, err := service.buildRelationshipPreview(txCtx, tenantID, actor, input.CycleID, input.Change)
		if err != nil {
			return 0, nil, err
		}
		if !state.preview.CommitAllowed {
			return 0, nil, &APIError{Code: CodeRelationshipLocked, Cause: shared.ErrConflict}
		}
		if (state.preview.ReasonRequired && input.Reason == "") || token.SelectedHead != state.cycle.SelectedHeadAssessmentID || !equalRelationshipMemberVersions(token.MemberVersions, state.memberVersions) || !equalRelationshipImpact(token.Impact, state.preview.Impact) {
			return 0, nil, &APIError{Code: CodeRelationshipPreviewStale, Cause: shared.ErrConflict}
		}
		cycleBefore := *state.cycle
		originalCycle = &cycleBefore
		switch input.Change.Command {
		case RelationshipCommandReparent:
			member := memberByID(state.members, input.Change.AssessmentID)
			if member == nil {
				return 0, nil, shared.ErrNotFound
			}
			memberBefore := *member
			originalMember = &memberBefore
			err = service.cycles.ReparentWithinCycle(txCtx, ReparentInput{
				TenantID: tenantID, CycleID: input.CycleID, AssessmentID: input.Change.AssessmentID,
				NewPredecessorAssessmentID: input.Change.NewPredecessorAssessmentID, ExpectedMemberVersion: member.RelationshipVersion,
				ExpectedCycleVersion: input.ExpectedVersion, Actor: actor,
			})
		case RelationshipCommandSelectHead:
			err = service.cycles.SelectHead(txCtx, SelectHeadInput{TenantID: tenantID, CycleID: input.CycleID, TargetAssessmentID: input.Change.SelectedHeadAssessmentID, ExpectedCycleVersion: input.ExpectedVersion, Actor: actor})
		}
		if err != nil {
			if errors.Is(err, shared.ErrConflict) {
				return 0, nil, &APIError{Code: CodeRelationshipPreviewStale, Cause: err}
			}
			return 0, nil, err
		}
		replaced, replacements := make([]string, 0, len(state.comparisons)), make([]string, 0, len(state.comparisons))
		for _, comparison := range state.comparisons {
			replacement, changed, replaceErr := service.relationshipChanges.replacer.Replace(txCtx, cmpuc.ReplaceInput{TenantID: tenantID, ComparisonID: comparison.ID, Actor: actor})
			if replaceErr != nil {
				return 0, nil, &APIError{Code: CodeRelationshipRecomputeFailed, Cause: replaceErr}
			}
			if changed {
				replaced, replacements = append(replaced, comparison.ID.String()), append(replacements, replacement.ID.String())
			}
		}
		cycle, err := service.cycles.GetCycle(txCtx, tenantID, input.CycleID)
		if err != nil {
			return 0, nil, err
		}
		reasonDigest := sha256.Sum256([]byte(input.Reason))
		service.record(txCtx, input.Request, "assessment_cycle.relationship_committed", input.CycleID, map[string]string{
			"command": input.Change.Command, "preview_nonce": token.Nonce, "reason_sha256": hex.EncodeToString(reasonDigest[:]),
			"replaced_comparison_count": fmt.Sprintf("%d", len(replaced)),
		})
		// ponytail: state/version drift burns the nonce because every supported command mutates CAS state;
		// add a durable nonce ledger before introducing any zero-mutation relationship command.
		return 200, RelationshipCommitResult{Cycle: projectCycle(cycle), ReplacedComparisonIDs: replaced, ReplacementComparisonIDs: replacements}, nil
	}, func(cleanupCtx context.Context) error {
		if originalCycle == nil {
			return nil
		}
		return service.cycles.compensateRelationshipMutation(cleanupCtx, originalCycle, originalMember)
	})
}

func (service *APIService) buildRelationshipPreview(ctx context.Context, tenantID shared.ID, actor string, cycleID shared.ID, request RelationshipChangeRequest) (relationshipPreviewState, error) {
	request.Command = strings.TrimSpace(request.Command)
	if request.Command != RelationshipCommandReparent && request.Command != RelationshipCommandSelectHead {
		return relationshipPreviewState{}, &APIError{Code: CodeRelationshipUnsupportedCommand, Cause: shared.ErrValidation}
	}
	cycle, err := service.cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		return relationshipPreviewState{}, err
	}
	members, err := service.cycles.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		return relationshipPreviewState{}, err
	}
	preview := RelationshipPreview{
		CycleID: cycleID.String(), Command: request.Command, OldSelectedHeadAssessmentID: cycle.SelectedHeadAssessmentID.String(),
		NewSelectedHeadAssessmentID: cycle.SelectedHeadAssessmentID.String(), CycleVersion: cycle.Version,
		Impact: RelationshipImpact{ProjectionIDs: []string{"assessment-cycle-detail:" + cycleID.String(), "assessment-cycle-list:" + cycleID.String(), "assessment-cycle-report:" + cycleID.String()}},
	}
	proposed := append([]cycledom.Member(nil), members...)
	impactedMembers := map[shared.ID]struct{}{}
	switch request.Command {
	case RelationshipCommandReparent:
		if request.AssessmentID.IsZero() || request.NewPredecessorAssessmentID.IsZero() {
			return relationshipPreviewState{}, fmt.Errorf("%w: reparent assessment and predecessor are required", shared.ErrValidation)
		}
		targetIndex, predecessorIndex := memberIndex(proposed, request.AssessmentID), memberIndex(proposed, request.NewPredecessorAssessmentID)
		if targetIndex < 0 || predecessorIndex < 0 {
			return relationshipPreviewState{}, shared.ErrNotFound
		}
		target, predecessor := proposed[targetIndex], proposed[predecessorIndex]
		if target.IsRoot() || target.IsArchived() || predecessor.IsArchived() || target.PredecessorAssessmentID == predecessor.AssessmentID {
			return relationshipPreviewState{}, fmt.Errorf("%w: reparent command is not eligible", shared.ErrValidation)
		}
		isDescendant, err := cycledom.IsAncestor(proposed, target.AssessmentID, predecessor.AssessmentID)
		if err != nil || isDescendant {
			return relationshipPreviewState{}, fmt.Errorf("%w: reparent would create a cycle", shared.ErrValidation)
		}
		descendants, err := cycledom.DeriveDescendants(proposed, target.AssessmentID)
		if err != nil {
			return relationshipPreviewState{}, err
		}
		preview.AssessmentID = target.AssessmentID.String()
		preview.OldPredecessorAssessmentID, preview.NewPredecessorAssessmentID = target.PredecessorAssessmentID.String(), predecessor.AssessmentID.String()
		impactedMembers[target.AssessmentID] = struct{}{}
		for _, descendant := range descendants {
			impactedMembers[descendant.AssessmentID] = struct{}{}
			preview.DescendantAssessmentIDs = append(preview.DescendantAssessmentIDs, descendant.AssessmentID.String())
		}
		proposed[targetIndex].PredecessorAssessmentID = predecessor.AssessmentID
		if !containsMember(cycledom.DeriveBranchHeads(proposed), cycle.SelectedHeadAssessmentID) {
			preview.Locks = append(preview.Locks, "selected_head_would_not_be_branch_head")
		}
	case RelationshipCommandSelectHead:
		if request.SelectedHeadAssessmentID.IsZero() || request.SelectedHeadAssessmentID == cycle.SelectedHeadAssessmentID {
			return relationshipPreviewState{}, fmt.Errorf("%w: a different selected branch head is required", shared.ErrValidation)
		}
		if !containsMember(cycledom.DeriveBranchHeads(proposed), request.SelectedHeadAssessmentID) {
			return relationshipPreviewState{}, cycledom.ErrInvalidBranchHead
		}
		preview.NewSelectedHeadAssessmentID = request.SelectedHeadAssessmentID.String()
		impactedMembers[cycle.SelectedHeadAssessmentID], impactedMembers[request.SelectedHeadAssessmentID] = struct{}{}, struct{}{}
	}
	if cycle.Status != cycledom.StatusOpen {
		preview.Locks = append(preview.Locks, "cycle_"+string(cycle.Status))
	}
	memberIDs := make([]shared.ID, 0, len(impactedMembers))
	for memberID := range impactedMembers {
		memberIDs = append(memberIDs, memberID)
	}
	sort.Slice(memberIDs, func(left, right int) bool { return memberIDs[left] < memberIDs[right] })
	for _, memberID := range memberIDs {
		preview.Impact.MemberIDs = append(preview.Impact.MemberIDs, memberID.String())
	}
	jobs, err := service.relationshipChanges.scanJobs.LatestForEngagements(ctx, memberIDs)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return relationshipPreviewState{}, err
	}
	for _, job := range jobs {
		if job.Status == ports.ScanRunning {
			preview.Locks = append(preview.Locks, "running_scan_job")
			break
		}
	}
	snapshotSet, identitySet := map[shared.ID]struct{}{}, map[shared.ID]struct{}{}
	for _, memberID := range memberIDs {
		snapshots, err := service.relationshipChanges.snapshots.ListByAssessment(ctx, tenantID, memberID)
		if err != nil {
			return relationshipPreviewState{}, err
		}
		for _, snapshot := range snapshots {
			snapshotSet[snapshot.ID] = struct{}{}
			observations, err := service.relationshipChanges.lineage.ListObservationsBySnapshot(ctx, tenantID, cycleID, snapshot.ID)
			if err != nil {
				return relationshipPreviewState{}, err
			}
			for _, observation := range observations {
				identitySet[observation.IdentityID] = struct{}{}
			}
		}
	}
	preview.Impact.SnapshotIDs = sortedIDStrings(snapshotSet)
	preview.Impact.IdentityIDs = sortedIDStrings(identitySet)
	allComparisons, err := service.relationshipChanges.comparisons.ListMetadataByCycle(ctx, tenantID, cycleID)
	if err != nil {
		return relationshipPreviewState{}, err
	}
	impactedComparisons := make([]cmpdom.Comparison, 0)
	for _, comparison := range allComparisons {
		if comparison.Status != cmpdom.StatusComplete && comparison.Status != cmpdom.StatusNeedsReview {
			continue
		}
		if _, baselineImpacted := snapshotSet[comparison.BaselineSnapshotID]; !baselineImpacted {
			if _, currentImpacted := snapshotSet[comparison.CurrentSnapshotID]; !currentImpacted {
				continue
			}
		}
		baseline, err := service.relationshipChanges.snapshots.Get(ctx, tenantID, comparison.BaselineSnapshotID)
		if err != nil {
			return relationshipPreviewState{}, err
		}
		current, err := service.relationshipChanges.snapshots.Get(ctx, tenantID, comparison.CurrentSnapshotID)
		if err != nil {
			return relationshipPreviewState{}, err
		}
		decision, err := cmpdom.DecidePair(comparison.Mode, baseline, current, proposed)
		if err != nil || !decision.Allowed {
			preview.Locks = append(preview.Locks, "comparison_pair_would_be_invalid:"+comparison.ID.String())
			continue
		}
		impactedComparisons = append(impactedComparisons, comparison)
		preview.Impact.ComparisonIDs = append(preview.Impact.ComparisonIDs, comparison.ID.String())
	}
	sort.Strings(preview.Impact.ComparisonIDs)
	sort.Strings(preview.DescendantAssessmentIDs)
	sort.Strings(preview.Locks)
	preview.ReasonRequired = len(preview.Impact.SnapshotIDs)+len(preview.Impact.IdentityIDs)+len(preview.Impact.ComparisonIDs) > 0
	preview.CommitAllowed = len(preview.Locks) == 0
	versions := make([]relationshipMemberVersion, 0, len(members))
	for _, member := range members {
		versions = append(versions, relationshipMemberVersion{AssessmentID: member.AssessmentID, Version: member.RelationshipVersion})
	}
	sort.Slice(versions, func(left, right int) bool { return versions[left].AssessmentID < versions[right].AssessmentID })
	return relationshipPreviewState{preview: preview, cycle: cycle, members: members, memberVersions: versions, comparisons: impactedComparisons}, nil
}

func signRelationshipPreview(key []byte, payload relationshipPreviewToken) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal relationship preview token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyRelationshipPreview(key []byte, token string) (relationshipPreviewToken, error) {
	if len(token) > 64<<10 {
		return relationshipPreviewToken{}, &APIError{Code: CodeRelationshipPreviewInvalid, Cause: shared.ErrValidation}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return relationshipPreviewToken{}, &APIError{Code: CodeRelationshipPreviewInvalid, Cause: shared.ErrValidation}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return relationshipPreviewToken{}, &APIError{Code: CodeRelationshipPreviewInvalid, Cause: shared.ErrValidation}
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return relationshipPreviewToken{}, &APIError{Code: CodeRelationshipPreviewInvalid, Cause: shared.ErrForbidden}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return relationshipPreviewToken{}, &APIError{Code: CodeRelationshipPreviewInvalid, Cause: shared.ErrValidation}
	}
	var payload relationshipPreviewToken
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.TenantID.IsZero() || payload.CycleID.IsZero() || payload.Actor == "" || payload.Nonce == "" || payload.ExpiresAt.IsZero() {
		return relationshipPreviewToken{}, &APIError{Code: CodeRelationshipPreviewInvalid, Cause: shared.ErrValidation}
	}
	return payload, nil
}

func safeRelationshipReason(reason string) bool {
	if len(reason) > 512 {
		return false
	}
	lower := strings.ToLower(reason)
	for _, marker := range []string{"password=", "passwd=", "api_key", "apikey", "access_token", "authorization:", "bearer ", "private_key", "client_secret"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func memberIndex(members []cycledom.Member, assessmentID shared.ID) int {
	for index := range members {
		if members[index].AssessmentID == assessmentID {
			return index
		}
	}
	return -1
}

func memberByID(members []cycledom.Member, assessmentID shared.ID) *cycledom.Member {
	index := memberIndex(members, assessmentID)
	if index < 0 {
		return nil
	}
	return &members[index]
}

func containsMember(members []cycledom.Member, assessmentID shared.ID) bool {
	return memberIndex(members, assessmentID) >= 0
}

func sortedIDStrings(values map[shared.ID]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value.String())
	}
	sort.Strings(result)
	return result
}

func equalRelationshipMemberVersions(left, right []relationshipMemberVersion) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalRelationshipImpact(left, right RelationshipImpact) bool {
	return equalStrings(left.MemberIDs, right.MemberIDs) && equalStrings(left.SnapshotIDs, right.SnapshotIDs) && equalStrings(left.IdentityIDs, right.IdentityIDs) && equalStrings(left.ComparisonIDs, right.ComparisonIDs) && equalStrings(left.ProjectionIDs, right.ProjectionIDs)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
