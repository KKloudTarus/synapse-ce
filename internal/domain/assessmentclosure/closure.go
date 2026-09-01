package assessmentclosure

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	PolicyVersionV1           = "closure-policy-v1"
	RendererContractVersionV1 = "assessment-cycle-report-v1"
)

type Lifecycle string

const (
	LifecycleBuilding   Lifecycle = "building"
	LifecycleActive     Lifecycle = "active"
	LifecycleSuperseded Lifecycle = "superseded"
)

type Blocker struct {
	ID           string `json:"id"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	Overrideable bool   `json:"overrideable"`
	Overridden   bool   `json:"overridden"`
}

type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type CoverageDecision struct {
	SnapshotID  shared.ID                        `json:"snapshot_id"`
	DimensionID string                           `json:"dimension_id"`
	State       assessmentsnapshot.CoverageState `json:"state"`
	ReasonCode  string                           `json:"reason_code"`
	Waived      bool                             `json:"waived"`
}

type CoverageDecisions struct {
	Initial []CoverageDecision `json:"initial"`
	Final   []CoverageDecision `json:"final"`
}

type PathMember struct {
	PathPosition        int                            `json:"path_position"`
	AssessmentID        shared.ID                      `json:"assessment_id"`
	AssessmentType      assessmentcycle.AssessmentType `json:"assessment_type"`
	RetestNumber        int                            `json:"retest_number"`
	RelationshipVersion int64                          `json:"relationship_version"`
	SnapshotID          shared.ID                      `json:"snapshot_id,omitempty"`
}

type Reference struct {
	Kind        string          `json:"kind"`
	ID          shared.ID       `json:"id"`
	Version     int64           `json:"version"`
	ContentHash string          `json:"content_hash,omitempty"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

type BranchState struct {
	AssessmentID        shared.ID `json:"assessment_id"`
	RelationshipVersion int64     `json:"relationship_version"`
	Archived            bool      `json:"archived"`
}

type ScopeProfileChange struct {
	AssessmentID shared.ID `json:"assessment_id"`
	Kind         string    `json:"kind"`
	Summary      string    `json:"summary"`
}

type Manifest struct {
	TenantID                shared.ID
	CycleID                 shared.ID
	ID                      shared.ID
	ManifestVersion         int64
	Lifecycle               Lifecycle
	CycleVersion            int64
	RootAssessmentID        shared.ID
	FinalAssessmentID       shared.ID
	InitialSnapshotID       shared.ID
	FinalSnapshotID         shared.ID
	ComparisonID            shared.ID
	InitialSnapshotHash     string
	FinalSnapshotHash       string
	ComparisonHash          string
	CanonicalInputHash      string
	ContentHash             string
	PolicyVersion           string
	AlgorithmVersion        string
	FingerprintVersion      string
	RiskVersion             string
	RendererContractVersion string
	CoverageDecisions       CoverageDecisions
	ScopeProfileChanges     []ScopeProfileChange
	OverrideBlockerIDs      []string
	NonFinalBranches        []BranchState
	Path                    []PathMember
	References              []Reference
	Reason                  string
	OverrideReason          string
	AsOfAt                  time.Time
	CreatedAt               time.Time
	CreatedBy               string
	SealedAt                *time.Time
	SealedBy                string
	SupersededAt            *time.Time
	SupersededByManifestID  shared.ID
}

type PolicyInput struct {
	Cycle              *assessmentcycle.AssessmentCycle
	FinalStatus        engagement.Status
	InitialSnapshot    *assessmentsnapshot.Snapshot
	FinalSnapshot      *assessmentsnapshot.Snapshot
	Comparison         *assessmentcomparison.Comparison
	References         []Reference
	AsOfAt             time.Time
	OverrideBlockerIDs []string
	OverrideReason     string
}

type PolicyResult struct {
	PolicyVersion     string            `json:"policy_version"`
	Blockers          []Blocker         `json:"blockers"`
	Warnings          []Warning         `json:"warnings"`
	CoverageDecisions CoverageDecisions `json:"coverage_decisions"`
	CommitAllowed     bool              `json:"commit_allowed"`
}

func Evaluate(input PolicyInput) PolicyResult {
	result := PolicyResult{PolicyVersion: PolicyVersionV1, Blockers: []Blocker{}, Warnings: []Warning{}}
	add := func(id, code, message string, overrideable bool) {
		result.Blockers = append(result.Blockers, Blocker{ID: id, Code: code, Message: message, Overrideable: overrideable})
	}
	if input.Cycle == nil || input.Cycle.Status != assessmentcycle.StatusOpen {
		add("cycle:not_open", "cycle_not_open", "Assessment Cycle must be open.", false)
	}
	if input.FinalStatus != engagement.StatusCompleted {
		add("assessment:not_completed", "final_assessment_not_completed", "Selected final Assessment must be completed.", false)
	}
	if input.InitialSnapshot == nil {
		add("snapshot:initial_missing", "initial_snapshot_missing", "Root Assessment has no default finalized Snapshot.", false)
	}
	if input.FinalSnapshot == nil {
		add("snapshot:final_missing", "final_snapshot_missing", "Selected final Assessment has no default finalized Snapshot.", false)
	}
	if input.Comparison == nil {
		add("comparison:missing", "comparison_missing", "No immutable root-to-final lifecycle Comparison exists.", false)
	} else {
		if input.Comparison.Status != assessmentcomparison.StatusComplete {
			add("comparison:incomplete", "comparison_incomplete", "Lifecycle Comparison must be complete with no pending review.", false)
		}
		if input.InitialSnapshot != nil && input.FinalSnapshot != nil &&
			(input.Comparison.BaselineSnapshotID != input.InitialSnapshot.ID || input.Comparison.CurrentSnapshotID != input.FinalSnapshot.ID || input.Comparison.Mode != assessmentcomparison.ModeLifecycle) {
			add("comparison:pair_mismatch", "comparison_pair_mismatch", "Lifecycle Comparison does not bind the root and selected final Snapshots.", false)
		}
		if input.Comparison.Summary.ReviewCount > 0 {
			add("comparison:review_pending", "identity_review_pending", "Comparison contains unresolved identity review.", false)
		}
		for _, item := range input.Comparison.Items {
			if !item.VerificationID.IsZero() && item.VerificationState != "remediated" {
				add("verification:"+item.VerificationID.String(), "verification_incomplete", "Required Finding verification is not complete.", false)
			}
			severity := item.CurrentObservation.Severity
			if item.CurrentActionable && (severity == shared.SeverityCritical || severity == shared.SeverityHigh) {
				add("finding:"+item.ID.String(), "open_high_critical", "Critical/High finding remains actionable at closure.", true)
			}
		}
	}
	asOfAt := input.AsOfAt.UTC()
	for _, reference := range input.References {
		if !asOfAt.IsZero() && reference.ExpiresAt != nil && !asOfAt.Before(*reference.ExpiresAt) {
			add("reference:expired:"+digestID(reference.Kind+"|"+reference.ID.String()), "decision_expired", "An effective closure decision expired before preview.", false)
		}
	}
	result.CoverageDecisions.Initial = coverageDecisions(input.InitialSnapshot, "initial", add)
	result.CoverageDecisions.Final = coverageDecisions(input.FinalSnapshot, "final", add)
	applyOverrides(&result, input.OverrideBlockerIDs, input.OverrideReason)
	result.CommitAllowed = true
	for _, blocker := range result.Blockers {
		if !blocker.Overridden {
			result.CommitAllowed = false
			break
		}
	}
	return result
}

func coverageDecisions(snapshot *assessmentsnapshot.Snapshot, label string, add func(string, string, string, bool)) []CoverageDecision {
	if snapshot == nil {
		return []CoverageDecision{}
	}
	decisions := make([]CoverageDecision, 0, len(snapshot.Dimensions))
	for _, dimension := range snapshot.Dimensions {
		id := strings.Join([]string{string(dimension.Target.Kind), dimension.Target.Canonical, dimension.Producer, dimension.FindingKind}, "|")
		decision := CoverageDecision{SnapshotID: snapshot.ID, DimensionID: id, State: dimension.State, ReasonCode: dimension.ReasonCode}
		if dimension.State != assessmentsnapshot.CoverageComplete {
			add("coverage:"+label+":"+digestID(id), "coverage_incomplete", "Required coverage is partial or unknown.", true)
		}
		decisions = append(decisions, decision)
	}
	return decisions
}

func applyOverrides(result *PolicyResult, requested []string, reason string) {
	requested = canonicalStrings(requested)
	known := map[string]int{}
	for index := range result.Blockers {
		known[result.Blockers[index].ID] = index
	}
	for _, id := range requested {
		index, exists := known[id]
		switch {
		case !exists:
			result.Blockers = append(result.Blockers, Blocker{ID: "override:unknown:" + digestID(id), Code: "override_unknown", Message: "Requested override does not match a current blocker."})
		case !result.Blockers[index].Overrideable:
			result.Blockers = append(result.Blockers, Blocker{ID: "override:hard:" + digestID(id), Code: "override_hard_blocker", Message: "Integrity blocker cannot be overridden."})
		case strings.TrimSpace(reason) == "":
			result.Blockers = append(result.Blockers, Blocker{ID: "override:reason_required", Code: "override_reason_required", Message: "Override reason is required."})
		default:
			result.Blockers[index].Overridden = true
		}
	}
	for index := range result.CoverageDecisions.Initial {
		result.CoverageDecisions.Initial[index].Waived = coverageWaived(result.Blockers, "initial", result.CoverageDecisions.Initial[index].DimensionID)
	}
	for index := range result.CoverageDecisions.Final {
		result.CoverageDecisions.Final[index].Waived = coverageWaived(result.Blockers, "final", result.CoverageDecisions.Final[index].DimensionID)
	}
}

func coverageWaived(blockers []Blocker, label, dimensionID string) bool {
	id := "coverage:" + label + ":" + digestID(dimensionID)
	for _, blocker := range blockers {
		if blocker.ID == id {
			return blocker.Overridden
		}
	}
	return false
}

type ManifestInput struct {
	TenantID            shared.ID
	CycleID             shared.ID
	ManifestVersion     int64
	CycleVersion        int64
	RootAssessmentID    shared.ID
	FinalAssessmentID   shared.ID
	InitialSnapshot     *assessmentsnapshot.Snapshot
	FinalSnapshot       *assessmentsnapshot.Snapshot
	Comparison          *assessmentcomparison.Comparison
	CoverageDecisions   CoverageDecisions
	ScopeProfileChanges []ScopeProfileChange
	OverrideBlockerIDs  []string
	NonFinalBranches    []BranchState
	Path                []PathMember
	References          []Reference
	Reason              string
	OverrideReason      string
	AsOfAt              time.Time
	CreatedAt           time.Time
	CreatedBy           string
}

func NewManifest(id shared.ID, input ManifestInput) (*Manifest, error) {
	if input.InitialSnapshot == nil || input.FinalSnapshot == nil || input.Comparison == nil {
		return nil, fmt.Errorf("%w: closure manifest immutable artifacts are required", shared.ErrValidation)
	}
	if input.InitialSnapshot.TenantID != input.TenantID || input.FinalSnapshot.TenantID != input.TenantID || input.Comparison.TenantID != input.TenantID ||
		input.InitialSnapshot.CycleID != input.CycleID || input.FinalSnapshot.CycleID != input.CycleID || input.Comparison.CycleID != input.CycleID ||
		input.InitialSnapshot.AssessmentID != input.RootAssessmentID || input.FinalSnapshot.AssessmentID != input.FinalAssessmentID ||
		input.Comparison.BaselineSnapshotID != input.InitialSnapshot.ID || input.Comparison.CurrentSnapshotID != input.FinalSnapshot.ID ||
		(input.InitialSnapshot.Lifecycle != assessmentsnapshot.LifecycleFinalized && input.InitialSnapshot.Lifecycle != assessmentsnapshot.LifecycleSuperseded) ||
		(input.FinalSnapshot.Lifecycle != assessmentsnapshot.LifecycleFinalized && input.FinalSnapshot.Lifecycle != assessmentsnapshot.LifecycleSuperseded) ||
		input.Comparison.Mode != assessmentcomparison.ModeLifecycle || input.Comparison.Status != assessmentcomparison.StatusComplete ||
		input.Comparison.AlgorithmVersion < 1 || input.Comparison.FingerprintVersion < 1 || input.Comparison.RiskModelVersion < 1 {
		return nil, fmt.Errorf("%w: closure manifest immutable artifacts do not match the final path", shared.ErrValidation)
	}
	references, err := canonicalReferences(input.References)
	if err != nil {
		return nil, err
	}
	manifest := &Manifest{
		TenantID: input.TenantID, CycleID: input.CycleID, ID: id, ManifestVersion: input.ManifestVersion,
		Lifecycle: LifecycleBuilding, CycleVersion: input.CycleVersion, RootAssessmentID: input.RootAssessmentID, FinalAssessmentID: input.FinalAssessmentID,
		InitialSnapshotID: input.InitialSnapshot.ID, FinalSnapshotID: input.FinalSnapshot.ID, ComparisonID: input.Comparison.ID,
		InitialSnapshotHash: input.InitialSnapshot.ContentHash, FinalSnapshotHash: input.FinalSnapshot.ContentHash, ComparisonHash: input.Comparison.ContentHash,
		PolicyVersion: PolicyVersionV1, AlgorithmVersion: fmt.Sprintf("comparison-v%d", input.Comparison.AlgorithmVersion),
		FingerprintVersion: fmt.Sprintf("fingerprint-v%d", input.Comparison.FingerprintVersion), RiskVersion: fmt.Sprintf("risk-v%d", input.Comparison.RiskModelVersion),
		RendererContractVersion: RendererContractVersionV1, CoverageDecisions: canonicalCoverage(input.CoverageDecisions),
		ScopeProfileChanges: canonicalScopeChanges(input.ScopeProfileChanges), OverrideBlockerIDs: canonicalStrings(input.OverrideBlockerIDs),
		NonFinalBranches: canonicalBranches(input.NonFinalBranches), Path: canonicalPath(input.Path), References: references,
		Reason: strings.TrimSpace(input.Reason), OverrideReason: strings.TrimSpace(input.OverrideReason), AsOfAt: canonicalTime(input.AsOfAt), CreatedAt: canonicalTime(input.CreatedAt), CreatedBy: strings.TrimSpace(input.CreatedBy),
	}
	hash, err := manifest.hashInput()
	if err != nil {
		return nil, err
	}
	manifest.CanonicalInputHash = hash
	return manifest, manifest.Validate()
}

func (manifest *Manifest) Seal(at time.Time, actor string) error {
	if manifest == nil || manifest.Lifecycle != LifecycleBuilding || at.IsZero() || strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: closure manifest cannot be sealed", shared.ErrValidation)
	}
	hash, err := manifest.hashContent()
	if err != nil {
		return err
	}
	sealedAt := canonicalTime(at)
	manifest.Lifecycle, manifest.ContentHash, manifest.SealedAt, manifest.SealedBy = LifecycleActive, hash, &sealedAt, strings.TrimSpace(actor)
	return manifest.Validate()
}

func (manifest *Manifest) Supersede(at time.Time, successor shared.ID) error {
	if manifest == nil || manifest.Lifecycle != LifecycleActive || at.IsZero() {
		return fmt.Errorf("%w: active closure manifest is required", shared.ErrValidation)
	}
	supersededAt := canonicalTime(at)
	manifest.Lifecycle, manifest.SupersededAt, manifest.SupersededByManifestID = LifecycleSuperseded, &supersededAt, successor
	return manifest.Validate()
}

func (manifest Manifest) Validate() error {
	if manifest.TenantID.IsZero() || manifest.CycleID.IsZero() || manifest.ID.IsZero() || manifest.RootAssessmentID.IsZero() || manifest.FinalAssessmentID.IsZero() ||
		manifest.InitialSnapshotID.IsZero() || manifest.FinalSnapshotID.IsZero() || manifest.ComparisonID.IsZero() || manifest.ManifestVersion < 1 || manifest.CycleVersion < 1 {
		return fmt.Errorf("%w: closure manifest identity is invalid", shared.ErrValidation)
	}
	if !validHash(manifest.InitialSnapshotHash) || !validHash(manifest.FinalSnapshotHash) || !validHash(manifest.ComparisonHash) || !validHash(manifest.CanonicalInputHash) {
		return fmt.Errorf("%w: closure manifest reference hash is invalid", shared.ErrValidation)
	}
	versions := []string{manifest.PolicyVersion, manifest.AlgorithmVersion, manifest.FingerprintVersion, manifest.RiskVersion, manifest.RendererContractVersion}
	for _, version := range versions {
		if version == "" || version != strings.TrimSpace(version) || len(version) > 128 {
			return fmt.Errorf("%w: closure manifest policy metadata is invalid", shared.ErrValidation)
		}
	}
	if manifest.AsOfAt.IsZero() || manifest.CreatedAt.IsZero() || manifest.AsOfAt.After(manifest.CreatedAt) || manifest.CreatedBy == "" ||
		manifest.CreatedBy != strings.TrimSpace(manifest.CreatedBy) || len(manifest.CreatedBy) > 256 || manifest.SealedBy != strings.TrimSpace(manifest.SealedBy) || len(manifest.SealedBy) > 256 ||
		len(manifest.Reason) > 4096 || len(manifest.OverrideReason) > 4096 {
		return fmt.Errorf("%w: closure manifest policy metadata is invalid", shared.ErrValidation)
	}
	if err := validatePath(manifest); err != nil {
		return err
	}
	if err := validateCoverage(manifest.CoverageDecisions, manifest.InitialSnapshotID, manifest.FinalSnapshotID); err != nil {
		return err
	}
	for _, reference := range manifest.References {
		if strings.TrimSpace(reference.Kind) == "" || reference.ID.IsZero() || reference.Version < 1 || reference.Kind != strings.TrimSpace(reference.Kind) ||
			(reference.ContentHash != "" && !validHash(reference.ContentHash)) {
			return fmt.Errorf("%w: closure manifest reference is invalid", shared.ErrValidation)
		}
		canonical, err := canonicalJSON(reference.Metadata)
		if err != nil || !bytes.Equal(canonical, reference.Metadata) {
			return fmt.Errorf("%w: closure manifest reference metadata is not canonical", shared.ErrValidation)
		}
	}
	wantInputHash, err := manifest.hashInput()
	if err != nil || wantInputHash != manifest.CanonicalInputHash {
		return fmt.Errorf("%w: closure manifest canonical input hash mismatch", shared.ErrValidation)
	}
	switch manifest.Lifecycle {
	case LifecycleBuilding:
		if manifest.ContentHash != "" || manifest.SealedAt != nil || manifest.SealedBy != "" || manifest.SupersededAt != nil || !manifest.SupersededByManifestID.IsZero() {
			return fmt.Errorf("%w: building closure manifest has terminal fields", shared.ErrValidation)
		}
	case LifecycleActive:
		if !validHash(manifest.ContentHash) || manifest.SealedAt == nil || manifest.SealedBy == "" || manifest.SealedAt.Before(manifest.CreatedAt) || manifest.SupersededAt != nil || !manifest.SupersededByManifestID.IsZero() {
			return fmt.Errorf("%w: active closure manifest is not sealed", shared.ErrValidation)
		}
	case LifecycleSuperseded:
		if !validHash(manifest.ContentHash) || manifest.SealedAt == nil || manifest.SealedBy == "" || manifest.SealedAt.Before(manifest.CreatedAt) || manifest.SupersededAt == nil || manifest.SupersededAt.Before(*manifest.SealedAt) {
			return fmt.Errorf("%w: superseded closure manifest is invalid", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: closure manifest lifecycle is invalid", shared.ErrValidation)
	}
	if manifest.Lifecycle != LifecycleBuilding {
		wantContentHash, err := manifest.hashContent()
		if err != nil || wantContentHash != manifest.ContentHash {
			return fmt.Errorf("%w: closure manifest content hash mismatch", shared.ErrValidation)
		}
	}
	return nil
}

func (manifest Manifest) hashInput() (string, error) {
	return hashJSON(struct {
		TenantID            shared.ID            `json:"tenant_id"`
		CycleID             shared.ID            `json:"cycle_id"`
		ManifestVersion     int64                `json:"manifest_version"`
		CycleVersion        int64                `json:"cycle_version"`
		RootAssessmentID    shared.ID            `json:"root_assessment_id"`
		FinalAssessmentID   shared.ID            `json:"final_assessment_id"`
		InitialSnapshotID   shared.ID            `json:"initial_snapshot_id"`
		FinalSnapshotID     shared.ID            `json:"final_snapshot_id"`
		ComparisonID        shared.ID            `json:"comparison_id"`
		InitialSnapshotHash string               `json:"initial_snapshot_hash"`
		FinalSnapshotHash   string               `json:"final_snapshot_hash"`
		ComparisonHash      string               `json:"comparison_hash"`
		PolicyVersion       string               `json:"policy_version"`
		AlgorithmVersion    string               `json:"algorithm_version"`
		FingerprintVersion  string               `json:"fingerprint_version"`
		RiskVersion         string               `json:"risk_version"`
		RendererVersion     string               `json:"renderer_contract_version"`
		Coverage            CoverageDecisions    `json:"coverage_decisions"`
		ScopeProfileChanges []ScopeProfileChange `json:"scope_profile_changes"`
		OverrideBlockerIDs  []string             `json:"override_blocker_ids"`
		NonFinalBranches    []BranchState        `json:"non_final_branches"`
		Path                []PathMember         `json:"path"`
		References          []Reference          `json:"references"`
		AsOfAt              time.Time            `json:"as_of_at"`
	}{manifest.TenantID, manifest.CycleID, manifest.ManifestVersion, manifest.CycleVersion, manifest.RootAssessmentID, manifest.FinalAssessmentID,
		manifest.InitialSnapshotID, manifest.FinalSnapshotID, manifest.ComparisonID, manifest.InitialSnapshotHash, manifest.FinalSnapshotHash, manifest.ComparisonHash,
		manifest.PolicyVersion, manifest.AlgorithmVersion, manifest.FingerprintVersion, manifest.RiskVersion, manifest.RendererContractVersion, manifest.CoverageDecisions,
		manifest.ScopeProfileChanges, manifest.OverrideBlockerIDs, manifest.NonFinalBranches, manifest.Path, manifest.References, manifest.AsOfAt})
}

func (manifest Manifest) hashContent() (string, error) {
	return hashJSON(struct {
		CanonicalInputHash string    `json:"canonical_input_hash"`
		Reason             string    `json:"reason"`
		OverrideReason     string    `json:"override_reason"`
		CreatedAt          time.Time `json:"created_at"`
		CreatedBy          string    `json:"created_by"`
	}{manifest.CanonicalInputHash, manifest.Reason, manifest.OverrideReason, manifest.CreatedAt, manifest.CreatedBy})
}

func hashJSON(value any) (string, error) {
	// ponytail: these canonical structs contain no maps or floating-point values; switch to a full RFC 8785 encoder if either is added.
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", fmt.Errorf("marshal canonical closure manifest: %w", err)
	}
	digest := sha256.Sum256(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")))
	return hex.EncodeToString(digest[:]), nil
}

func canonicalPath(values []PathMember) []PathMember {
	result := append([]PathMember(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].PathPosition < result[j].PathPosition })
	return result
}

func canonicalCoverage(values CoverageDecisions) CoverageDecisions {
	canonical := func(decisions []CoverageDecision) []CoverageDecision {
		result := append([]CoverageDecision(nil), decisions...)
		sort.Slice(result, func(i, j int) bool {
			if result[i].SnapshotID == result[j].SnapshotID {
				return result[i].DimensionID < result[j].DimensionID
			}
			return result[i].SnapshotID < result[j].SnapshotID
		})
		return result
	}
	return CoverageDecisions{Initial: canonical(values.Initial), Final: canonical(values.Final)}
}

func canonicalBranches(values []BranchState) []BranchState {
	result := append([]BranchState(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].AssessmentID < result[j].AssessmentID })
	return result
}

func canonicalReferences(values []Reference) ([]Reference, error) {
	result := append([]Reference(nil), values...)
	for index := range result {
		metadata, err := canonicalJSON(result[index].Metadata)
		if err != nil {
			return nil, fmt.Errorf("%w: closure reference metadata is invalid", shared.ErrValidation)
		}
		result[index].Metadata = metadata
		if result[index].ExpiresAt != nil {
			expiresAt := canonicalTime(*result[index].ExpiresAt)
			result[index].ExpiresAt = &expiresAt
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind == result[j].Kind {
			return result[i].ID < result[j].ID
		}
		return result[i].Kind < result[j].Kind
	})
	return result, nil
}

func canonicalJSON(value json.RawMessage) (json.RawMessage, error) {
	if len(value) == 0 {
		return json.RawMessage("{}"), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func validatePath(manifest Manifest) error {
	if len(manifest.Path) == 0 || manifest.Path[0].AssessmentID != manifest.RootAssessmentID || manifest.Path[len(manifest.Path)-1].AssessmentID != manifest.FinalAssessmentID {
		return fmt.Errorf("%w: closure manifest path endpoints are invalid", shared.ErrValidation)
	}
	seen := map[shared.ID]struct{}{}
	for index, member := range manifest.Path {
		if member.PathPosition != index || member.AssessmentID.IsZero() || !member.AssessmentType.Valid() || member.RelationshipVersion < 1 {
			return fmt.Errorf("%w: closure manifest path member is invalid", shared.ErrValidation)
		}
		if member.AssessmentType == assessmentcycle.AssessmentTypeInitial && (index != 0 || member.RetestNumber != 0) ||
			member.AssessmentType == assessmentcycle.AssessmentTypeRetest && member.RetestNumber < 1 {
			return fmt.Errorf("%w: closure manifest path sequence is invalid", shared.ErrValidation)
		}
		if _, exists := seen[member.AssessmentID]; exists {
			return fmt.Errorf("%w: closure manifest path member is duplicated", shared.ErrValidation)
		}
		seen[member.AssessmentID] = struct{}{}
	}
	return nil
}

func validateCoverage(coverage CoverageDecisions, initialSnapshotID, finalSnapshotID shared.ID) error {
	validate := func(decisions []CoverageDecision, snapshotID shared.ID) error {
		seen := map[string]struct{}{}
		for _, decision := range decisions {
			if decision.SnapshotID != snapshotID || strings.TrimSpace(decision.DimensionID) == "" ||
				(decision.State != assessmentsnapshot.CoverageComplete && decision.State != assessmentsnapshot.CoveragePartial && decision.State != assessmentsnapshot.CoverageUnknown) {
				return fmt.Errorf("%w: closure manifest coverage decision is invalid", shared.ErrValidation)
			}
			if _, exists := seen[decision.DimensionID]; exists {
				return fmt.Errorf("%w: closure manifest coverage decision is duplicated", shared.ErrValidation)
			}
			seen[decision.DimensionID] = struct{}{}
		}
		return nil
	}
	if err := validate(coverage.Initial, initialSnapshotID); err != nil {
		return err
	}
	return validate(coverage.Final, finalSnapshotID)
}

func canonicalScopeChanges(values []ScopeProfileChange) []ScopeProfileChange {
	result := append([]ScopeProfileChange(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].AssessmentID == result[j].AssessmentID {
			return result[i].Kind < result[j].Kind
		}
		return result[i].AssessmentID < result[j].AssessmentID
	})
	return result
}

func canonicalStrings(values []string) []string {
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

func digestID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}

func validHash(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func canonicalTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}
