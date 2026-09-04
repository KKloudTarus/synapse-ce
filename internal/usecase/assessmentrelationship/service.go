package assessmentrelationship

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentrelationship"
	snapshotdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	DefaultExpiry = 30 * 24 * time.Hour
	MaxExpiry     = 90 * 24 * time.Hour
	DefaultLimit  = 50
	MaxLimit      = 200
)

const (
	StatusOpen      = "open"
	StatusConfirmed = "confirmed"
	StatusRejected  = "rejected"
	StatusDismissed = "dismissed"
	StatusExpired   = "expired"
)

type Service struct {
	store     ports.AssessmentRelationshipRepository
	cycles    ports.AssessmentCycleRepository
	snapshots ports.AssessmentSnapshotRepository
	lineage   ports.FindingLineageRepository
	tx        ports.TenantTransactionRunner
	ids       ports.IDGenerator
	clock     ports.Clock
	audit     ports.AuditLogger
	observer  ports.AssessmentRelationshipObserver
}

func NewService(store ports.AssessmentRelationshipRepository, cycles ports.AssessmentCycleRepository, snapshots ports.AssessmentSnapshotRepository, lineage ports.FindingLineageRepository, tx ports.TenantTransactionRunner, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger, observer ports.AssessmentRelationshipObserver) (*Service, error) {
	if store == nil || cycles == nil || snapshots == nil || lineage == nil || tx == nil || ids == nil || clock == nil || audit == nil {
		return nil, fmt.Errorf("%w: assessment relationship dependencies are required", shared.ErrValidation)
	}
	return &Service{store: store, cycles: cycles, snapshots: snapshots, lineage: lineage, tx: tx, ids: ids, clock: clock, audit: audit, observer: observer}, nil
}

func (service *Service) SetObserver(observer ports.AssessmentRelationshipObserver) {
	service.observer = observer
}

type GenerateInput struct {
	TenantID              shared.ID
	PredecessorCycleID    shared.ID
	SuccessorCycleID      shared.ID
	ImportedReferenceHash string
	ExpiresIn             time.Duration
	Actor                 string
}

func (service *Service) Generate(ctx context.Context, input GenerateInput) (View, bool, error) {
	tenantID, actor := shared.TenantOrDefault(input.TenantID), strings.TrimSpace(input.Actor)
	if tenantID.IsZero() || input.PredecessorCycleID.IsZero() || input.SuccessorCycleID.IsZero() || input.PredecessorCycleID == input.SuccessorCycleID || actor == "" || len([]rune(actor)) > 256 {
		return View{}, false, fmt.Errorf("%w: relationship candidate request is invalid", shared.ErrValidation)
	}
	expiresIn := input.ExpiresIn
	if expiresIn == 0 {
		expiresIn = DefaultExpiry
	}
	if expiresIn < 24*time.Hour || expiresIn > MaxExpiry {
		return View{}, false, fmt.Errorf("%w: relationship candidate expiry must be between 1 and 90 days", shared.ErrValidation)
	}
	if input.ImportedReferenceHash != "" && !validDigest(input.ImportedReferenceHash) {
		return View{}, false, fmt.Errorf("%w: imported relationship reference must be a SHA-256 digest", shared.ErrValidation)
	}

	predecessor, predecessorMember, predecessorSnapshot, err := service.loadSubject(ctx, tenantID, input.PredecessorCycleID)
	if err != nil {
		return View{}, false, err
	}
	successor, successorMember, successorSnapshot, err := service.loadSubject(ctx, tenantID, input.SuccessorCycleID)
	if err != nil {
		return View{}, false, err
	}
	boundaryHash, err := exactBoundaryHash(predecessor, successor)
	if err != nil {
		return View{}, false, err
	}
	signals := []domain.Signal{{Kind: domain.SignalExactBoundary, EvidenceHash: boundaryHash, SchemaVersion: domain.SchemaVersion}}
	if input.ImportedReferenceHash != "" {
		// ponytail: imported evidence is hash-only; add a signed import-evidence adapter when ingestion exposes one.
		signals = append(signals, domain.Signal{Kind: domain.SignalImportedReference, EvidenceHash: input.ImportedReferenceHash, MatchCount: 1, ScoreMilli: 1000, SchemaVersion: domain.SchemaVersion})
	}
	if signal, ok := compatibleManifestSignal(predecessorSnapshot, successorSnapshot); ok {
		signals = append(signals, signal)
	}
	if signal, ok, err := service.overlapSignal(ctx, tenantID, predecessorSnapshot, successorSnapshot); err != nil {
		return View{}, false, err
	} else if ok {
		signals = append(signals, signal)
	}
	if len(signals) == 1 {
		return View{}, false, fmt.Errorf("%w: exact boundary alone cannot establish a historical relationship candidate", shared.ErrValidation)
	}
	confidence := domain.ConfidenceMedium
	if len(signals) >= 3 {
		confidence = domain.ConfidenceHigh
	}
	now := service.clock.Now().UTC()
	candidate, err := domain.NewCandidate(domain.Candidate{
		TenantID: tenantID, ID: service.ids.NewID(),
		PredecessorCycleID: predecessor.ID, PredecessorAssessmentID: predecessorMember.AssessmentID,
		PredecessorRelationshipVersion: predecessorMember.RelationshipVersion, PredecessorSnapshotID: predecessorSnapshot.ID,
		PredecessorSnapshotHash: predecessorSnapshot.ContentHash, SuccessorCycleID: successor.ID,
		SuccessorAssessmentID: successorMember.AssessmentID, SuccessorRelationshipVersion: successorMember.RelationshipVersion,
		SuccessorSnapshotID: successorSnapshot.ID, SuccessorSnapshotHash: successorSnapshot.ContentHash,
		BoundaryKeyHash: boundaryHash, Signals: signals, Confidence: confidence,
		ExpiresAt: now.Add(expiresIn), CreatedBy: actor, CreatedAt: now,
	})
	if err != nil {
		return View{}, false, err
	}
	var record domain.Record
	var created bool
	err = service.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		var err error
		record, created, err = service.store.CreateCandidate(txCtx, candidate)
		if err != nil {
			return err
		}
		if !created {
			return nil
		}
		return service.audit.Record(txCtx, ports.AuditEntry{Actor: actor, Action: "assessment_relationship.candidate_created", Target: record.Candidate.ID.String(), Metadata: map[string]string{
			"input_hash": record.Candidate.InputHash, "confidence": string(record.Candidate.Confidence),
			"predecessor_cycle_id": record.Candidate.PredecessorCycleID.String(), "successor_cycle_id": record.Candidate.SuccessorCycleID.String(),
		}, At: now})
	})
	if err != nil {
		if service.observer != nil {
			service.observer.ObserveAssessmentRelationshipCandidate("failed", string(confidence))
		}
		return View{}, false, err
	}
	if service.observer != nil {
		outcome := "existing"
		if created {
			outcome = "created"
		}
		service.observer.ObserveAssessmentRelationshipCandidate(outcome, string(record.Candidate.Confidence))
	}
	return project(record, now), created, nil
}

type DecideInput struct {
	TenantID        shared.ID
	CandidateID     shared.ID
	ExpectedVersion int64
	IdempotencyKey  string
	Action          domain.DecisionAction
	Reason          string
	Actor           string
}

func (service *Service) Decide(ctx context.Context, input DecideInput) (View, bool, error) {
	tenantID, actor := shared.TenantOrDefault(input.TenantID), strings.TrimSpace(input.Actor)
	reason, key := strings.TrimSpace(input.Reason), strings.TrimSpace(input.IdempotencyKey)
	if tenantID.IsZero() || input.CandidateID.IsZero() || input.ExpectedVersion < 1 || !input.Action.Valid() || actor == "" || len([]rune(actor)) > 256 || key == "" || len([]rune(key)) > 128 || reason == "" || len([]rune(reason)) > 2000 {
		return View{}, false, fmt.Errorf("%w: relationship candidate decision request is invalid", shared.ErrValidation)
	}
	if input.ExpectedVersion != 1 {
		return View{}, false, fmt.Errorf("%w: relationship candidate version mismatch", shared.ErrConflict)
	}
	if sensitiveReason(reason) {
		return View{}, false, fmt.Errorf("%w: decision reason contains credential material", shared.ErrValidation)
	}
	requestHash := hashJSON(struct {
		Action domain.DecisionAction `json:"action"`
		Reason string                `json:"reason"`
	}{input.Action, reason})
	now := service.clock.Now().UTC()
	decision := domain.Decision{
		TenantID: tenantID, ID: service.ids.NewID(), CandidateID: input.CandidateID, Action: input.Action,
		Actor: actor, Reason: reason, IdempotencyKey: key, RequestHash: requestHash,
		ExpectedVersion: input.ExpectedVersion, Version: 2, CreatedAt: now,
	}
	var plan *domain.RepairPlan
	var result domain.Record
	var replayed bool
	err := service.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		record, err := service.store.GetCandidate(txCtx, tenantID, input.CandidateID)
		if err != nil {
			return err
		}
		if record.Decision == nil && !record.Candidate.ExpiresAt.After(now) {
			return fmt.Errorf("%w: relationship candidate expired", shared.ErrConflict)
		}
		if input.Action == domain.DecisionConfirm {
			built, err := service.buildRepairPlan(record.Candidate, actor, now)
			if err != nil {
				return err
			}
			plan = &built
			decision.RepairPlanID = built.ID
		}
		result, replayed, err = service.store.DecideCandidateCAS(txCtx, decision, plan)
		if err != nil {
			return err
		}
		if replayed {
			return nil
		}
		return service.audit.Record(txCtx, ports.AuditEntry{Actor: actor, Action: "assessment_relationship.candidate_" + string(input.Action), Target: input.CandidateID.String(), Metadata: map[string]string{
			"idempotency_key": key, "request_hash": requestHash,
		}, At: now})
	})
	if err != nil {
		if service.observer != nil {
			service.observer.ObserveAssessmentRelationshipDecision(string(input.Action), "failed")
		}
		return View{}, false, err
	}
	if service.observer != nil {
		outcome := "applied"
		if replayed {
			outcome = "replayed"
		}
		service.observer.ObserveAssessmentRelationshipDecision(string(input.Action), outcome)
	}
	return project(result, now), replayed, nil
}

func (service *Service) Get(ctx context.Context, tenantID, candidateID shared.ID) (View, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || candidateID.IsZero() {
		return View{}, fmt.Errorf("%w: relationship candidate identity is invalid", shared.ErrValidation)
	}
	record, err := service.store.GetCandidate(ctx, tenantID, candidateID)
	if err != nil {
		return View{}, err
	}
	return project(record, service.clock.Now().UTC()), nil
}

func (service *Service) List(ctx context.Context, tenantID shared.ID, status string, limit int) ([]View, error) {
	tenantID, status = shared.TenantOrDefault(tenantID), strings.TrimSpace(status)
	if status == "" {
		status = StatusOpen
	}
	if !validStatus(status) {
		return nil, fmt.Errorf("%w: relationship candidate status is invalid", shared.ErrValidation)
	}
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return nil, fmt.Errorf("%w: relationship candidate limit is invalid", shared.ErrValidation)
	}
	records, err := service.store.ListCandidates(ctx, tenantID, ports.AssessmentRelationshipCandidateFilter{Limit: MaxLimit})
	if err != nil {
		return nil, err
	}
	now := service.clock.Now().UTC()
	views := make([]View, 0, limit)
	for _, record := range records {
		view := project(record, now)
		if status != "all" && view.Status != status {
			continue
		}
		views = append(views, view)
		if len(views) == limit {
			break
		}
	}
	return views, nil
}

func (service *Service) loadSubject(ctx context.Context, tenantID, cycleID shared.ID) (*cycledom.AssessmentCycle, cycledom.Member, *snapshotdom.Snapshot, error) {
	cycle, err := service.cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		return nil, cycledom.Member{}, nil, err
	}
	members, err := service.cycles.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		return nil, cycledom.Member{}, nil, err
	}
	if len(members) != 1 || !members[0].IsRoot() || members[0].IsArchived() || cycle.RootAssessmentID != members[0].AssessmentID {
		return nil, cycledom.Member{}, nil, fmt.Errorf("%w: relationship review requires two singleton cycles", shared.ErrValidation)
	}
	snapshot, err := service.selectSnapshot(ctx, tenantID, members[0].AssessmentID)
	if err != nil {
		return nil, cycledom.Member{}, nil, err
	}
	if snapshot.CycleID != cycle.ID || snapshot.AssessmentID != members[0].AssessmentID || snapshot.Lifecycle != snapshotdom.LifecycleFinalized {
		return nil, cycledom.Member{}, nil, fmt.Errorf("%w: relationship candidate snapshot ownership is invalid", shared.ErrValidation)
	}
	return cycle, members[0], snapshot, nil
}

func (service *Service) selectSnapshot(ctx context.Context, tenantID, assessmentID shared.ID) (*snapshotdom.Snapshot, error) {
	if snapshot, _, err := service.snapshots.GetDefault(ctx, tenantID, assessmentID); err == nil {
		return snapshot, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, err
	}
	items, err := service.snapshots.ListByAssessment(ctx, tenantID, assessmentID)
	if err != nil {
		return nil, err
	}
	for index := len(items) - 1; index >= 0; index-- {
		if items[index].Lifecycle == snapshotdom.LifecycleFinalized {
			item := items[index]
			return &item, nil
		}
	}
	return nil, fmt.Errorf("relationship candidate snapshot: %w", shared.ErrNotFound)
}

func exactBoundaryHash(predecessor, successor *cycledom.AssessmentCycle) (string, error) {
	if predecessor.BoundaryKind != successor.BoundaryKind || predecessor.BusinessAssetID != successor.BusinessAssetID || predecessor.ProjectID != successor.ProjectID {
		return "", fmt.Errorf("%w: candidate cycles do not share the exact frozen boundary", shared.ErrValidation)
	}
	return hashJSON(struct {
		Kind            cycledom.BoundaryKind `json:"kind"`
		BusinessAssetID shared.ID             `json:"business_asset_id,omitempty"`
		ProjectID       shared.ID             `json:"project_id,omitempty"`
	}{predecessor.BoundaryKind, predecessor.BusinessAssetID, predecessor.ProjectID}), nil
}

func compatibleManifestSignal(predecessor, successor *snapshotdom.Snapshot) (domain.Signal, bool) {
	if predecessor.Provenance != snapshotdom.ProvenanceNative || successor.Provenance != snapshotdom.ProvenanceNative {
		return domain.Signal{}, false
	}
	left, right := manifestKeys(predecessor), manifestKeys(successor)
	var matches []string
	for key := range left {
		if right[key] {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return domain.Signal{}, false
	}
	sort.Strings(matches)
	return domain.Signal{Kind: domain.SignalTrustedManifest, EvidenceHash: hashJSON(matches), MatchCount: len(matches), ScoreMilli: 1000, SchemaVersion: domain.SchemaVersion}, true
}

func manifestKeys(snapshot *snapshotdom.Snapshot) map[string]bool {
	keys := make(map[string]bool, len(snapshot.Dimensions))
	for _, dimension := range snapshot.Dimensions {
		included := append([]string(nil), dimension.IncludedScope...)
		excluded := append([]string(nil), dimension.ExcludedScope...)
		versions := append([]snapshotdom.Version(nil), dimension.Versions...)
		sort.Strings(included)
		sort.Strings(excluded)
		sort.Slice(versions, func(left, right int) bool {
			return strings.Join([]string{string(versions[left].Kind), versions[left].Name, versions[left].Version, versions[left].Digest}, "\x00") < strings.Join([]string{string(versions[right].Kind), versions[right].Name, versions[right].Version, versions[right].Digest}, "\x00")
		})
		keys[hashJSON(struct {
			Producer      string                `json:"producer"`
			FindingKind   string                `json:"finding_kind"`
			Target        snapshotdom.Target    `json:"target"`
			IncludedScope []string              `json:"included_scope"`
			ExcludedScope []string              `json:"excluded_scope"`
			Versions      []snapshotdom.Version `json:"versions"`
		}{dimension.Producer, dimension.FindingKind, dimension.Target, included, excluded, versions})] = true
	}
	return keys
}

func (service *Service) overlapSignal(ctx context.Context, tenantID shared.ID, predecessor, successor *snapshotdom.Snapshot) (domain.Signal, bool, error) {
	left, err := service.fingerprintSet(ctx, tenantID, predecessor)
	if err != nil {
		return domain.Signal{}, false, err
	}
	right, err := service.fingerprintSet(ctx, tenantID, successor)
	if err != nil {
		return domain.Signal{}, false, err
	}
	if len(left) == 0 || len(right) == 0 {
		return domain.Signal{}, false, nil
	}
	var matches []string
	for key := range left {
		if right[key] {
			matches = append(matches, key)
		}
	}
	minimum := len(left)
	if len(right) < minimum {
		minimum = len(right)
	}
	score := len(matches) * 1000 / minimum
	if len(matches) < 2 || score < 800 {
		return domain.Signal{}, false, nil
	}
	sort.Strings(matches)
	return domain.Signal{Kind: domain.SignalDeterministicOverlap, EvidenceHash: hashJSON(matches), MatchCount: len(matches), ScoreMilli: score, SchemaVersion: domain.SchemaVersion}, true, nil
}

func (service *Service) fingerprintSet(ctx context.Context, tenantID shared.ID, snapshot *snapshotdom.Snapshot) (map[string]bool, error) {
	observations, err := service.lineage.ListObservationsBySnapshot(ctx, tenantID, snapshot.CycleID, snapshot.ID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(observations))
	for _, observation := range observations {
		identity, err := service.lineage.GetIdentity(ctx, tenantID, snapshot.CycleID, observation.IdentityID)
		if err != nil {
			return nil, err
		}
		set[strings.Join([]string{identity.ProducerKind, identity.FindingKind, identity.TargetIdentityCanonical, identity.LineageFingerprint}, "\x00")] = true
	}
	return set, nil
}

func (service *Service) buildRepairPlan(candidate domain.Candidate, actor string, now time.Time) (domain.RepairPlan, error) {
	body, err := json.Marshal(struct {
		SchemaVersion int       `json:"schema_version"`
		Command       string    `json:"command"`
		Execution     string    `json:"execution"`
		Requires      string    `json:"requires"`
		CandidateID   shared.ID `json:"candidate_id"`
		InputHash     string    `json:"input_hash"`
		Predecessor   struct {
			CycleID             shared.ID `json:"cycle_id"`
			AssessmentID        shared.ID `json:"assessment_id"`
			RelationshipVersion int64     `json:"relationship_version"`
		} `json:"predecessor"`
		Successor struct {
			CycleID             shared.ID `json:"cycle_id"`
			AssessmentID        shared.ID `json:"assessment_id"`
			RelationshipVersion int64     `json:"relationship_version"`
		} `json:"successor"`
	}{
		SchemaVersion: domain.SchemaVersion, Command: "assessment_cycle.merge_legacy_relationship",
		Execution: "blocked", Requires: "separately_approved_move_merge_command",
		CandidateID: candidate.ID, InputHash: candidate.InputHash,
		Predecessor: struct {
			CycleID             shared.ID `json:"cycle_id"`
			AssessmentID        shared.ID `json:"assessment_id"`
			RelationshipVersion int64     `json:"relationship_version"`
		}{candidate.PredecessorCycleID, candidate.PredecessorAssessmentID, candidate.PredecessorRelationshipVersion},
		Successor: struct {
			CycleID             shared.ID `json:"cycle_id"`
			AssessmentID        shared.ID `json:"assessment_id"`
			RelationshipVersion int64     `json:"relationship_version"`
		}{candidate.SuccessorCycleID, candidate.SuccessorAssessmentID, candidate.SuccessorRelationshipVersion},
	})
	if err != nil {
		return domain.RepairPlan{}, fmt.Errorf("marshal relationship repair plan: %w", err)
	}
	return domain.NewRepairPlan(domain.RepairPlan{TenantID: candidate.TenantID, ID: service.ids.NewID(), CandidateID: candidate.ID, InputHash: candidate.InputHash, Body: body, CreatedBy: actor, CreatedAt: now})
}

type DecisionView struct {
	ID        shared.ID             `json:"id"`
	Action    domain.DecisionAction `json:"action"`
	Actor     string                `json:"actor"`
	Reason    string                `json:"reason"`
	Version   int64                 `json:"version"`
	CreatedAt time.Time             `json:"created_at"`
}

type RepairPlanView struct {
	ID        shared.ID       `json:"id"`
	InputHash string          `json:"input_hash"`
	PlanHash  string          `json:"plan_hash"`
	Body      json.RawMessage `json:"body"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
}

type View struct {
	ID                             shared.ID         `json:"id"`
	PredecessorCycleID             shared.ID         `json:"predecessor_cycle_id"`
	PredecessorAssessmentID        shared.ID         `json:"predecessor_assessment_id"`
	PredecessorRelationshipVersion int64             `json:"predecessor_relationship_version"`
	PredecessorSnapshotID          shared.ID         `json:"predecessor_snapshot_id"`
	SuccessorCycleID               shared.ID         `json:"successor_cycle_id"`
	SuccessorAssessmentID          shared.ID         `json:"successor_assessment_id"`
	SuccessorRelationshipVersion   int64             `json:"successor_relationship_version"`
	SuccessorSnapshotID            shared.ID         `json:"successor_snapshot_id"`
	BoundaryKeyHash                string            `json:"boundary_key_hash"`
	Signals                        []domain.Signal   `json:"signals"`
	InputHash                      string            `json:"input_hash"`
	Confidence                     domain.Confidence `json:"confidence"`
	Status                         string            `json:"status"`
	Version                        int64             `json:"version"`
	ExpiresAt                      time.Time         `json:"expires_at"`
	CreatedBy                      string            `json:"created_by"`
	CreatedAt                      time.Time         `json:"created_at"`
	Decision                       *DecisionView     `json:"decision,omitempty"`
	RepairPlan                     *RepairPlanView   `json:"repair_plan,omitempty"`
}

func project(record domain.Record, now time.Time) View {
	candidate := record.Candidate
	view := View{
		ID: candidate.ID, PredecessorCycleID: candidate.PredecessorCycleID, PredecessorAssessmentID: candidate.PredecessorAssessmentID,
		PredecessorRelationshipVersion: candidate.PredecessorRelationshipVersion, PredecessorSnapshotID: candidate.PredecessorSnapshotID,
		SuccessorCycleID: candidate.SuccessorCycleID, SuccessorAssessmentID: candidate.SuccessorAssessmentID,
		SuccessorRelationshipVersion: candidate.SuccessorRelationshipVersion, SuccessorSnapshotID: candidate.SuccessorSnapshotID,
		BoundaryKeyHash: candidate.BoundaryKeyHash, Signals: append([]domain.Signal(nil), candidate.Signals...), InputHash: candidate.InputHash,
		Confidence: candidate.Confidence, Status: StatusOpen, Version: 1, ExpiresAt: candidate.ExpiresAt,
		CreatedBy: candidate.CreatedBy, CreatedAt: candidate.CreatedAt,
	}
	if record.Decision == nil {
		if !candidate.ExpiresAt.After(now) {
			view.Status = StatusExpired
		}
		return view
	}
	view.Status, view.Version = decisionStatus(record.Decision.Action), record.Decision.Version
	view.Decision = &DecisionView{ID: record.Decision.ID, Action: record.Decision.Action, Actor: record.Decision.Actor, Reason: record.Decision.Reason, Version: record.Decision.Version, CreatedAt: record.Decision.CreatedAt}
	if record.Plan != nil {
		view.RepairPlan = &RepairPlanView{ID: record.Plan.ID, InputHash: record.Plan.InputHash, PlanHash: record.Plan.PlanHash, Body: append(json.RawMessage(nil), record.Plan.Body...), CreatedBy: record.Plan.CreatedBy, CreatedAt: record.Plan.CreatedAt}
	}
	return view
}

func decisionStatus(action domain.DecisionAction) string {
	switch action {
	case domain.DecisionConfirm:
		return StatusConfirmed
	case domain.DecisionReject:
		return StatusRejected
	case domain.DecisionDismiss:
		return StatusDismissed
	default:
		return "unknown"
	}
}

func validStatus(status string) bool {
	return status == "all" || status == StatusOpen || status == StatusConfirmed || status == StatusRejected || status == StatusDismissed || status == StatusExpired
}

func sensitiveReason(reason string) bool {
	if redact.URLCreds(reason) != reason {
		return true
	}
	lower := strings.ToLower(reason)
	for _, marker := range []string{"-----begin private key-----", "authorization: bearer ", "authorization: basic ", "password=", "passwd=", "secret=", "client_secret=", "api_key=", "api-key=", "access_token=", "token="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func hashJSON(value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
