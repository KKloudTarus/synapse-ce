package assessmentcomparison

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	DefaultMaxAttempts = 3
	MaxAttempts        = 10
	RiskModelVersionV1 = 1
)

var errGenerationInputChanged = errors.New("comparison generation input changed")

type Service struct {
	comparisons  ports.AssessmentComparisonRepository
	snapshots    ports.AssessmentSnapshotRepository
	cycles       ports.AssessmentCycleRepository
	lineage      ports.FindingLineageRepository
	transactions ports.TenantTransactionRunner
	audit        ports.AuditLogger
	clock        ports.Clock
	ids          ports.IDGenerator
	verification ports.AssessmentComparisonVerificationReader
	observer     ports.AssessmentComparisonObserver
	requests     ports.AssessmentCycleRequestStore
	jobs         ports.JobQueue
	reviewer     *lineageuc.Service
}

func NewService(
	comparisons ports.AssessmentComparisonRepository,
	snapshots ports.AssessmentSnapshotRepository,
	cycles ports.AssessmentCycleRepository,
	lineage ports.FindingLineageRepository,
	transactions ports.TenantTransactionRunner,
	audit ports.AuditLogger,
	clock ports.Clock,
	ids ports.IDGenerator,
	verification ports.AssessmentComparisonVerificationReader,
	observer ports.AssessmentComparisonObserver,
) (*Service, error) {
	if comparisons == nil || snapshots == nil || cycles == nil || lineage == nil || transactions == nil || audit == nil || clock == nil || ids == nil || verification == nil {
		return nil, fmt.Errorf("%w: assessment comparison dependencies are required", shared.ErrValidation)
	}
	if observer == nil {
		observer = noopObserver{}
	}
	return &Service{
		comparisons: comparisons, snapshots: snapshots, cycles: cycles, lineage: lineage,
		transactions: transactions, audit: audit, clock: clock, ids: ids,
		verification: verification, observer: observer,
	}, nil
}

func (service *Service) SetAPIStores(requests ports.AssessmentCycleRequestStore, jobs ports.JobQueue, reviewer *lineageuc.Service) {
	service.requests, service.jobs, service.reviewer = requests, jobs, reviewer
}

func (service *Service) SetObserver(observer ports.AssessmentComparisonObserver) {
	if observer == nil {
		observer = noopObserver{}
	}
	service.observer = observer
}

type QueueInput struct {
	TenantID           shared.ID
	BaselineSnapshotID shared.ID
	CurrentSnapshotID  shared.ID
	Mode               assessmentcomparison.Mode
	FingerprintVersion int
	RiskModelVersion   int
	Actor              string
}

func (service *Service) Queue(ctx context.Context, input QueueInput) (assessmentcomparison.Comparison, bool, assessmentcomparison.PairDecision, error) {
	if err := validateQueueInput(&input); err != nil {
		return assessmentcomparison.Comparison{}, false, assessmentcomparison.PairDecision{}, err
	}
	defer service.observeBacklog(context.WithoutCancel(ctx), input.TenantID)
	var stored assessmentcomparison.Comparison
	var created bool
	var decision assessmentcomparison.PairDecision
	err := service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		prepared, err := service.prepare(txCtx, input.TenantID, input.BaselineSnapshotID, input.CurrentSnapshotID, input.Mode, input.FingerprintVersion, input.RiskModelVersion)
		if err != nil {
			return err
		}
		decision = prepared.decision
		if !decision.Allowed {
			return service.audit.Record(txCtx, ports.AuditEntry{
				Actor: input.Actor, Action: "assessment_comparison.rejected", Target: input.CurrentSnapshotID.String(), At: service.clock.Now().UTC(),
				Metadata: map[string]string{"tenant_id": input.TenantID.String(), "mode": string(input.Mode), "reason": decision.ReasonCode},
			})
		}
		payload, inputHash, err := assessmentcomparison.HashGenerationInput(prepared.input)
		if err != nil {
			return err
		}
		candidate, err := assessmentcomparison.NewQueued(input.TenantID, prepared.baseline.CycleID, service.ids.NewID(), prepared.input, payload, inputHash, service.clock.Now().UTC())
		if err != nil {
			return err
		}
		stored, created, err = service.comparisons.CreateQueued(txCtx, candidate)
		if err != nil || !created {
			return err
		}
		if err := service.enqueueGeneration(txCtx, stored.ID); err != nil {
			return err
		}
		return service.recordAudit(txCtx, input.Actor, "assessment_comparison.queued", stored, map[string]string{"created": "true"})
	})
	if err != nil {
		return assessmentcomparison.Comparison{}, false, decision, err
	}
	if !decision.Allowed {
		service.observer.ObserveAssessmentComparison("rejected", string(input.Mode), decision.ReasonCode)
		return assessmentcomparison.Comparison{}, false, decision, nil
	}
	if created {
		service.observer.ObserveAssessmentComparison("queued", string(input.Mode), "created")
	} else {
		service.observer.ObserveAssessmentComparison("queued", string(input.Mode), "replayed")
	}
	return stored, created, decision, nil
}

type WorkInput struct {
	TenantID     shared.ID
	ComparisonID shared.ID
	Actor        string
	MaxAttempts  int
}

func (service *Service) Generate(ctx context.Context, input WorkInput) (assessmentcomparison.Comparison, error) {
	return service.generate(ctx, input, false)
}

func (service *Service) Repair(ctx context.Context, input WorkInput) (assessmentcomparison.Comparison, error) {
	return service.generate(ctx, input, true)
}

func (service *Service) generate(ctx context.Context, input WorkInput, repair bool) (assessmentcomparison.Comparison, error) {
	if err := validateWorkInput(&input); err != nil {
		return assessmentcomparison.Comparison{}, err
	}
	defer service.observeBacklog(context.WithoutCancel(ctx), input.TenantID)
	startedAt := time.Now()
	generatedItems := 0
	generationStatus := "failed"
	generationMode := ""
	fingerprintVersion := 0
	riskModelVersion := 0
	measureGeneration := false
	defer func() {
		observer, ok := service.observer.(ports.AssessmentComparisonGenerationObserver)
		if measureGeneration && ok {
			observer.ObserveAssessmentComparisonGeneration(input.TenantID.String(), generationMode, generationStatus, fingerprintVersion, riskModelVersion, generatedItems, time.Since(startedAt))
		}
	}()
	comparison, terminal, err := service.start(ctx, input, repair)
	if err != nil || terminal {
		return comparison, err
	}
	measureGeneration = true
	generationMode, fingerprintVersion, riskModelVersion = string(comparison.Mode), comparison.FingerprintVersion, comparison.RiskModelVersion
	prepared, err := service.prepare(ctx, input.TenantID, comparison.BaselineSnapshotID, comparison.CurrentSnapshotID, comparison.Mode, comparison.FingerprintVersion, comparison.RiskModelVersion)
	if err != nil {
		return assessmentcomparison.Comparison{}, service.failGeneration(ctx, input, comparison, err)
	}
	if !prepared.decision.Allowed {
		return assessmentcomparison.Comparison{}, service.failGeneration(ctx, input, comparison, errGenerationInputChanged)
	}
	_, inputHash, err := assessmentcomparison.HashGenerationInput(prepared.input)
	if err != nil || inputHash != comparison.InputHash {
		if err == nil {
			err = errGenerationInputChanged
		}
		return assessmentcomparison.Comparison{}, service.failGeneration(ctx, input, comparison, err)
	}
	items, err := service.buildItems(ctx, prepared)
	if err != nil {
		return assessmentcomparison.Comparison{}, service.failGeneration(ctx, input, comparison, err)
	}
	generatedItems = len(items)

	var completed assessmentcomparison.Comparison
	err = service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		current, err := service.comparisons.Get(txCtx, input.TenantID, input.ComparisonID)
		if err != nil {
			return err
		}
		if isTerminal(current.Status) {
			completed = current
			return nil
		}
		if current.Status != assessmentcomparison.StatusGenerating {
			return fmt.Errorf("%w: comparison is no longer generating", shared.ErrConflict)
		}
		latest, err := service.prepare(txCtx, input.TenantID, current.BaselineSnapshotID, current.CurrentSnapshotID, current.Mode, current.FingerprintVersion, current.RiskModelVersion)
		if err != nil {
			return err
		}
		if !latest.decision.Allowed {
			return errGenerationInputChanged
		}
		_, latestHash, err := assessmentcomparison.HashGenerationInput(latest.input)
		if err != nil {
			return err
		}
		if latestHash != current.InputHash {
			return errGenerationInputChanged
		}
		if err := current.Complete(items, current.Version, service.clock.Now().UTC()); err != nil {
			return err
		}
		if err := service.comparisons.UpdateCAS(txCtx, current, current.Version-1); err != nil {
			return err
		}
		if err := service.recordAudit(txCtx, input.Actor, "assessment_comparison.completed", current, map[string]string{"status": string(current.Status), "items": fmt.Sprintf("%d", len(current.Items))}); err != nil {
			return err
		}
		completed = current
		return nil
	})
	if errors.Is(err, errGenerationInputChanged) {
		return assessmentcomparison.Comparison{}, service.failGeneration(ctx, input, comparison, err)
	}
	if err != nil {
		if errors.Is(err, shared.ErrConflict) {
			retained, getErr := service.comparisons.Get(context.WithoutCancel(ctx), input.TenantID, input.ComparisonID)
			if getErr == nil && isTerminal(retained.Status) {
				return retained, nil
			}
		}
		return assessmentcomparison.Comparison{}, err
	}
	service.observer.ObserveAssessmentComparison(string(completed.Status), string(completed.Mode), "generated")
	generationStatus = string(completed.Status)
	return completed, nil
}

func (service *Service) start(ctx context.Context, input WorkInput, repair bool) (assessmentcomparison.Comparison, bool, error) {
	var comparison assessmentcomparison.Comparison
	err := service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		loaded, err := service.comparisons.Get(txCtx, input.TenantID, input.ComparisonID)
		if err != nil {
			return err
		}
		comparison = loaded
		if isTerminal(loaded.Status) {
			return nil
		}
		if repair && loaded.Status != assessmentcomparison.StatusFailed {
			return fmt.Errorf("%w: only a failed comparison can be repaired", shared.ErrValidation)
		}
		if loaded.Status == assessmentcomparison.StatusGenerating {
			return nil
		}
		if loaded.Status == assessmentcomparison.StatusFailed && loaded.Attempts >= input.MaxAttempts && !repair {
			return fmt.Errorf("%w: comparison is in dead letter after %d attempts", shared.ErrConflict, loaded.Attempts)
		}
		if err := loaded.Start(loaded.Version, service.clock.Now().UTC()); err != nil {
			return err
		}
		if err := service.comparisons.UpdateCAS(txCtx, loaded, loaded.Version-1); err != nil {
			return err
		}
		action := "assessment_comparison.started"
		if repair {
			action = "assessment_comparison.repaired"
		}
		if err := service.recordAudit(txCtx, input.Actor, action, loaded, map[string]string{"attempt": fmt.Sprintf("%d", loaded.Attempts)}); err != nil {
			return err
		}
		comparison = loaded
		return nil
	})
	return comparison, isTerminal(comparison.Status), err
}

func (service *Service) Recover(ctx context.Context, input WorkInput) (assessmentcomparison.Comparison, error) {
	if err := validateWorkInput(&input); err != nil {
		return assessmentcomparison.Comparison{}, err
	}
	var recovered assessmentcomparison.Comparison
	err := service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		current, err := service.comparisons.Get(txCtx, input.TenantID, input.ComparisonID)
		if err != nil {
			return err
		}
		if current.Status != assessmentcomparison.StatusGenerating {
			return fmt.Errorf("%w: only a generating comparison can be recovered", shared.ErrValidation)
		}
		if err := current.Fail("worker_recovered", true, input.MaxAttempts, current.Version, service.clock.Now().UTC()); err != nil {
			return err
		}
		if err := service.comparisons.UpdateCAS(txCtx, current, current.Version-1); err != nil {
			return err
		}
		if err := service.recordAudit(txCtx, input.Actor, "assessment_comparison.recovered", current, map[string]string{"status": string(current.Status)}); err != nil {
			return err
		}
		recovered = current
		return nil
	})
	if err == nil {
		service.observer.ObserveAssessmentComparison(string(recovered.Status), string(recovered.Mode), "worker_recovered")
	}
	return recovered, err
}

type ReplaceInput struct {
	TenantID     shared.ID
	ComparisonID shared.ID
	Actor        string
}

func (service *Service) Replace(ctx context.Context, input ReplaceInput) (assessmentcomparison.Comparison, bool, error) {
	input.Actor = strings.TrimSpace(input.Actor)
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	if input.ComparisonID.IsZero() || !validActor(input.Actor) {
		return assessmentcomparison.Comparison{}, false, fmt.Errorf("%w: comparison replacement identity and actor are required", shared.ErrValidation)
	}
	var replacement assessmentcomparison.Comparison
	var replaced bool
	err := service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		current, err := service.comparisons.Get(txCtx, input.TenantID, input.ComparisonID)
		if err != nil {
			return err
		}
		if current.Status == assessmentcomparison.StatusSuperseded {
			replacement, err = service.comparisons.Get(txCtx, input.TenantID, current.SupersededBy)
			return err
		}
		if current.Status != assessmentcomparison.StatusComplete && current.Status != assessmentcomparison.StatusNeedsReview {
			return fmt.Errorf("%w: only a completed comparison can be replaced", shared.ErrValidation)
		}
		prepared, err := service.prepare(txCtx, input.TenantID, current.BaselineSnapshotID, current.CurrentSnapshotID, current.Mode, current.FingerprintVersion, current.RiskModelVersion)
		if err != nil {
			return err
		}
		if !prepared.decision.Allowed {
			return fmt.Errorf("%w: replacement pair is invalid: %s", shared.ErrConflict, prepared.decision.ReasonCode)
		}
		payload, inputHash, err := assessmentcomparison.HashGenerationInput(prepared.input)
		if err != nil {
			return err
		}
		if inputHash == current.InputHash {
			replacement = current
			return nil
		}
		candidate, err := assessmentcomparison.NewQueued(input.TenantID, current.CycleID, service.ids.NewID(), prepared.input, payload, inputHash, service.clock.Now().UTC())
		if err != nil {
			return err
		}
		var created bool
		replacement, created, err = service.comparisons.CreateQueued(txCtx, candidate)
		if err != nil {
			return err
		}
		if created {
			if err := service.enqueueGeneration(txCtx, replacement.ID); err != nil {
				return err
			}
		}
		if err := current.Supersede(replacement.ID, current.Version, service.clock.Now().UTC()); err != nil {
			return err
		}
		if err := service.comparisons.UpdateCAS(txCtx, current, current.Version-1); err != nil {
			return err
		}
		if err := service.recordAudit(txCtx, input.Actor, "assessment_comparison.superseded", current, map[string]string{"successor_id": replacement.ID.String()}); err != nil {
			return err
		}
		replaced = true
		return nil
	})
	if err == nil && replaced {
		service.observer.ObserveAssessmentComparison("superseded", string(replacement.Mode), "input_changed")
	}
	return replacement, replaced, err
}

type preparedProjection struct {
	decision      assessmentcomparison.PairDecision
	baseline      *assessmentsnapshot.Snapshot
	current       *assessmentsnapshot.Snapshot
	members       []assessmentcycle.Member
	snapshots     []*assessmentsnapshot.Snapshot
	overrides     map[shared.ID][]findinglineage.OverrideEvent
	candidates    map[shared.ID][]findinglineage.MatchCandidate
	verifications []ports.AssessmentComparisonVerification
	input         assessmentcomparison.GenerationInput
}

func (service *Service) prepare(ctx context.Context, tenantID, baselineID, currentID shared.ID, mode assessmentcomparison.Mode, fingerprintVersion, riskModelVersion int) (preparedProjection, error) {
	if riskModelVersion != RiskModelVersionV1 || fingerprintVersion <= 0 {
		return preparedProjection{}, fmt.Errorf("%w: unsupported comparison fingerprint or risk model version", shared.ErrValidation)
	}
	baseline, err := service.snapshots.Get(ctx, tenantID, baselineID)
	if err != nil {
		return preparedProjection{}, err
	}
	current, err := service.snapshots.Get(ctx, tenantID, currentID)
	if err != nil {
		return preparedProjection{}, err
	}
	members, err := service.cycles.ListMembers(ctx, tenantID, baseline.CycleID)
	if err != nil {
		return preparedProjection{}, err
	}
	decision, err := assessmentcomparison.DecidePair(mode, baseline, current, members)
	if err != nil || !decision.Allowed {
		return preparedProjection{decision: decision, baseline: baseline, current: current, members: members}, err
	}
	relevantMembers, err := relevantMembers(members, baseline.AssessmentID, current.AssessmentID)
	if err != nil {
		return preparedProjection{}, err
	}
	relevantSnapshots, err := service.relevantSnapshots(ctx, tenantID, mode, baseline, current, relevantMembers)
	if err != nil {
		return preparedProjection{}, err
	}
	prepared := preparedProjection{
		decision: decision, baseline: baseline, current: current, members: relevantMembers, snapshots: relevantSnapshots,
		overrides: map[shared.ID][]findinglineage.OverrideEvent{}, candidates: map[shared.ID][]findinglineage.MatchCandidate{},
	}
	var overrideIDs, candidateIDs []shared.ID
	snapshotIDs := make([]shared.ID, 0, len(relevantSnapshots))
	for _, snapshot := range relevantSnapshots {
		snapshotIDs = append(snapshotIDs, snapshot.ID)
		overrides, err := service.lineage.ListActiveOverridesBySnapshot(ctx, tenantID, baseline.CycleID, snapshot.ID)
		if err != nil {
			return preparedProjection{}, err
		}
		candidates, err := service.lineage.ListOpenCandidatesBySnapshot(ctx, tenantID, baseline.CycleID, snapshot.ID)
		if err != nil {
			return preparedProjection{}, err
		}
		prepared.overrides[snapshot.ID], prepared.candidates[snapshot.ID] = overrides, candidates
		for _, override := range overrides {
			overrideIDs = append(overrideIDs, override.ID)
		}
		for _, candidate := range candidates {
			candidateIDs = append(candidateIDs, candidate.ID)
		}
	}
	prepared.verifications, err = service.verification.ListEffectiveComparisonVerifications(ctx, tenantID, baseline.CycleID, snapshotIDs)
	if err != nil {
		return preparedProjection{}, err
	}
	if err := validateVerifications(prepared.verifications, snapshotIDs); err != nil {
		return preparedProjection{}, err
	}
	history := make([]assessmentcomparison.SnapshotHashRef, 0, len(relevantSnapshots))
	if mode == assessmentcomparison.ModeLifecycle {
		for _, snapshot := range relevantSnapshots {
			if snapshot.ID != baseline.ID && snapshot.ID != current.ID {
				history = append(history, assessmentcomparison.SnapshotHashRef{ID: snapshot.ID, ContentHash: snapshot.ContentHash})
			}
		}
	}
	relationships := make([]assessmentcomparison.RelationshipRef, len(relevantMembers))
	for index, member := range relevantMembers {
		relationships[index] = assessmentcomparison.RelationshipRef{
			AssessmentID: member.AssessmentID, PredecessorID: member.PredecessorAssessmentID, RelationshipVersion: member.RelationshipVersion,
		}
	}
	verificationIDs := make([]shared.ID, len(prepared.verifications))
	for index, verification := range prepared.verifications {
		verificationIDs[index] = verification.ID
	}
	prepared.input = assessmentcomparison.GenerationInput{
		Mode:             mode,
		Baseline:         assessmentcomparison.SnapshotHashRef{ID: baseline.ID, ContentHash: baseline.ContentHash},
		Current:          assessmentcomparison.SnapshotHashRef{ID: current.ID, ContentHash: current.ContentHash},
		HistorySnapshots: history, Relationships: relationships,
		AlgorithmVersion: assessmentcomparison.AlgorithmVersionV1, FingerprintVersion: fingerprintVersion,
		RiskModelVersion: riskModelVersion, CoveragePolicyVersion: assessmentcomparison.CoveragePolicyVersionV1,
		ActiveOverrideIDs: overrideIDs, MatchCandidateIDs: candidateIDs, VerificationDecisionIDs: verificationIDs,
	}
	return prepared, nil
}

func (service *Service) relevantSnapshots(ctx context.Context, tenantID shared.ID, mode assessmentcomparison.Mode, baseline, current *assessmentsnapshot.Snapshot, members []assessmentcycle.Member) ([]*assessmentsnapshot.Snapshot, error) {
	if mode == assessmentcomparison.ModeNeutral {
		return []*assessmentsnapshot.Snapshot{baseline, current}, nil
	}
	path, err := pathToAssessment(members, current.AssessmentID)
	if err != nil {
		return nil, err
	}
	var snapshots []*assessmentsnapshot.Snapshot
	for _, member := range path {
		listed, err := service.snapshots.ListByAssessment(ctx, tenantID, member.AssessmentID)
		if err != nil {
			return nil, err
		}
		sort.Slice(listed, func(left, right int) bool {
			if listed[left].SnapshotNumber == listed[right].SnapshotNumber {
				return listed[left].ID < listed[right].ID
			}
			return listed[left].SnapshotNumber < listed[right].SnapshotNumber
		})
		for index := range listed {
			if member.AssessmentID == current.AssessmentID && listed[index].SnapshotNumber > current.SnapshotNumber {
				continue
			}
			copySnapshot := listed[index]
			snapshots = append(snapshots, &copySnapshot)
		}
	}
	baselinePosition, currentPosition := -1, -1
	for index, snapshot := range snapshots {
		if snapshot.ID == baseline.ID {
			baselinePosition = index
		}
		if snapshot.ID == current.ID {
			currentPosition = index
		}
	}
	if baselinePosition < 0 || currentPosition < 0 || baselinePosition >= currentPosition {
		return nil, fmt.Errorf("%w: lifecycle snapshots are absent from effective ancestry order", shared.ErrValidation)
	}
	return snapshots[:currentPosition+1], nil
}

type projectedSnapshot struct {
	snapshot     *assessmentsnapshot.Snapshot
	observations map[shared.ID][]findinglineage.Observation
	ambiguous    map[shared.ID]bool
	candidates   map[shared.ID][]shared.ID
	reviews      map[shared.ID][]assessmentcomparison.ReviewCandidateView
	methods      map[shared.ID][]findinglineage.MatchMethod
}

func (service *Service) buildItems(ctx context.Context, prepared preparedProjection) ([]assessmentcomparison.Item, error) {
	states := make(map[shared.ID]*projectedSnapshot, len(prepared.snapshots))
	observationIdentity := map[shared.ID]shared.ID{}
	for _, snapshot := range prepared.snapshots {
		observations, err := service.lineage.ListObservationsBySnapshot(ctx, prepared.baseline.TenantID, prepared.baseline.CycleID, snapshot.ID)
		if err != nil {
			return nil, err
		}
		overrides := map[shared.ID]findinglineage.OverrideEvent{}
		for _, event := range prepared.overrides[snapshot.ID] {
			overrides[event.SourceObservationID] = event
		}
		state := &projectedSnapshot{snapshot: snapshot, observations: map[shared.ID][]findinglineage.Observation{}, ambiguous: map[shared.ID]bool{}, candidates: map[shared.ID][]shared.ID{}, reviews: map[shared.ID][]assessmentcomparison.ReviewCandidateView{}, methods: map[shared.ID][]findinglineage.MatchMethod{}}
		for _, observation := range observations {
			identityID := observation.IdentityID
			if event, ok := overrides[observation.ID]; ok {
				identityID = event.TargetIdentityID
				delete(overrides, observation.ID)
			}
			state.observations[identityID] = append(state.observations[identityID], observation)
			observationIdentity[observation.ID] = identityID
		}
		if len(overrides) != 0 {
			return nil, fmt.Errorf("%w: active override source observation is absent from snapshot", shared.ErrValidation)
		}
		for identityID, observations := range state.observations {
			sort.Slice(observations, func(left, right int) bool { return observations[left].ID < observations[right].ID })
			state.observations[identityID] = observations
			if len(observations) > 1 {
				state.ambiguous[identityID] = true
			}
		}
		states[snapshot.ID] = state
	}
	for snapshotID, candidates := range prepared.candidates {
		state := states[snapshotID]
		for _, candidate := range candidates {
			sourceObservationIDs := make([]shared.ID, 0, len(candidate.Refs))
			for _, reference := range candidate.Refs {
				if reference.Role == findinglineage.RoleSource && !reference.ObservationID.IsZero() {
					sourceObservationIDs = append(sourceObservationIDs, reference.ObservationID)
				}
			}
			review := assessmentcomparison.ReviewCandidateView{ID: candidate.ID, SourceObservationIDs: sourceObservationIDs}
			for _, reference := range candidate.Refs {
				if !reference.IdentityID.IsZero() {
					state.ambiguous[reference.IdentityID] = true
					state.candidates[reference.IdentityID] = append(state.candidates[reference.IdentityID], candidate.ID)
					state.reviews[reference.IdentityID] = append(state.reviews[reference.IdentityID], review)
					state.methods[reference.IdentityID] = append(state.methods[reference.IdentityID], reference.Method)
				}
				if !reference.ObservationID.IsZero() {
					if identityID := observationIdentity[reference.ObservationID]; !identityID.IsZero() {
						state.ambiguous[identityID] = true
						state.candidates[identityID] = append(state.candidates[identityID], candidate.ID)
						state.reviews[identityID] = append(state.reviews[identityID], review)
						state.methods[identityID] = append(state.methods[identityID], reference.Method)
					}
				}
			}
		}
	}
	baselineState, currentState := states[prepared.baseline.ID], states[prepared.current.ID]
	identities := map[shared.ID]struct{}{}
	for identityID := range baselineState.observations {
		identities[identityID] = struct{}{}
	}
	for identityID := range currentState.observations {
		identities[identityID] = struct{}{}
	}
	orderedIDs := make([]shared.ID, 0, len(identities))
	for identityID := range identities {
		orderedIDs = append(orderedIDs, identityID)
	}
	sort.Slice(orderedIDs, func(left, right int) bool { return orderedIDs[left] < orderedIDs[right] })
	verificationByIdentity := make(map[shared.ID]ports.AssessmentComparisonVerification, len(prepared.verifications))
	verificationBySnapshot := make(map[shared.ID]map[shared.ID]ports.AssessmentComparisonVerification)
	for _, verification := range prepared.verifications {
		verificationByIdentity[verification.IdentityID] = verification
		if verificationBySnapshot[verification.EffectiveSnapshotID] == nil {
			verificationBySnapshot[verification.EffectiveSnapshotID] = map[shared.ID]ports.AssessmentComparisonVerification{}
		}
		verificationBySnapshot[verification.EffectiveSnapshotID][verification.IdentityID] = verification
	}
	coverage := newCoverageCache()
	items := make([]assessmentcomparison.Item, 0, len(orderedIDs))
	for _, identityID := range orderedIDs {
		baselineObservation := firstObservation(baselineState.observations[identityID])
		currentObservation := firstObservation(currentState.observations[identityID])
		verification := verificationByIdentity[identityID]
		classification := assessmentcomparison.ClassifyInput{
			IdentityID: identityID, Baseline: baselineObservation, Current: currentObservation,
			Ambiguous:      baselineState.ambiguous[identityID] || currentState.ambiguous[identityID],
			VerificationID: verification.ID, VerificationState: verification.State, VerificationRemediated: verification.Remediated,
			BaselineActionable: baselineObservation != nil, CurrentActionable: currentObservation != nil,
			BaselineRiskMilli: observationRisk(baselineObservation), CurrentRiskMilli: observationRisk(currentObservation),
		}
		if baselineObservation != nil && currentObservation == nil {
			classification.CurrentCoverage = coverage.compare(prepared.baseline, prepared.current, baselineObservation)
		}
		if baselineObservation == nil && currentObservation != nil && prepared.input.Mode == assessmentcomparison.ModeLifecycle {
			classification.History = buildHistory(identityID, prepared.current.ID, prepared.snapshots, states, verificationBySnapshot, coverage)
		}
		var item assessmentcomparison.Item
		var err error
		if prepared.input.Mode == assessmentcomparison.ModeLifecycle {
			item, err = assessmentcomparison.ClassifyLifecycle(classification)
		} else {
			item, err = assessmentcomparison.ClassifyNeutral(classification)
		}
		if err != nil {
			return nil, err
		}
		if baselineObservation != nil {
			item.CoverageDecision = coverage.compare(prepared.baseline, prepared.current, baselineObservation)
		}
		item.ReviewCandidateIDs = append(item.ReviewCandidateIDs, baselineState.candidates[identityID]...)
		item.ReviewCandidateIDs = append(item.ReviewCandidateIDs, currentState.candidates[identityID]...)
		item.ReviewCandidates = append(item.ReviewCandidates, baselineState.reviews[identityID]...)
		item.ReviewCandidates = append(item.ReviewCandidates, currentState.reviews[identityID]...)
		item.MatchMethods = canonicalMatchMethods(append(append([]findinglineage.MatchMethod(nil), baselineState.methods[identityID]...), currentState.methods[identityID]...))
		items = append(items, item)
	}
	return items, nil
}

func canonicalMatchMethods(methods []findinglineage.MatchMethod) []findinglineage.MatchMethod {
	seen := map[findinglineage.MatchMethod]struct{}{}
	result := make([]findinglineage.MatchMethod, 0, len(methods))
	for _, method := range methods {
		if !method.Valid() {
			continue
		}
		if _, duplicate := seen[method]; duplicate {
			continue
		}
		seen[method] = struct{}{}
		result = append(result, method)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func buildHistory(identityID, currentSnapshotID shared.ID, snapshots []*assessmentsnapshot.Snapshot, states map[shared.ID]*projectedSnapshot, verifications map[shared.ID]map[shared.ID]ports.AssessmentComparisonVerification, coverage *coverageCache) []assessmentcomparison.HistoryState {
	history := make([]assessmentcomparison.HistoryState, 0, len(snapshots))
	var lastObserved *findinglineage.Observation
	var lastObservedSnapshot *assessmentsnapshot.Snapshot
	for index, snapshot := range snapshots {
		if snapshot.ID == currentSnapshotID {
			break
		}
		state := states[snapshot.ID]
		observation := firstObservation(state.observations[identityID])
		historyState := assessmentcomparison.HistoryState{Order: int64(index + 1), Ambiguous: state.ambiguous[identityID]}
		if verification, ok := verifications[snapshot.ID][identityID]; ok {
			historyState.VerifiedRemediation = verification.Remediated
			historyState.VerificationDecision = verification.ID
		}
		if observation != nil {
			historyState.Observed = true
			lastObserved, lastObservedSnapshot = observation, snapshot
		} else if lastObserved != nil {
			historyState.ComparableAbsence = coverage.compare(lastObservedSnapshot, snapshot, lastObserved) == assessmentsnapshot.Comparable
		}
		history = append(history, historyState)
	}
	return history
}

type coverageCache struct {
	pairs map[string]map[string]assessmentsnapshot.Comparability
}

func newCoverageCache() *coverageCache {
	return &coverageCache{pairs: map[string]map[string]assessmentsnapshot.Comparability{}}
}

func (cache *coverageCache) compare(baseline, current *assessmentsnapshot.Snapshot, observation *findinglineage.Observation) assessmentsnapshot.Comparability {
	if baseline == nil || current == nil || observation == nil {
		return assessmentsnapshot.NotComparable
	}
	pairKey := baseline.ID.String() + "\x00" + current.ID.String()
	index, ok := cache.pairs[pairKey]
	if !ok {
		index = map[string]assessmentsnapshot.Comparability{}
		comparisons, err := assessmentsnapshot.Compare(baseline, current)
		if err != nil {
			return assessmentsnapshot.NotComparable
		}
		for _, comparison := range comparisons {
			key := comparisonDimensionKey(comparison.Baseline.Producer, comparison.Baseline.FindingKind, comparison.Baseline.Target.Canonical)
			if existing, exists := index[key]; !exists || comparabilityRank(comparison.Comparability) < comparabilityRank(existing) {
				index[key] = comparison.Comparability
			}
		}
		cache.pairs[pairKey] = index
	}
	comparability, exists := index[comparisonDimensionKey(observation.ProducerKind, observation.FindingKind, observation.TargetCanonical)]
	if !exists {
		return assessmentsnapshot.NotComparable
	}
	return comparability
}

func comparabilityRank(value assessmentsnapshot.Comparability) int {
	switch value {
	case assessmentsnapshot.Comparable:
		return 2
	case assessmentsnapshot.PartiallyComparable:
		return 1
	default:
		return 0
	}
}

func comparisonDimensionKey(producer, findingKind, target string) string {
	return strings.Join([]string{producer, findingKind, target}, "\x00")
}

func observationRisk(observation *findinglineage.Observation) int64 {
	if observation == nil {
		return 0
	}
	if observation.RiskScoreMilli != nil {
		return int64(*observation.RiskScoreMilli)
	}
	// ponytail: v1 treats every immutable observation as actionable and derives missing risk from severity;
	// add a versioned immutable actionability projection reader when workflow-policy IDs become part of #698 inputs.
	return int64(shared.SeverityRank(observation.Severity) * 2000)
}

func firstObservation(observations []findinglineage.Observation) *findinglineage.Observation {
	if len(observations) == 0 {
		return nil
	}
	return &observations[0]
}

func relevantMembers(members []assessmentcycle.Member, baselineAssessmentID, currentAssessmentID shared.ID) ([]assessmentcycle.Member, error) {
	baselinePath, err := pathToAssessment(members, baselineAssessmentID)
	if err != nil {
		return nil, err
	}
	currentPath, err := pathToAssessment(members, currentAssessmentID)
	if err != nil {
		return nil, err
	}
	byID := map[shared.ID]assessmentcycle.Member{}
	depth := map[shared.ID]int{}
	for _, path := range [][]assessmentcycle.Member{baselinePath, currentPath} {
		for index, member := range path {
			byID[member.AssessmentID] = member
			if current, exists := depth[member.AssessmentID]; !exists || index < current {
				depth[member.AssessmentID] = index
			}
		}
	}
	result := make([]assessmentcycle.Member, 0, len(byID))
	for _, member := range byID {
		result = append(result, member)
	}
	sort.Slice(result, func(left, right int) bool {
		leftDepth, rightDepth := depth[result[left].AssessmentID], depth[result[right].AssessmentID]
		if leftDepth == rightDepth {
			return result[left].AssessmentID < result[right].AssessmentID
		}
		return leftDepth < rightDepth
	})
	return result, nil
}

func pathToAssessment(members []assessmentcycle.Member, assessmentID shared.ID) ([]assessmentcycle.Member, error) {
	byID := make(map[shared.ID]assessmentcycle.Member, len(members))
	for _, member := range members {
		byID[member.AssessmentID] = member
	}
	current, exists := byID[assessmentID]
	if !exists {
		return nil, fmt.Errorf("%w: assessment %q is absent from cycle relationships", shared.ErrNotFound, assessmentID)
	}
	path := []assessmentcycle.Member{current}
	seen := map[shared.ID]struct{}{current.AssessmentID: {}}
	for !current.PredecessorAssessmentID.IsZero() {
		predecessor, exists := byID[current.PredecessorAssessmentID]
		if !exists {
			return nil, fmt.Errorf("%w: predecessor %q is absent from cycle relationships", shared.ErrNotFound, current.PredecessorAssessmentID)
		}
		if _, duplicate := seen[predecessor.AssessmentID]; duplicate {
			return nil, fmt.Errorf("%w: cycle relationship loop at %q", shared.ErrValidation, predecessor.AssessmentID)
		}
		seen[predecessor.AssessmentID] = struct{}{}
		path = append(path, predecessor)
		current = predecessor
	}
	for left, right := 0, len(path)-1; left < right; left, right = left+1, right-1 {
		path[left], path[right] = path[right], path[left]
	}
	return path, nil
}

func validateQueueInput(input *QueueInput) error {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	input.Actor = strings.TrimSpace(input.Actor)
	if input.BaselineSnapshotID.IsZero() || input.CurrentSnapshotID.IsZero() || !input.Mode.Valid() || input.FingerprintVersion <= 0 || input.RiskModelVersion != RiskModelVersionV1 || !validActor(input.Actor) {
		return fmt.Errorf("%w: comparison queue input is invalid", shared.ErrValidation)
	}
	return nil
}

func validateWorkInput(input *WorkInput) error {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	input.Actor = strings.TrimSpace(input.Actor)
	if input.MaxAttempts == 0 {
		input.MaxAttempts = DefaultMaxAttempts
	}
	if input.ComparisonID.IsZero() || !validActor(input.Actor) || input.MaxAttempts < 1 || input.MaxAttempts > MaxAttempts {
		return fmt.Errorf("%w: comparison work input is invalid", shared.ErrValidation)
	}
	return nil
}

func validateVerifications(verifications []ports.AssessmentComparisonVerification, snapshotIDs []shared.ID) error {
	allowedSnapshots := make(map[shared.ID]struct{}, len(snapshotIDs))
	for _, snapshotID := range snapshotIDs {
		allowedSnapshots[snapshotID] = struct{}{}
	}
	seenIDs := map[shared.ID]struct{}{}
	seenIdentities := map[shared.ID]struct{}{}
	for _, verification := range verifications {
		_, allowed := allowedSnapshots[verification.EffectiveSnapshotID]
		if verification.ID.IsZero() || verification.IdentityID.IsZero() || !allowed || !validToken(verification.State) {
			return fmt.Errorf("%w: effective comparison verification is invalid", shared.ErrValidation)
		}
		if _, duplicate := seenIDs[verification.ID]; duplicate {
			return fmt.Errorf("%w: effective comparison verification id is duplicated", shared.ErrValidation)
		}
		if _, duplicate := seenIdentities[verification.IdentityID]; duplicate {
			return fmt.Errorf("%w: multiple effective comparison verifications exist for one identity", shared.ErrConflict)
		}
		seenIDs[verification.ID], seenIdentities[verification.IdentityID] = struct{}{}, struct{}{}
	}
	return nil
}

func validActor(actor string) bool {
	return actor != "" && len(actor) <= 256
}

func validToken(value string) bool {
	if value == "" || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char != '_' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func (service *Service) failGeneration(ctx context.Context, input WorkInput, comparison assessmentcomparison.Comparison, cause error) error {
	code, retryable := generationFailure(cause)
	failCtx := context.WithoutCancel(ctx)
	err := service.transactions.Run(failCtx, input.TenantID, func(txCtx context.Context) error {
		current, err := service.comparisons.Get(txCtx, input.TenantID, input.ComparisonID)
		if err != nil {
			return err
		}
		if current.Status != assessmentcomparison.StatusGenerating {
			return nil
		}
		if err := current.Fail(code, retryable, input.MaxAttempts, current.Version, service.clock.Now().UTC()); err != nil {
			return err
		}
		if err := service.comparisons.UpdateCAS(txCtx, current, current.Version-1); err != nil {
			return err
		}
		return service.recordAudit(txCtx, input.Actor, "assessment_comparison.failed", current, map[string]string{"reason": code, "retryable": fmt.Sprintf("%t", retryable), "status": string(current.Status)})
	})
	service.observer.ObserveAssessmentComparison("failed", string(comparison.Mode), code)
	if err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func generationFailure(err error) (string, bool) {
	switch {
	case errors.Is(err, errGenerationInputChanged), errors.Is(err, shared.ErrConflict):
		return "input_changed", false
	case errors.Is(err, shared.ErrNotFound):
		return "input_missing", false
	case errors.Is(err, shared.ErrValidation):
		return "invalid_input", false
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "worker_cancelled", true
	default:
		return "generation_failed", true
	}
}

func (service *Service) recordAudit(ctx context.Context, actor, action string, comparison assessmentcomparison.Comparison, metadata map[string]string) error {
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata["tenant_id"] = comparison.TenantID.String()
	metadata["cycle_id"] = comparison.CycleID.String()
	metadata["mode"] = string(comparison.Mode)
	metadata["input_hash"] = comparison.InputHash
	return service.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: comparison.ID.String(), Metadata: metadata, At: service.clock.Now().UTC()})
}

func (service *Service) enqueueGeneration(ctx context.Context, comparisonID shared.ID) error {
	if service.jobs == nil {
		return nil
	}
	payload, err := json.Marshal(Job{ComparisonID: comparisonID})
	if err != nil {
		return err
	}
	_, err = service.jobs.Enqueue(ctx, JobKind, payload)
	return err
}

func (service *Service) observeBacklog(ctx context.Context, tenantID shared.ID) {
	reader, readable := service.comparisons.(ports.AssessmentComparisonBacklogReader)
	observer, observable := service.observer.(ports.AssessmentComparisonBacklogObserver)
	if !readable || !observable {
		return
	}
	metricCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	backlog, err := reader.GetAssessmentComparisonBacklog(metricCtx, tenantID)
	if err == nil {
		observer.ObserveAssessmentComparisonBacklog(tenantID.String(), backlog, service.clock.Now().UTC())
	}
}

func isTerminal(status assessmentcomparison.Status) bool {
	return status == assessmentcomparison.StatusComplete || status == assessmentcomparison.StatusNeedsReview || status == assessmentcomparison.StatusSuperseded
}

type noopObserver struct{}

func (noopObserver) ObserveAssessmentComparison(string, string, string) {}
