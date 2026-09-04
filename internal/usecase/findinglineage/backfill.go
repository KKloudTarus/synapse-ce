package findinglineage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	snapshotdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	lineagedom "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityoccurrence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	FindingLineageBackfillSchemaVersion = 1
	DefaultFindingLineageBackfillBatch  = 500
	MaxFindingLineageBackfillBatch      = 2000
	findingLineageBackfillRetries       = 3
	defaultFindingLineageBackfillLease  = 10 * time.Minute
)

const (
	BackfillOutcomeObservationCreated   = "observation_created"
	BackfillOutcomeProvisionalCandidate = "provisional_candidate_created"
	BackfillOutcomeSkipped              = "skipped"

	BackfillReasonInvalidOwnership           = "invalid_ownership_reference"
	BackfillReasonMissingSnapshot            = "snapshot_not_found"
	BackfillReasonMalformedTrustBoundary     = "malformed_trust_boundary"
	BackfillReasonProducerMatcherUnavailable = "producer_matcher_unavailable"
	BackfillReasonMissingTarget              = "missing_target_identity"
	BackfillReasonAmbiguousTarget            = "ambiguous_target_identity"
	BackfillReasonMissingTrustedJudgment     = "missing_trusted_judgment"
)

type FindingLineageBackfillObserver interface {
	ObserveFindingLineageBackfillItem(outcome string)
	ObserveFindingLineageBackfillRun(state string)
}

type lineageBackfillCorrelator interface {
	Correlate(context.Context, CorrelateInput) (Result, error)
	CorrelateNativeManual(context.Context, NativeManualInput) (Result, error)
}

type BackfillRunner struct {
	lineage     lineageBackfillCorrelator
	source      ports.FindingLineageBackfillSource
	store       ports.FindingLineageBackfillStore
	snapshots   ports.AssessmentSnapshotRepository
	occurrences ports.VulnerabilityOccurrenceStore
	judgments   ports.JudgmentStore
	ids         ports.IDGenerator
	clock       ports.Clock
	audit       ports.AuditLogger
	observer    FindingLineageBackfillObserver
	sca         SCAMatcherV1
	sast        SASTMatcherV1
	quality     QualityMatcherV1
	secret      SecretMatcherV1
	iac         IaCMatcherV1
}

func NewFindingLineageBackfillRunner(lineage lineageBackfillCorrelator, source ports.FindingLineageBackfillSource, store ports.FindingLineageBackfillStore, snapshots ports.AssessmentSnapshotRepository, occurrences ports.VulnerabilityOccurrenceStore, judgments ports.JudgmentStore, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger, observer FindingLineageBackfillObserver) (*BackfillRunner, error) {
	if lineage == nil || source == nil || store == nil || snapshots == nil || occurrences == nil || judgments == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: finding lineage backfill dependencies are required", shared.ErrValidation)
	}
	sca, err := NewSCAMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	sast, err := NewSASTMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	quality, err := NewQualityMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	secret, err := NewSecretMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	iac, err := NewIaCMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	return &BackfillRunner{
		lineage: lineage, source: source, store: store, snapshots: snapshots, occurrences: occurrences, judgments: judgments,
		ids: ids, clock: clock, audit: audit, observer: observer, sca: sca, sast: sast, quality: quality, secret: secret, iac: iac,
	}, nil
}

type FindingLineageBackfillRequest struct {
	TenantID       shared.ID
	Actor          string
	LeaseOwner     string
	DryRun         bool
	BatchSize      int
	ProducerFilter []string
	ResumeAfter    shared.ID
	LeaseDuration  time.Duration
}

func (runner *BackfillRunner) RunBackfill(ctx context.Context, request FindingLineageBackfillRequest) (ports.FindingLineageBackfillRun, error) {
	tenantID := shared.TenantOrDefault(request.TenantID)
	actor, leaseOwner := strings.TrimSpace(request.Actor), strings.TrimSpace(request.LeaseOwner)
	if tenantID.IsZero() || actor == "" || len(actor) > 256 || leaseOwner == "" || len(leaseOwner) > 256 {
		return ports.FindingLineageBackfillRun{}, fmt.Errorf("%w: tenant, actor, and lease owner are required", shared.ErrValidation)
	}
	batchSize := request.BatchSize
	if batchSize == 0 {
		batchSize = DefaultFindingLineageBackfillBatch
	}
	if batchSize < 1 || batchSize > MaxFindingLineageBackfillBatch {
		return ports.FindingLineageBackfillRun{}, fmt.Errorf("%w: batch size must be between 1 and %d", shared.ErrValidation, MaxFindingLineageBackfillBatch)
	}
	producerFilters, err := NormalizeFindingLineageProducerFilters(request.ProducerFilter)
	if err != nil {
		return ports.FindingLineageBackfillRun{}, err
	}
	leaseDuration := request.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultFindingLineageBackfillLease
	}
	now := runner.clock.Now().UTC()
	acquisitionID := runner.ids.NewID()
	run, resumed, err := runner.store.AcquireFindingLineageBackfillRun(ctx, ports.FindingLineageBackfillAcquireRequest{
		Run: ports.FindingLineageBackfillRun{
			TenantID: tenantID, ID: acquisitionID, SchemaVersion: FindingLineageBackfillSchemaVersion,
			DryRun: request.DryRun, BatchSize: batchSize, ProducerFilters: producerFilters, SnapshotAt: now,
			State: ports.FindingLineageBackfillRunning, LeaseOwner: leaseOwner, LeaseToken: acquisitionID, LeaseExpiresAt: now.Add(leaseDuration),
			CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		},
		InitialCheckpoint: request.ResumeAfter,
		LeaseDuration:     leaseDuration,
	})
	if err != nil {
		return ports.FindingLineageBackfillRun{}, err
	}
	ctx = shared.WithTenant(ctx, tenantID)
	runner.record(ctx, actor, "finding_lineage.backfill_started", run.ID, map[string]string{
		"tenant_id": tenantID.String(), "dry_run": strconv.FormatBool(run.DryRun), "resumed": strconv.FormatBool(resumed), "batch_size": strconv.Itoa(run.BatchSize),
	})
	cache := backfillCache{snapshots: map[shared.ID]*snapshotdom.Snapshot{}, occurrences: map[shared.ID]map[shared.ID]vulnerabilityoccurrence.Occurrence{}, judgments: map[shared.ID]map[shared.ID]judgment.Judgment{}}
	for {
		if err := ctx.Err(); err != nil {
			return runner.finishBackfill(ctx, run, leaseOwner, ports.FindingLineageBackfillCancelled, actor, err)
		}
		sources, err := runner.source.ListFindingLineageBackfillSources(ctx, tenantID, run.CheckpointFinding, run.SnapshotAt, run.ProducerFilters, run.BatchSize)
		if err != nil {
			return runner.finishBackfill(ctx, run, leaseOwner, findingLineageBackfillTerminalState(err), actor, err)
		}
		if len(sources) == 0 {
			return runner.finishBackfill(ctx, run, leaseOwner, ports.FindingLineageBackfillCompleted, actor, nil)
		}
		if len(sources) > run.BatchSize {
			return runner.finishBackfill(ctx, run, leaseOwner, ports.FindingLineageBackfillFailed, actor, fmt.Errorf("backfill source returned %d rows for limit %d", len(sources), run.BatchSize))
		}
		for _, source := range sources {
			if err := ctx.Err(); err != nil {
				return runner.finishBackfill(ctx, run, leaseOwner, ports.FindingLineageBackfillCancelled, actor, err)
			}
			if source.TenantID != tenantID || source.FindingID.IsZero() || source.AssessmentID.IsZero() {
				return runner.finishBackfill(ctx, run, leaseOwner, ports.FindingLineageBackfillFailed, actor, fmt.Errorf("%w: backfill source ownership is invalid", shared.ErrValidation))
			}
			if _, err := runner.store.GetFindingLineageBackfillItem(ctx, tenantID, run.ID, source.FindingID); err == nil {
				continue
			} else if !errors.Is(err, shared.ErrNotFound) {
				return runner.finishBackfill(ctx, run, leaseOwner, findingLineageBackfillTerminalState(err), actor, err)
			}
			item, created, err := runner.store.CommitFindingLineageBackfillItem(ctx, tenantID, run.ID, run.LeaseToken, runner.clock.Now().UTC(), func(txCtx context.Context) (ports.FindingLineageBackfillItem, error) {
				return runner.processFindingSource(txCtx, run, source, actor, &cache)
			})
			if err != nil {
				return runner.finishBackfill(ctx, run, leaseOwner, findingLineageBackfillTerminalState(err), actor, err)
			}
			if created && runner.observer != nil {
				runner.observer.ObserveFindingLineageBackfillItem(item.Outcome)
			}
		}
		checkpoint := sources[len(sources)-1].FindingID
		run, err = runner.store.AdvanceFindingLineageBackfillRun(ctx, tenantID, run.ID, leaseOwner, run.LeaseToken, checkpoint, runner.clock.Now().UTC(), leaseDuration)
		if err != nil {
			return runner.finishBackfill(ctx, run, leaseOwner, findingLineageBackfillTerminalState(err), actor, err)
		}
		runner.record(ctx, actor, "finding_lineage.backfill_batch_committed", run.ID, map[string]string{
			"tenant_id": tenantID.String(), "checkpoint_finding_id": checkpoint.String(), "processed_count": strconv.Itoa(run.ProcessedCount),
		})
	}
}

type backfillCache struct {
	snapshots   map[shared.ID]*snapshotdom.Snapshot
	occurrences map[shared.ID]map[shared.ID]vulnerabilityoccurrence.Occurrence
	judgments   map[shared.ID]map[shared.ID]judgment.Judgment
}

type preparedBackfill struct {
	correlate      *CorrelateInput
	manual         *NativeManualInput
	matcherVersion int
	reasonCode     string
	plannedOutcome string
}

func (runner *BackfillRunner) processFindingSource(ctx context.Context, run ports.FindingLineageBackfillRun, source ports.FindingLineageBackfillSourceRow, actor string, cache *backfillCache) (ports.FindingLineageBackfillItem, error) {
	item := ports.FindingLineageBackfillItem{
		TenantID: run.TenantID, RunID: run.ID, AssessmentID: source.AssessmentID, CycleID: source.CycleID,
		SnapshotID: source.SnapshotID, SourceFindingID: source.FindingID, SchemaVersion: run.SchemaVersion, ProcessedAt: runner.clock.Now().UTC(),
	}
	if !source.OwnershipValid || source.CycleID.IsZero() {
		item.MatcherVersion, item.Outcome, item.ReasonCode = 1, BackfillOutcomeSkipped, BackfillReasonInvalidOwnership
		finalizeFindingLineageBackfillItem(&item, source.SnapshotContentHash)
		return item, nil
	}
	if source.SnapshotID.IsZero() || source.SnapshotContentHash == "" {
		item.MatcherVersion, item.Outcome, item.ReasonCode = 1, BackfillOutcomeSkipped, BackfillReasonMissingSnapshot
		finalizeFindingLineageBackfillItem(&item, source.SnapshotContentHash)
		return item, nil
	}
	snapshot, err := runner.loadSnapshot(ctx, run.TenantID, source.SnapshotID, cache)
	if err != nil {
		return ports.FindingLineageBackfillItem{}, err
	}
	if snapshot.CycleID != source.CycleID || snapshot.AssessmentID != source.AssessmentID || snapshot.ContentHash != source.SnapshotContentHash {
		return ports.FindingLineageBackfillItem{}, fmt.Errorf("%w: source Snapshot ownership or content hash changed", shared.ErrConflict)
	}
	var prepared preparedBackfill
	for attempt := 0; attempt < findingLineageBackfillRetries; attempt++ {
		prepared, err = runner.prepareFinding(ctx, source, *snapshot, actor, cache)
		if err == nil || !retryableFindingLineageBackfillError(err) {
			break
		}
	}
	if err != nil {
		if retryableFindingLineageBackfillError(err) {
			return ports.FindingLineageBackfillItem{}, err
		}
		prepared = runner.prepareSkip(source, *snapshot, actor, BackfillReasonMalformedTrustBoundary, false, false)
	}
	item.MatcherVersion = prepared.matcherVersion
	finalizeFindingLineageBackfillItem(&item, source.SnapshotContentHash)
	if run.DryRun {
		item.Outcome, item.ReasonCode = prepared.plannedOutcome, prepared.reasonCode
		return item, nil
	}
	var result Result
	for attempt := 0; attempt < findingLineageBackfillRetries; attempt++ {
		if prepared.manual != nil {
			result, err = runner.lineage.CorrelateNativeManual(ctx, *prepared.manual)
		} else {
			result, err = runner.lineage.Correlate(ctx, *prepared.correlate)
		}
		if err == nil || !retryableFindingLineageBackfillError(err) {
			break
		}
	}
	if err != nil {
		return ports.FindingLineageBackfillItem{}, err
	}
	item.ReasonCode = prepared.reasonCode
	if item.ReasonCode == "" {
		item.ReasonCode = result.Reason
	}
	switch result.Outcome {
	case OutcomeCreated:
		item.Outcome = BackfillOutcomeObservationCreated
	case OutcomeMatched:
		item.Outcome = prepared.plannedOutcome
	case OutcomeReview:
		item.Outcome = BackfillOutcomeProvisionalCandidate
	case OutcomeSkipped:
		item.Outcome = BackfillOutcomeSkipped
	default:
		return ports.FindingLineageBackfillItem{}, fmt.Errorf("%w: unsupported lineage backfill result %q", shared.ErrValidation, result.Outcome)
	}
	return item, nil
}

func (runner *BackfillRunner) prepareFinding(ctx context.Context, source ports.FindingLineageBackfillSourceRow, snapshot snapshotdom.Snapshot, actor string, cache *backfillCache) (preparedBackfill, error) {
	producer, findingKind := legacyProducer(source.Kind)
	target := selectBackfillTarget(snapshot, producer, findingKind, source.AssessmentID)
	observation, err := backfillObservation(source, target)
	if err != nil {
		return preparedBackfill{}, err
	}
	base := CorrelateInput{
		TenantID: source.TenantID, CycleID: source.CycleID, SnapshotID: source.SnapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true, Observation: observation, Actor: actor,
	}
	var prepared preparedBackfill
	switch source.Kind {
	case "", finding.KindSCA:
		occurrence, occurrenceFound, occurrenceErr := runner.findOccurrence(ctx, source, cache)
		if occurrenceErr != nil {
			if errors.Is(occurrenceErr, shared.ErrNotFound) {
				return runner.prepareSkip(source, snapshot, actor, "invalid_source_reference", false, true), nil
			}
			return preparedBackfill{}, occurrenceErr
		}
		input := SCAFingerprintInputV1{TargetIdentityCanonical: target.canonical, AdvisoryID: source.AdvisoryID, DependencyInstanceID: source.ComponentFingerprint, LegacyDedupKey: source.DedupKey}
		if occurrenceFound {
			input.AdvisoryID, input.PackageEcosystem, input.PackageName = occurrence.AdvisoryID, occurrence.Ecosystem, occurrence.Package
			input.DependencyInstanceID = occurrence.ComponentFingerprint
			base.Observation.ComponentVersion = occurrence.ComponentVersion
		}
		plan, err := runner.sca.Build(input)
		if err != nil {
			return preparedBackfill{}, err
		}
		correlate := plan.Apply(base)
		prepared = preparedBackfill{correlate: &correlate, matcherVersion: SCAMatcherVersionV1, reasonCode: plan.ReasonCode}
	case finding.KindSAST:
		var judgmentAnchor *SASTAnchorV1
		if judgmentID := legacySASTJudgmentID(source.DedupKey); !judgmentID.IsZero() {
			current, found, err := runner.findJudgment(ctx, source.AssessmentID, judgmentID, cache)
			if err != nil {
				return preparedBackfill{}, err
			}
			if found {
				anchor, anchorErr := SASTJudgmentAnchorV1(source.AssessmentID, current)
				if anchorErr == nil {
					judgmentAnchor = &anchor
				}
			}
		}
		plan, err := runner.sast.Build(SASTFingerprintInputV1{
			TargetIdentityCanonical: target.canonical, RepoPath: sourcePath(source), RuleKey: source.RuleKey,
			LegacyDedupKey: source.DedupKey, LegacySourceValidated: true, LegacyOwnershipValid: true, JudgmentAnchor: judgmentAnchor,
		})
		if err != nil {
			return preparedBackfill{}, err
		}
		correlate := plan.Apply(base)
		prepared = preparedBackfill{correlate: &correlate, matcherVersion: SASTMatcherVersionV1, reasonCode: plan.ReasonCode}
		if !legacySASTJudgmentID(source.DedupKey).IsZero() && judgmentAnchor == nil {
			correlate.ReviewDetailCode = BackfillReasonMissingTrustedJudgment
			prepared.reasonCode = BackfillReasonMissingTrustedJudgment
		}
	case finding.KindQuality, finding.KindReliability:
		plan, err := runner.quality.Build(QualityFingerprintInputV1{
			TargetIdentityCanonical: target.canonical, FindingClass: string(source.Kind), RepoPath: sourcePath(source),
			RuleKey: source.RuleKey, LegacyDedupKey: source.DedupKey, LegacySourceValidated: true,
		})
		if err != nil {
			return preparedBackfill{}, err
		}
		correlate := plan.Apply(base)
		prepared = preparedBackfill{correlate: &correlate, matcherVersion: QualityMatcherVersionV1, reasonCode: plan.ReasonCode}
	case finding.KindSecret:
		if unsafeLegacySecretKey(source.DedupKey) {
			return preparedBackfill{}, ErrSecretMaterialRejected
		}
		redacted, err := RedactSecretProducerInputV1(SecretProducerInputV1{
			TargetIdentityCanonical: target.canonical, DetectorKey: source.RuleKey, RepoPath: sourcePath(source),
			LegacyDedupKey: source.DedupKey, LegacySourceValidated: true,
		})
		if err != nil {
			return preparedBackfill{}, err
		}
		plan, err := runner.secret.Build(redacted)
		if err != nil {
			return preparedBackfill{}, err
		}
		correlate := plan.Apply(base)
		prepared = preparedBackfill{correlate: &correlate, matcherVersion: SecretMatcherVersionV1, reasonCode: plan.ReasonCode}
	case finding.KindMisconfig:
		plan, err := runner.iac.Build(IaCFingerprintInputV1{
			TargetIdentityCanonical: target.canonical, RuleKey: source.RuleKey, RepoPath: sourcePath(source),
			LegacyDedupKey: source.DedupKey, LegacySourceValidated: true,
		})
		if err != nil {
			return preparedBackfill{}, err
		}
		correlate := plan.Apply(base)
		prepared = preparedBackfill{correlate: &correlate, matcherVersion: IaCMatcherVersionV1, reasonCode: plan.ReasonCode}
	case finding.KindManual, finding.KindRecon, finding.KindExploitation:
		class := ManualFindingNative
		if source.Kind != finding.KindManual {
			class = ManualFindingOffensive
		}
		if nativeManualSource(source) {
			manual := NativeManualInput{
				TenantID: source.TenantID, CycleID: source.CycleID, SnapshotID: source.SnapshotID, AssessmentID: source.AssessmentID,
				IdentityID: legacyManualIdentityID(source.FindingID), FindingClass: class, Observation: observation, Actor: actor,
			}
			prepared = preparedBackfill{manual: &manual, matcherVersion: ManualNativeFingerprintSchemaVersionV1, reasonCode: "manual_native_explicit_id", plannedOutcome: BackfillOutcomeObservationCreated}
			return prepared, nil
		}
		plan, err := BuildManualImportMatchPlanV1(ManualImportFingerprintInputV1{
			TargetIdentityCanonical: "assessment:" + source.AssessmentID.String(), AssessmentID: source.AssessmentID,
			FindingClass: class, ImporterNamespace: "legacy-finding", ImporterSchemaVersion: 1, SourceValidated: true, RedactionComplete: true,
		})
		if err != nil {
			return preparedBackfill{}, err
		}
		correlate := plan.Apply(base)
		prepared = preparedBackfill{correlate: &correlate, matcherVersion: ManualImportFingerprintSchemaVersionV1, reasonCode: plan.ReasonCode}
	default:
		return runner.prepareSkip(source, snapshot, actor, BackfillReasonProducerMatcherUnavailable, false, false), nil
	}
	if prepared.correlate != nil && target.reasonCode != "" && !prepared.correlate.ReviewReason.Valid() {
		prepared.correlate.ProvisionalIdentity = true
		prepared.correlate.ReviewReason = lineagedom.ReasonInsufficientAnchor
		prepared.correlate.ReviewDetailCode = target.reasonCode
		prepared.reasonCode = target.reasonCode
	}
	prepared.plannedOutcome = BackfillOutcomeObservationCreated
	if prepared.correlate != nil && (prepared.correlate.ProvisionalIdentity || prepared.correlate.ReviewReason.Valid()) {
		prepared.plannedOutcome = BackfillOutcomeProvisionalCandidate
	}
	return prepared, nil
}

func (runner *BackfillRunner) prepareSkip(source ports.FindingLineageBackfillSourceRow, snapshot snapshotdom.Snapshot, actor, detailCode string, redactionInvalid, ownershipInvalid bool) preparedBackfill {
	producer, findingKind := legacyProducer(source.Kind)
	target := selectBackfillTarget(snapshot, producer, findingKind, source.AssessmentID)
	correlate := CorrelateInput{
		TenantID: source.TenantID, CycleID: source.CycleID, SnapshotID: source.SnapshotID,
		ProducerKind: producer, FindingKind: findingKind, FingerprintSchemaVersion: 1,
		FingerprintInput: lineagedom.FingerprintCanonicalInputV1{
			CanonicalizationVersion: lineagedom.CanonicalizationVersionV1, ProducerKind: producer,
			TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: target.canonical, IdentityFields: map[string]lineagedom.CanonicalValue{},
		},
		InputTrusted:       detailCode != BackfillReasonProducerMatcherUnavailable && detailCode != BackfillReasonMalformedTrustBoundary,
		OwnershipValidated: !ownershipInvalid, RedactionComplete: !redactionInvalid, SkipDetailCode: detailCode,
		Observation: ObservationInput{SourceFindingID: source.FindingID.String(), Severity: validBackfillSeverity(source.Severity), ScannerProvenance: lineagedom.ScannerProvenance{ToolName: "legacy-" + producer}, ObservedAt: source.ObservedAt},
		Actor:       actor,
	}
	return preparedBackfill{correlate: &correlate, matcherVersion: 1, reasonCode: detailCode, plannedOutcome: BackfillOutcomeSkipped}
}

type backfillTarget struct {
	canonical  string
	reasonCode string
	provenance lineagedom.ScannerProvenance
}

func selectBackfillTarget(snapshot snapshotdom.Snapshot, producer, findingKind string, assessmentID shared.ID) backfillTarget {
	targets := map[string]lineagedom.ScannerProvenance{}
	for _, dimension := range snapshot.Dimensions {
		if dimension.Producer != producer && dimension.FindingKind != findingKind {
			continue
		}
		targets[dimension.Target.Canonical] = lineagedom.ScannerProvenance{
			ScanRunID: dimension.RunID, LaneKey: dimension.LaneKey, ToolName: dimension.Producer,
		}
	}
	if len(targets) == 1 {
		for canonical, provenance := range targets {
			if strings.TrimSpace(provenance.ToolName) == "" {
				provenance.ToolName = "legacy-" + producer
			}
			return backfillTarget{canonical: canonical, provenance: provenance}
		}
	}
	reason := BackfillReasonMissingTarget
	if len(targets) > 1 {
		reason = BackfillReasonAmbiguousTarget
	}
	// ponytail: legacy Findings have no direct target FK; keep the assessment-scoped fallback
	// provisional until producers persist an exact Snapshot dimension reference.
	return backfillTarget{
		canonical: "assessment:" + assessmentID.String(), reasonCode: reason,
		provenance: lineagedom.ScannerProvenance{ToolName: "legacy-" + producer},
	}
}

func backfillObservation(source ports.FindingLineageBackfillSourceRow, target backfillTarget) (ObservationInput, error) {
	severity := validBackfillSeverity(source.Severity)
	var riskScore *int
	if source.RiskScore != 0 {
		if math.IsNaN(source.RiskScore) || math.IsInf(source.RiskScore, 0) || source.RiskScore < 0 || source.RiskScore > 10 {
			return ObservationInput{}, fmt.Errorf("%w: legacy risk score is outside the supported range", shared.ErrValidation)
		}
		value := int(math.Round(source.RiskScore * 1000))
		riskScore = &value
	}
	componentVersion := ""
	if source.Kind == "" || source.Kind == finding.KindSCA {
		_, _, version, ok := vulnerability.ParseDedupKey(source.DedupKey)
		if componentVersion == "" && ok {
			componentVersion = version
		}
	}
	return ObservationInput{
		SourceFindingID: source.FindingID.String(), SourceOccurrenceID: source.OccurrenceID.String(), Severity: severity,
		RiskScoreMilli: riskScore, ComponentVersion: componentVersion, Location: sourceLocation(source), Reachability: strings.TrimSpace(source.Reachability),
		ScannerProvenance: target.provenance, ObservedAt: source.ObservedAt,
	}, nil
}

func (runner *BackfillRunner) findOccurrence(ctx context.Context, source ports.FindingLineageBackfillSourceRow, cache *backfillCache) (vulnerabilityoccurrence.Occurrence, bool, error) {
	if source.OccurrenceID.IsZero() {
		return vulnerabilityoccurrence.Occurrence{}, false, nil
	}
	items, ok := cache.occurrences[source.AssessmentID]
	if !ok {
		listed, err := runner.occurrences.ListByEngagement(ctx, source.TenantID, source.AssessmentID, nil)
		if err != nil {
			return vulnerabilityoccurrence.Occurrence{}, false, err
		}
		items = make(map[shared.ID]vulnerabilityoccurrence.Occurrence, len(listed))
		for _, item := range listed {
			items[item.ID] = item
		}
		cache.occurrences[source.AssessmentID] = items
	}
	item, ok := items[source.OccurrenceID]
	if !ok || item.TenantID != source.TenantID || item.EngagementID != source.AssessmentID {
		return vulnerabilityoccurrence.Occurrence{}, false, shared.ErrNotFound
	}
	return item, true, nil
}

func (runner *BackfillRunner) findJudgment(ctx context.Context, assessmentID, judgmentID shared.ID, cache *backfillCache) (judgment.Judgment, bool, error) {
	items, ok := cache.judgments[assessmentID]
	if !ok {
		listed, err := runner.judgments.ListByEngagement(ctx, assessmentID)
		if err != nil {
			return judgment.Judgment{}, false, err
		}
		items = make(map[shared.ID]judgment.Judgment, len(listed))
		for _, item := range listed {
			items[item.ID] = item
		}
		cache.judgments[assessmentID] = items
	}
	item, ok := items[judgmentID]
	return item, ok, nil
}

func (runner *BackfillRunner) loadSnapshot(ctx context.Context, tenantID, snapshotID shared.ID, cache *backfillCache) (*snapshotdom.Snapshot, error) {
	if snapshot := cache.snapshots[snapshotID]; snapshot != nil {
		return snapshot, nil
	}
	snapshot, err := runner.snapshots.Get(ctx, tenantID, snapshotID)
	if err != nil {
		return nil, err
	}
	cache.snapshots[snapshotID] = snapshot
	return snapshot, nil
}

func NormalizeFindingLineageProducerFilters(values []string) ([]string, error) {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || value == "all" {
			continue
		}
		var kinds []finding.Kind
		switch value {
		case "sca", "sast", "secret", "quality", "reliability", "manual", "dast", "threat", "hypothesis":
			kinds = []finding.Kind{finding.Kind(value)}
		case "iac", "misconfig":
			kinds = []finding.Kind{finding.KindMisconfig}
		case "cloud", "cloud_posture":
			kinds = []finding.Kind{finding.KindCloudPosture}
		case "offensive":
			kinds = []finding.Kind{finding.KindRecon, finding.KindExploitation}
		case "recon", "exploitation":
			kinds = []finding.Kind{finding.Kind(value)}
		default:
			return nil, fmt.Errorf("%w: unsupported producer filter %q", shared.ErrValidation, value)
		}
		for _, kind := range kinds {
			set[string(kind)] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func finalizeFindingLineageBackfillItem(item *ports.FindingLineageBackfillItem, snapshotContentHash string) {
	if item.MatcherVersion <= 0 {
		item.MatcherVersion = 1
	}
	payload := strings.Join([]string{item.SourceFindingID.String(), strconv.Itoa(item.MatcherVersion), snapshotContentHash}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	item.SourceHash = hex.EncodeToString(sum[:])
	key := sha256.Sum256([]byte("synapse:finding-lineage-backfill:v1\x00" + payload))
	item.IdempotencyKey = hex.EncodeToString(key[:])
}

func legacyProducer(kind finding.Kind) (string, string) {
	switch kind {
	case "", finding.KindSCA:
		return "sca", "vulnerability"
	case finding.KindMisconfig:
		return "iac", "misconfig"
	case finding.KindManual:
		return "manual_native", "manual"
	case finding.KindRecon, finding.KindExploitation:
		return "manual_import", "offensive"
	default:
		return string(kind), string(kind)
	}
}

func legacySASTJudgmentID(dedupKey string) shared.ID {
	const prefix = "sast:ai:"
	if !strings.HasPrefix(strings.TrimSpace(dedupKey), prefix) {
		return ""
	}
	return shared.ID(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(dedupKey), prefix)))
}

func nativeManualSource(source ports.FindingLineageBackfillSourceRow) bool {
	key := strings.TrimSpace(source.DedupKey)
	for _, prefix := range []string{"manual:", "exploitation:", "recon:"} {
		if strings.TrimPrefix(key, prefix) == source.FindingID.String() && strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func legacyManualIdentityID(sourceFindingID shared.ID) shared.ID {
	sum := sha256.Sum256([]byte("synapse:legacy-manual-identity:v1\x00" + sourceFindingID.String()))
	return shared.ID("legacy-manual-v1-" + hex.EncodeToString(sum[:16]))
}

func sourcePath(source ports.FindingLineageBackfillSourceRow) string {
	if source.SourceLocation != nil {
		return source.SourceLocation.File
	}
	if location, ok := legacyFindingSourceLocation(source); ok {
		return location.File
	}
	return ""
}

func sourceLocation(source ports.FindingLineageBackfillSourceRow) string {
	location := source.SourceLocation
	if location == nil {
		legacy, ok := legacyFindingSourceLocation(source)
		if !ok {
			return ""
		}
		location = &legacy
	}
	return location.File + ":" + strconv.Itoa(location.StartLine)
}

func legacyFindingSourceLocation(source ports.FindingLineageBackfillSourceRow) (finding.SourceLocation, bool) {
	var prefix string
	switch source.Kind {
	case finding.KindSAST:
		if strings.HasPrefix(source.DedupKey, "cq:sast:") {
			prefix = "cq:sast:"
		}
	case finding.KindQuality:
		prefix = "cq:quality:"
	case finding.KindReliability:
		prefix = "cq:reliability:"
	case finding.KindSecret:
		prefix = "secret:"
	case finding.KindMisconfig:
		prefix = "misconfig:"
	}
	if prefix == "" || strings.TrimSpace(source.RuleKey) == "" {
		return finding.SourceLocation{}, false
	}
	location := strings.TrimPrefix(source.DedupKey, prefix+source.RuleKey+":")
	if location == source.DedupKey {
		return finding.SourceLocation{}, false
	}
	return finding.SourceLocationFromLegacy(location)
}

func unsafeLegacySecretKey(value string) bool {
	return strings.Contains(value, "://") || containsSourceSensitiveMarker(value)
}

func validBackfillSeverity(severity shared.Severity) shared.Severity {
	if severity.Valid() {
		return severity
	}
	return shared.SeverityUnknown
}

func (runner *BackfillRunner) finishBackfill(ctx context.Context, run ports.FindingLineageBackfillRun, leaseOwner string, state ports.FindingLineageBackfillState, actor string, cause error) (ports.FindingLineageBackfillRun, error) {
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	finished, err := runner.store.FinishFindingLineageBackfillRun(finishCtx, run.TenantID, run.ID, leaseOwner, run.LeaseToken, state, runner.clock.Now().UTC())
	if err != nil {
		if cause != nil {
			return run, errors.Join(cause, err)
		}
		return run, err
	}
	if runner.observer != nil {
		runner.observer.ObserveFindingLineageBackfillRun(string(state))
	}
	runner.record(finishCtx, actor, "finding_lineage.backfill_"+string(state), run.ID, map[string]string{
		"tenant_id": run.TenantID.String(), "processed_count": strconv.Itoa(finished.ProcessedCount),
		"observation_created_count": strconv.Itoa(finished.ObservationCreatedCount), "provisional_candidate_count": strconv.Itoa(finished.ProvisionalCandidateCount),
		"skipped_count": strconv.Itoa(finished.SkippedCount),
	})
	if cause != nil {
		return finished, cause
	}
	return finished, nil
}

func (runner *BackfillRunner) record(ctx context.Context, actor, action string, target shared.ID, metadata map[string]string) {
	if runner.audit != nil {
		_ = runner.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target.String(), Metadata: metadata, At: runner.clock.Now().UTC()})
	}
}

func retryableFindingLineageBackfillError(err error) bool {
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, shared.ErrValidation) && !errors.Is(err, shared.ErrNotFound) && !errors.Is(err, shared.ErrConflict) && !errors.Is(err, lineagedom.ErrSensitiveInput) && !errors.Is(err, ErrSecretMaterialRejected)
}

func findingLineageBackfillTerminalState(err error) ports.FindingLineageBackfillState {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ports.FindingLineageBackfillCancelled
	}
	return ports.FindingLineageBackfillFailed
}
