package sca

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRunObserver receives a successfully persisted immutable scan-run boundary.
// Implementations may create Snapshot, lineage, and comparison shadow artifacts.
type ScanRunObserver interface {
	AssessmentScanRunSealed(context.Context, shared.ID, shared.ID, shared.ID) error
}

func (s *Service) SetScanRunObserver(observer ScanRunObserver) { s.scanRunObserver = observer }

func (s *Service) SetAssessmentCycleMembership(cycles ports.AssessmentCycleRepository, snapshots ports.AssessmentSnapshotDefaultReader) {
	s.assessmentCycles, s.assessmentSnapshots = cycles, snapshots
}

// SetScanRunProvenance enables native manifests without broadening the legacy
// ScanRunStore port used by integrations and existing scan-history callers.
func (s *Service) SetScanRunProvenance(store ports.ScanRunProvenanceStore, tx ports.TenantTransactionRunner) {
	s.runProvenance, s.scanRunTransactions = store, tx
}

func (s *Service) persistAssessmentScanRun(ctx context.Context, engagementID, preferredRunID shared.ID, startedAt time.Time, request ports.AcquireRequest, result *ScanResult, sourceDigest string) (shared.ID, error) {
	if s.runs == nil || result == nil {
		return "", nil
	}
	item, err := s.engagements.GetByID(ctx, engagementID)
	if err != nil {
		return "", fmt.Errorf("load scan-run engagement: %w", err)
	}
	tenantID := shared.TenantOrDefault(item.TenantID)
	if bound, ok := shared.TenantFrom(ctx); ok && shared.TenantOrDefault(bound) != tenantID {
		return "", fmt.Errorf("%w: scan-run tenant context mismatch", shared.ErrValidation)
	}
	runID := preferredRunID
	if runID.IsZero() {
		runID = shared.ID(s.newRunID())
	}
	if s.runProvenance == nil {
		return runID, s.runs.Save(shared.WithTenant(ctx, tenantID), ports.ScanRun{
			ID: runID.String(), EngagementID: engagementID.String(), CreatedAt: startedAt.UTC(),
			Manifest: result.Manifest, FindingKeys: assessmentFindingKeys(result.Findings),
		})
	}
	manifest, err := json.Marshal(result.Manifest)
	if err != nil {
		return "", fmt.Errorf("marshal scan-run manifest: %w", err)
	}
	building := scanrun.ScanRun{
		TenantID: tenantID, EngagementID: engagementID, ID: runID.String(), Provenance: scanrun.ProvenanceNative,
		TerminalStatus: scanrun.StatusBuilding, ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
		CreatedAt: startedAt.UTC(), UpdatedAt: startedAt.UTC(), LegacyManifest: manifest, LegacyFindingKeys: assessmentFindingKeys(result.Findings),
	}

	evidenceStore, ok := s.runProvenance.(ports.ScanRunEvidenceStore)
	if !ok || s.scanRunTransactions == nil {
		return "", fmt.Errorf("%w: native scan evidence persistence is unavailable", shared.ErrValidation)
	}
	finishedAt := s.clock.Now().UTC()
	lane, terminalStatus, err := assessmentSCALane(item, runID.String(), startedAt.UTC(), finishedAt, request, result, sourceDigest)
	if err != nil {
		return "", err
	}
	if err := s.bindUploadedAssessmentSource(ctx, item, request, &lane); err != nil {
		return "", err
	}
	evidence, err := buildAssessmentEvidence(result, lane.Target.TargetIdentityCanonical)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(evidence)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	evidenceHash := hex.EncodeToString(digest[:])
	lane.ResultSHA256 = evidenceHash
	lane.Producer = "sca"
	lane.AuthoritativeFindingKinds = []string{"vulnerability"}
	if result.ScanMode == ScanModeLicenses {
		lane.Producer = "license"
		lane.AuthoritativeFindingKinds = []string{"license"}
		lane.TerminalStatus = scanrun.StatusPartial
	}
	lane.LaneKey = lane.Producer
	lanesByKey := map[string]scanrun.Lane{lane.Producer: lane}
	for _, record := range evidence.Records {
		if _, exists := lanesByKey[record.ProducerKind]; exists {
			continue
		}
		other := lane
		other.LaneKey, other.Producer = record.ProducerKind, record.ProducerKind
		other.AuthoritativeFindingKinds = []string{record.FindingKind}
		// Positive observations establish presence, not exhaustive source coverage.
		other.TerminalStatus = scanrun.StatusPartial
		lanesByKey[other.LaneKey] = other
	}
	keys := make([]string, 0, len(lanesByKey))
	for key := range lanesByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lanes := make([]scanrun.Lane, 0, len(keys))
	for _, key := range keys {
		current := lanesByKey[key]
		current.SealedAt = &finishedAt
		current.ManifestHash, err = scanrun.ComputeManifestHash(current)
		if err != nil {
			return "", err
		}
		if current.TerminalStatus != scanrun.StatusSucceeded {
			terminalStatus = scanrun.StatusPartial
		}
		lanes = append(lanes, current)
	}
	manifestHash, err := scanrun.ComputeRunManifestHash(lanes)
	if err != nil {
		return "", err
	}
	err = s.scanRunTransactions.Run(ctx, tenantID, func(txCtx context.Context) error {
		if err := s.runProvenance.SaveScanRun(txCtx, building); err != nil {
			return err
		}
		if err := evidenceStore.SaveScanRunEvidence(txCtx, ports.ScanRunEvidence{TenantID: tenantID, RunID: runID.String(), ContentHash: evidenceHash, Payload: payload}); err != nil {
			return err
		}
		if err := s.runProvenance.SealScanRun(txCtx, ports.SealScanRunCommand{TenantID: tenantID, RunID: runID.String(), TerminalStatus: terminalStatus, Lanes: lanes, ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion, ManifestHash: manifestHash, SealedAt: finishedAt}); err != nil {
			return err
		}
		if s.audit != nil {
			return s.audit.Record(txCtx, ports.AuditEntry{Actor: "system:scan-provenance", Action: "assessment_scan_run.sealed", Target: runID.String(), At: finishedAt, Metadata: map[string]string{"tenant_id": tenantID.String(), "assessment_id": engagementID.String(), "manifest_hash": manifestHash, "evidence_hash": evidenceHash}})
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("persist immutable native scan evidence: %w", err)
	}

	return runID, nil
}

// An uploaded revision changes bytes, not the logical application under test.
// Use the Cycle's immutable root source as its namespace anchor, while keeping
// the evaluated content digest on each run. Only explicit same-Cycle uploads are
// eligible; arbitrary local paths or unrelated repositories never share this key.
func (s *Service) bindUploadedAssessmentSource(ctx context.Context, item *engagement.Engagement, request ports.AcquireRequest, lane *scanrun.Lane) error {
	if s.assessmentCycles == nil || s.assessmentSnapshots == nil || request.Kind != ports.TargetUpload || sourcepackage.DigestFromTarget(request.Value) == "" {
		return nil
	}
	tenantID := shared.TenantOrDefault(item.TenantID)
	cycle, err := s.assessmentCycles.GetCycleByAssessment(ctx, tenantID, item.ID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil // Legacy/unmigrated uploads retain revision-isolated identity.
	}
	if err != nil {
		return err
	}
	baseline, _, err := s.assessmentSnapshots.GetDefault(ctx, tenantID, cycle.RootAssessmentID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	} // The initial run establishes the namespace.
	if err != nil {
		return err
	}
	if baseline.CycleID != cycle.ID || baseline.Provenance != assessmentsnapshot.ProvenanceNative {
		return nil
	}
	var rootTarget string
	for _, dimension := range baseline.Dimensions {
		for _, scope := range dimension.IncludedScope {
			candidate := strings.TrimPrefix(scope, string(engagement.TargetRepo)+":")
			if sourcepackage.DigestFromTarget(candidate) == "" {
				continue
			}
			if rootTarget != "" && rootTarget != candidate {
				return nil
			}
			rootTarget = candidate
		}
	}
	if rootTarget == "" {
		return nil
	}
	var target *assessmentsnapshot.Target
	for _, dimension := range baseline.Dimensions {
		matchesSource := false
		for _, scope := range dimension.IncludedScope {
			matchesSource = matchesSource || scope == string(engagement.TargetRepo)+":"+rootTarget
		}
		if !matchesSource || dimension.Target.Kind != scanrun.TargetRepository {
			continue
		}
		if target != nil && (target.Canonical != dimension.Target.Canonical || target.SchemaVersion != dimension.Target.SchemaVersion) {
			return nil
		}
		value := dimension.Target
		target = &value
	}
	if target == nil {
		return nil
	}
	lane.Target.TargetIdentityCanonical, lane.Target.TargetIdentitySchemaVersion = target.Canonical, target.SchemaVersion
	for index, scope := range lane.IncludedScope {
		if scope == string(engagement.TargetRepo)+":"+request.Value {
			lane.IncludedScope[index] = string(engagement.TargetRepo) + ":" + rootTarget
		}
	}
	sort.Strings(lane.IncludedScope)
	return lane.Validate()
}

func assessmentSCALane(item *engagement.Engagement, runID string, startedAt, finishedAt time.Time, request ports.AcquireRequest, result *ScanResult, sourceDigest string) (scanrun.Lane, scanrun.TerminalStatus, error) {
	target, immutable, err := assessmentScanTarget(request, result, sourceDigest)
	if err != nil {
		return scanrun.Lane{}, "", err
	}
	status := scanrun.StatusSucceeded
	if result.VulnsBelowThreshold > 0 || result.UnfixedSuppressed > 0 {
		status = scanrun.StatusPartial
	}
	if !immutable || !result.Completeness.Confident || len(result.SourceWarnings) > 0 || strings.TrimSpace(result.ReproDigest) == "" {
		status = scanrun.StatusPartial
	}
	for _, event := range result.DebugEvents {
		if event.Status == ports.ScanDebugFailed || event.Status == ports.ScanDebugRunning {
			status = scanrun.StatusPartial
			break
		}
	}
	lane := scanrun.Lane{
		TenantID: shared.TenantOrDefault(item.TenantID), EngagementID: item.ID, ScanRunID: runID, LaneKey: "sca", Producer: "synapse-sca", TerminalStatus: status,
		Target: target, AuthoritativeFindingKinds: assessmentFindingKinds(result), IncludedScope: assessmentScope(item.Scope.InScope), ExcludedScope: assessmentScope(item.Scope.OutOfScope),
		StartedAt: startedAt, FinishedAt: &finishedAt, ResultRef: "scan-result/" + runID, ResultSHA256: result.ReproDigest,
		ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion, Versions: assessmentScanVersions(result.Manifest), Stages: assessmentScanStages(result.DebugEvents, startedAt, finishedAt),
	}
	return lane, status, lane.Validate()
}

func assessmentScanTarget(request ports.AcquireRequest, result *ScanResult, sourceDigest string) (scanrun.TargetIdentity, bool, error) {
	if result.Image != nil && strings.TrimSpace(result.Image.Digest) != "" {
		reference := strings.TrimSpace(result.Image.Reference)
		digest := strings.TrimSpace(result.Image.Digest)
		if !strings.HasPrefix(strings.ToLower(digest), "sha256:") {
			digest = "sha256:" + digest
		}
		if at := strings.Index(reference, "@"); at >= 0 {
			reference = reference[:at]
		}
		if reference != "" {
			if target, err := scanrun.CanonicalizeOCITarget(reference + "@" + digest); err == nil {
				return target, true, nil
			}
		}
		return scanrun.TargetIdentity{TargetKind: scanrun.TargetOCI, TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: "managed-oci@" + strings.ToLower(digest), EvaluatedRevision: strings.ToLower(digest)}, true, nil
	}

	revision := strings.ToLower(strings.TrimSpace(result.SourceCommit))
	immutable := revision != ""
	if revision == "" {
		revision = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(sourceDigest)), "sha256:")
		if revision == "" && request.Kind == ports.TargetUpload {
			// Source-upload acquisition verifies these bytes against the retained
			// digest before scanning. A hash of a locator is not a content revision.
			revision = sourcepackage.DigestFromTarget(request.Value)
		}
		immutable = revision != ""
	}
	if len(revision) != 40 && len(revision) != 64 {
		sum := sha256.Sum256([]byte(strings.TrimSpace(request.Value)))
		revision = hex.EncodeToString(sum[:])
		immutable = false
	}
	raw := strings.TrimSpace(result.Target)
	if raw == "" {
		raw = strings.TrimSpace(request.Value)
	}
	if target, err := scanrun.CanonicalizeRepositoryTarget(raw, revision); err == nil {
		return target, immutable, nil
	}
	target := scanrun.TargetIdentity{
		TargetKind: scanrun.TargetRepository, TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical: "managed-repository://sha256/" + revision, EvaluatedRevision: revision,
	}
	return target, immutable, target.Validate()
}

func assessmentFindingKinds(result *ScanResult) []string {
	set := map[string]struct{}{}
	if result.ScanMode == ScanModeLicenses {
		set["license"] = struct{}{}
	} else {
		set[string(finding.KindSCA)] = struct{}{}
	}
	for _, item := range result.Findings {
		kind := item.Kind
		if kind == "" {
			kind = finding.KindSCA
		}
		set[string(kind)] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for kind := range set {
		out = append(out, kind)
	}
	sort.Strings(out)
	return out
}

func assessmentFindingKeys(findings []finding.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, item := range findings {
		keys = append(keys, item.DedupKey)
	}
	sort.Strings(keys)
	return keys
}

func assessmentScope(targets []engagement.Target) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		out = append(out, string(target.Kind)+":"+strings.TrimSpace(target.Value))
	}
	sort.Strings(out)
	return out
}

func assessmentScanVersions(manifest ports.ScanManifest) []scanrun.LaneVersion {
	versions := make([]scanrun.LaneVersion, 0, len(manifest.ToolVersions)+4)
	seen := map[string]struct{}{}
	appendVersion := func(kind scanrun.VersionKind, name, version string) {
		name, version = strings.TrimSpace(name), strings.TrimSpace(version)
		if name == "" || version == "" {
			return
		}
		key := string(kind) + "\x00" + name
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		versions = append(versions, scanrun.LaneVersion{VersionKind: kind, Name: name, Version: version})
	}
	for name, version := range manifest.ToolVersions {
		kind := scanrun.VersionTool
		lower := strings.ToLower(name)
		if lower == "epss-date" || lower == "kev-catalog" {
			// Risk enrichment is retained in the hashed run manifest/Observation,
			// but does not change vulnerability detection coverage. In particular,
			// an empty scan need not request EPSS scores for nonexistent findings.
			continue
		}
		if strings.Contains(lower, "db") || strings.Contains(lower, "catalog") {
			kind = scanrun.VersionAdvisoryDB
		}
		appendVersion(kind, name, version)
	}
	appendVersion(scanrun.VersionAdvisoryDB, "grype-db", manifest.GrypeDBVersion)
	appendVersion(scanrun.VersionAdvisoryDB, "vulnerability-feed", manifest.VulnDBSnapshot)
	appendVersion(scanrun.VersionCorrelation, "finding-correlation", strconv.Itoa(manifest.CorrelationVersion))
	appendVersion(scanrun.VersionSchema, "scan-run-manifest", strconv.Itoa(scanrun.CurrentManifestSchemaVersion))
	return versions
}

func assessmentScanStages(events []ports.ScanDebugEvent, fallbackStarted, fallbackFinished time.Time) []scanrun.LaneStage {
	if len(events) == 0 {
		return []scanrun.LaneStage{{StageKey: "pipeline", Status: scanrun.StageSucceeded, StartedAt: fallbackStarted, FinishedAt: &fallbackFinished}}
	}
	counts := map[string]int{}
	stages := make([]scanrun.LaneStage, 0, len(events))
	for _, event := range events {
		key := strings.TrimSpace(event.Step)
		if key == "" {
			key = strings.TrimSpace(event.Stage)
		}
		if key == "" {
			continue
		}
		counts[key]++
		if counts[key] > 1 {
			key += "-" + strconv.Itoa(counts[key])
		}
		status, reason := scanrun.StageSucceeded, ""
		if event.Status == ports.ScanDebugFailed {
			status, reason = scanrun.StageFailed, "producer_failed"
		} else if event.Status == ports.ScanDebugRunning {
			status, reason = scanrun.StageSkipped, "not_terminal"
		}
		started := event.StartedAt.UTC()
		if started.IsZero() {
			started = fallbackStarted
		}
		finished := event.FinishedAt
		if finished == nil || finished.IsZero() {
			value := fallbackFinished
			finished = &value
		}
		stages = append(stages, scanrun.LaneStage{StageKey: key, Status: status, ReasonCode: reason, StartedAt: started, FinishedAt: finished})
	}
	if len(stages) == 0 {
		return []scanrun.LaneStage{{StageKey: "pipeline", Status: scanrun.StageSucceeded, StartedAt: fallbackStarted, FinishedAt: &fallbackFinished}}
	}
	return stages
}

func (s *Service) notifyAssessmentScanRun(ctx context.Context, engagementID, runID shared.ID) error {
	if s.scanRunObserver == nil || runID.IsZero() {
		return nil
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		item, err := s.engagements.GetByID(ctx, engagementID)
		if err != nil {
			return fmt.Errorf("load scan-run engagement for lifecycle projection: %w", err)
		}
		tenantID = shared.TenantOrDefault(item.TenantID)
	}
	if err := s.scanRunObserver.AssessmentScanRunSealed(ctx, tenantID, engagementID, runID); err != nil {
		return fmt.Errorf("project native scan run to assessment lifecycle: %w", err)
	}
	return nil
}

func buildAssessmentEvidence(result *ScanResult, target string) (lineageuc.NativeEvidence, error) {
	evidence := lineageuc.NativeEvidence{Version: lineageuc.NativeEvidenceVersion, Records: make([]lineageuc.CorrelateInput, 0, len(result.Findings))}
	if len(result.Findings) > lineageuc.MaxNativeObservations {
		return evidence, fmt.Errorf("%w: native scan exceeds observation limit", shared.ErrValidation)
	}
	vulnerabilities := make(map[string]int, len(result.Vulnerabilities))
	for index, v := range result.Vulnerabilities {
		vulnerabilities[vulnDedupKey(v)] = index
	}
	for _, item := range result.Findings {
		switch item.Kind {
		case "", finding.KindSCA, finding.KindSAST, finding.KindQuality, finding.KindReliability, finding.KindSecret, finding.KindMisconfig:
		default:
			continue
		}
		var record lineageuc.CorrelateInput
		var err error
		if index, ok := vulnerabilities[item.DedupKey]; ok && (item.Kind == finding.KindSCA || item.Kind == "") {
			record, err = lineageuc.BuildNativeEvidenceRecord(item, target, &result.Vulnerabilities[index])
		} else {
			record, err = lineageuc.BuildNativeEvidenceRecord(item, target, nil)
		}
		if err != nil {
			return evidence, fmt.Errorf("prepare redacted native observation: %w", err)
		}
		evidence.Records = append(evidence.Records, record)
	}
	sort.Slice(evidence.Records, func(i, j int) bool {
		left, right := evidence.Records[i], evidence.Records[j]
		if left.ProducerKind != right.ProducerKind {
			return left.ProducerKind < right.ProducerKind
		}
		return left.Observation.SourceFindingID < right.Observation.SourceFindingID
	})
	return evidence, nil
}

func (s *Service) copyAssessmentScanResult(result *ScanResult) *ScanResult {
	copy := *result
	copy.Findings = append([]finding.Finding(nil), result.Findings...)
	copy.VulnsBelowThreshold = countBelowThreshold(copy.Vulnerabilities, s.minSeverity)
	copy.UnfixedSuppressed = countUnfixedSuppressed(copy.Vulnerabilities, s.minSeverity, s.ignoreUnfixed)
	copy.ReproDigest = ReproDigest(&copy)
	return &copy
}
