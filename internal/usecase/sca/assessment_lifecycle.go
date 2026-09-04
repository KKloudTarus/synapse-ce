package sca

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRunObserver receives a successfully persisted immutable scan-run boundary.
// Implementations may create Snapshot, lineage, and comparison shadow artifacts.
type ScanRunObserver interface {
	AssessmentScanRunSealed(context.Context, shared.ID, shared.ID, shared.ID) error
}

func (s *Service) SetScanRunObserver(observer ScanRunObserver) { s.scanRunObserver = observer }

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
	manifest, err := json.Marshal(result.Manifest)
	if err != nil {
		return "", fmt.Errorf("marshal scan-run manifest: %w", err)
	}
	building := scanrun.ScanRun{
		TenantID: tenantID, EngagementID: engagementID, ID: runID.String(), Provenance: scanrun.ProvenanceNative,
		TerminalStatus: scanrun.StatusBuilding, ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
		CreatedAt: startedAt.UTC(), UpdatedAt: startedAt.UTC(), LegacyManifest: manifest, LegacyFindingKeys: assessmentFindingKeys(result.Findings),
	}
	if err := s.runs.SaveScanRun(ctx, building); err != nil {
		return "", fmt.Errorf("begin native scan run: %w", err)
	}

	finishedAt := s.clock.Now().UTC()
	lane, terminalStatus, err := assessmentSCALane(item, runID.String(), startedAt.UTC(), finishedAt, request, result, sourceDigest)
	if err != nil {
		return "", err
	}
	lane.SealedAt = &finishedAt
	lane.ManifestHash, err = scanrun.ComputeManifestHash(lane)
	if err != nil {
		return "", fmt.Errorf("hash native scan-run lane: %w", err)
	}
	lanes := []scanrun.Lane{lane}
	manifestHash, err := scanrun.ComputeRunManifestHash(lanes)
	if err != nil {
		return "", fmt.Errorf("hash native scan run: %w", err)
	}
	if err := s.runs.SealScanRun(ctx, tenantID, runID.String(), terminalStatus, lanes, scanrun.CurrentManifestSchemaVersion, manifestHash, finishedAt); err != nil {
		return "", fmt.Errorf("seal native scan run: %w", err)
	}
	return runID, nil
}

func assessmentSCALane(item *engagement.Engagement, runID string, startedAt, finishedAt time.Time, request ports.AcquireRequest, result *ScanResult, sourceDigest string) (scanrun.Lane, scanrun.TerminalStatus, error) {
	target, immutable, err := assessmentScanTarget(request, result, sourceDigest)
	if err != nil {
		return scanrun.Lane{}, "", err
	}
	status := scanrun.StatusSucceeded
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
