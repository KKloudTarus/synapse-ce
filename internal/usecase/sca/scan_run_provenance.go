package sca

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

const scanRunManifestSchemaVersion = 1

func (service *Service) beginNativeScanRun(ctx context.Context, engagementID shared.ID, runID shared.ID, startedAt time.Time) (ports.ScanRun, *engagement.Engagement, error) {
	if service.runs == nil {
		return ports.ScanRun{ID: runID.String()}, nil, nil
	}
	tenantID, governedEngagement, err := service.scanRunTenant(ctx, engagementID)
	if err != nil {
		return ports.ScanRun{}, nil, err
	}
	stableRunID := !runID.IsZero()
	if !stableRunID {
		runID = shared.ID(service.newRunID())
	}
	run := ports.ScanRun{
		TenantID: tenantID.String(), ID: runID.String(), EngagementID: engagementID.String(), CreatedAt: startedAt.UTC(),
		Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding,
	}
	if err := service.runs.Begin(ctx, run); err != nil {
		if !stableRunID && errors.Is(err, shared.ErrConflict) {
			run.ID = randomScanRunID()
			if retryErr := service.runs.Begin(ctx, run); retryErr != nil {
				return ports.ScanRun{}, nil, fmt.Errorf("begin native scan run after id collision: %w", retryErr)
			}
			return run, governedEngagement, nil
		}
		if stableRunID && errors.Is(err, shared.ErrConflict) {
			existing, getErr := service.runs.Get(ctx, tenantID, run.ID)
			if getErr == nil && existing.EngagementID == engagementID.String() && existing.Provenance == scanrun.ProvenanceNative {
				return existing, governedEngagement, nil
			}
		}
		return ports.ScanRun{}, nil, fmt.Errorf("begin native scan run: %w", err)
	}
	return run, governedEngagement, nil
}

func (service *Service) persistNativeScanRun(ctx context.Context, engagementID shared.ID, runID shared.ID, startedAt time.Time, request ports.AcquireRequest, result *ScanResult, evidenceRef shared.ID, sourceDigest string) error {
	if service.runs == nil {
		return nil
	}
	run, governedEngagement, err := service.beginNativeScanRun(ctx, engagementID, runID, startedAt)
	if err != nil {
		return err
	}
	if run.TerminalStatus != scanrun.StatusBuilding {
		return nil
	}
	lane, terminalStatus, err := nativeSCALane(governedEngagement, run.ID, startedAt, request, result, evidenceRef, sourceDigest, service.clock.Now())
	if err != nil {
		return err
	}
	run.Manifest = result.Manifest
	run.FindingKeys = findingKeys(result.Findings)
	run.Lanes = []scanrun.Lane{lane}
	if err := run.Seal(terminalStatus, scanRunManifestSchemaVersion, service.clock.Now()); err != nil {
		return fmt.Errorf("seal native scan run manifest: %w", err)
	}
	if err := service.runs.Seal(ctx, run); err != nil {
		return fmt.Errorf("persist native scan run: %w", err)
	}
	return nil
}

func (service *Service) sealEmptyNativeScanRun(ctx context.Context, engagementID, runID shared.ID, startedAt time.Time, status scanrun.TerminalStatus, sealedAt time.Time) error {
	if service.runs == nil || runID.IsZero() {
		return nil
	}
	run, _, err := service.beginNativeScanRun(ctx, engagementID, runID, startedAt)
	if err != nil {
		return err
	}
	if run.TerminalStatus != scanrun.StatusBuilding {
		return nil
	}
	run.Manifest = ports.ScanManifest{}
	run.FindingKeys = nil
	run.Lanes = nil
	if err := run.Seal(status, scanRunManifestSchemaVersion, sealedAt); err != nil {
		return err
	}
	return service.runs.Seal(ctx, run)
}

func scanRunTerminalStatus(err error) scanrun.TerminalStatus {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return scanrun.StatusCancelled
	}
	return scanrun.StatusFailed
}

func (service *Service) scanRunTenant(ctx context.Context, engagementID shared.ID) (shared.ID, *engagement.Engagement, error) {
	item, err := service.engagements.GetByID(ctx, engagementID)
	if err != nil {
		return "", nil, fmt.Errorf("load scan run engagement: %w", err)
	}
	tenantID := shared.TenantOrDefault(item.TenantID)
	if bound, ok := shared.TenantFrom(ctx); ok && bound != tenantID {
		return "", nil, fmt.Errorf("%w: scan run tenant context mismatch", shared.ErrValidation)
	}
	return tenantID, item, nil
}

func nativeSCALane(item *engagement.Engagement, runID string, startedAt time.Time, request ports.AcquireRequest, result *ScanResult, evidenceRef shared.ID, sourceDigest string, finishedAt time.Time) (scanrun.Lane, scanrun.TerminalStatus, error) {
	if item == nil || result == nil {
		return scanrun.Lane{}, "", fmt.Errorf("%w: scan result provenance is required", shared.ErrValidation)
	}
	targetInput := scanrun.TargetInput{Kind: scanrun.TargetRepository, Raw: firstNonEmpty(result.Target, request.Value), EvaluatedRevision: result.SourceCommit, SchemaVersion: 1}
	if request.Kind == ports.TargetImage || result.Image != nil {
		targetInput.Kind = scanrun.TargetImage
		if result.Image != nil {
			targetInput.Raw = firstNonEmpty(result.Image.Reference, targetInput.Raw)
			targetInput.EvaluatedRevision = result.Image.Digest
		}
	} else if sourceDigest != "" {
		targetInput.EvaluatedRevision = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(sourceDigest)), "sha256:")
	} else if targetInput.EvaluatedRevision == "" {
		targetInput.EvaluatedRevision = digestFromManagedTarget(request.Value)
	}
	target, err := scanrun.CanonicalTarget(targetInput)
	if err != nil {
		return scanrun.Lane{}, "", fmt.Errorf("derive canonical scan target: %w", err)
	}
	terminalStatus := nativeTerminalStatus(result, target)
	finishedAt = finishedAt.UTC()
	lane := scanrun.Lane{
		Key: "sca", Producer: "synapse-sca", TerminalStatus: terminalStatus, Target: target,
		AuthoritativeFindingKinds: authoritativeFindingKinds(result),
		IncludedScope:             canonicalScope(item.Scope.InScope),
		ExcludedScope:             canonicalScope(item.Scope.OutOfScope),
		StartedAt:                 startedAt.UTC(), FinishedAt: &finishedAt,
		ResultRef: "scan-result/" + runID, EvidenceRef: evidenceRef.String(), ResultSHA256: result.ReproDigest,
		ManifestSchemaVersion: scanRunManifestSchemaVersion,
		Versions:              nativeVersions(result.Manifest),
		Stages:                nativeStages(result.DebugEvents),
	}
	return lane, terminalStatus, nil
}

func nativeTerminalStatus(result *ScanResult, target scanrun.TargetIdentity) scanrun.TerminalStatus {
	if result == nil || !result.Completeness.Confident || len(result.SourceWarnings) > 0 || result.ReproDigest == "" {
		return scanrun.StatusPartial
	}
	if (target.Kind == scanrun.TargetRepository || target.Kind == scanrun.TargetImage) && target.EvaluatedRevision == "" {
		return scanrun.StatusPartial
	}
	for _, event := range result.DebugEvents {
		if event.Status == ports.ScanDebugFailed || event.Status == ports.ScanDebugRunning {
			return scanrun.StatusPartial
		}
	}
	return scanrun.StatusSucceeded
}

func authoritativeFindingKinds(result *ScanResult) []string {
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

func nativeVersions(manifest ports.ScanManifest) []scanrun.Version {
	versions := make([]scanrun.Version, 0, len(manifest.ToolVersions)+4)
	for name, version := range manifest.ToolVersions {
		name, version = strings.TrimSpace(name), strings.TrimSpace(version)
		if name == "" || version == "" {
			continue
		}
		kind := scanrun.VersionTool
		if strings.Contains(strings.ToLower(name), "db") || strings.Contains(strings.ToLower(name), "catalog") {
			kind = scanrun.VersionAdvisoryDatabase
		}
		versions = append(versions, scanrun.Version{Kind: kind, Name: name, Version: version})
	}
	if manifest.GrypeDBVersion != "" {
		versions = append(versions, scanrun.Version{Kind: scanrun.VersionAdvisoryDatabase, Name: "grype-db", Version: manifest.GrypeDBVersion})
	}
	if manifest.VulnDBSnapshot != "" {
		versions = append(versions, scanrun.Version{Kind: scanrun.VersionAdvisoryDatabase, Name: "vulnerability-feed", Version: manifest.VulnDBSnapshot})
	}
	versions = append(versions,
		scanrun.Version{Kind: scanrun.VersionCorrelation, Name: "finding-correlation", Version: strconv.Itoa(manifest.CorrelationVersion)},
		scanrun.Version{Kind: scanrun.VersionSchema, Name: "scan-run-manifest", Version: strconv.Itoa(scanRunManifestSchemaVersion)},
	)
	seen := make(map[string]struct{}, len(versions))
	unique := versions[:0]
	for _, version := range versions {
		key := string(version.Kind) + "\x00" + version.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, version)
	}
	return unique
}

func nativeStages(events []ports.ScanDebugEvent) []scanrun.Stage {
	if len(events) == 0 {
		return []scanrun.Stage{{Key: "pipeline", Status: scanrun.StageSucceeded}}
	}
	counts := map[string]int{}
	stages := make([]scanrun.Stage, 0, len(events))
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
		status := scanrun.StageSucceeded
		reason := ""
		switch event.Status {
		case ports.ScanDebugFailed:
			status, reason = scanrun.StageFailed, "producer_failed"
		case ports.ScanDebugRunning:
			status, reason = scanrun.StageSkipped, "not_terminal"
		}
		started := event.StartedAt.UTC()
		var finished *time.Time
		if event.FinishedAt != nil {
			value := event.FinishedAt.UTC()
			finished = &value
		}
		stages = append(stages, scanrun.Stage{Key: key, Status: status, ReasonCode: reason, StartedAt: &started, FinishedAt: finished})
	}
	if len(stages) == 0 {
		return []scanrun.Stage{{Key: "pipeline", Status: scanrun.StageSucceeded}}
	}
	return stages
}

func canonicalScope(targets []engagement.Target) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		kind := scanrun.TargetHost
		switch target.Kind {
		case engagement.TargetRepo:
			kind = scanrun.TargetRepository
		case engagement.TargetImage:
			kind = scanrun.TargetImage
		case engagement.TargetURL:
			kind = scanrun.TargetURL
		case engagement.TargetCloudAccount:
			kind = scanrun.TargetCloud
		case engagement.TargetCIDR:
			out = append(out, string(target.Kind)+":"+strings.TrimSpace(target.Value))
			continue
		}
		identity, err := scanrun.CanonicalTarget(scanrun.TargetInput{Kind: kind, Raw: target.Value, SchemaVersion: 1})
		if err == nil {
			out = append(out, string(target.Kind)+":"+identity.Canonical)
		}
	}
	sort.Strings(out)
	return out
}

func findingKeys(findings []finding.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, item := range findings {
		keys = append(keys, item.DedupKey)
	}
	return keys
}

func digestFromManagedTarget(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{"sha256/", "sha256:"} {
		if index := strings.LastIndex(value, marker); index >= 0 {
			digest := strings.Trim(value[index+len(marker):], "/")
			if len(digest) == 64 {
				return digest
			}
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "unknown"
}

func randomScanRunID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("scan-run-%d", time.Now().UTC().UnixNano())
	}
	return "scan-run-" + hex.EncodeToString(value[:])
}
