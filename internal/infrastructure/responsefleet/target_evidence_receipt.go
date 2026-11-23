package responsefleet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const targetReceiptTimelineLimit = 10000

type TargetEvidenceReceiptBuilder struct {
	bindings   ports.TelemetryAssetBindingLister
	agents     ports.FleetAgentStore
	timeline   ports.EndpointTimelineStore
	coverage   ports.BoundedCoverageWindowReader
	store      ports.ResponseTargetEvidenceReceiptStore
	clock      ports.Clock
	staleAfter time.Duration
}

func NewTargetEvidenceReceiptBuilder(bindings ports.TelemetryAssetBindingLister, agents ports.FleetAgentStore, timeline ports.EndpointTimelineStore, coverage ports.BoundedCoverageWindowReader, store ports.ResponseTargetEvidenceReceiptStore, clock ports.Clock, staleAfter time.Duration) (*TargetEvidenceReceiptBuilder, error) {
	if bindings == nil || agents == nil || timeline == nil || coverage == nil || store == nil || clock == nil || staleAfter <= 0 {
		return nil, fmt.Errorf("%w: target evidence receipt builder has incomplete dependencies", shared.ErrValidation)
	}
	return &TargetEvidenceReceiptBuilder{bindings: bindings, agents: agents, timeline: timeline, coverage: coverage, store: store, clock: clock, staleAfter: staleAfter}, nil
}
func receiptDigest(a rdom.Action) string { d, _ := rdom.CanonicalDigest(a); return d }

// ErrTargetEvidencePending means accepted telemetry or complete coverage has not arrived yet.
// No receipt or observer order is written for a pending attempt.
var ErrTargetEvidencePending = ports.ErrResponseTargetEvidencePending

func pendingTargetEvidence(reason string) (fleetagent.ResponseTargetEvidenceReceipt, error) {
	return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("%w: %s", ErrTargetEvidencePending, reason)
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func (b *TargetEvidenceReceiptBuilder) Build(ctx context.Context, req ports.ResponseVerificationRequest) (fleetagent.ResponseTargetEvidenceReceipt, error) {
	if req.TenantID.IsZero() || req.EngagementID.IsZero() || req.Action.ID.IsZero() || strings.TrimSpace(req.AttemptKey) == "" || req.Target.Kind != responsesaga.FingerprintProcess || req.Target.ProcessAssetID.IsZero() || req.AttemptedAt.IsZero() || req.DeadlineAt.IsZero() {
		return fleetagent.ResponseTargetEvidenceReceipt{}, shared.ErrValidation
	}
	if existing, found, err := b.store.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey); err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, err
	} else if found {
		if err := validateReceiptRequest(existing, req); err != nil {
			return fleetagent.ResponseTargetEvidenceReceipt{}, err
		}
		return existing, nil
	}
	until := b.clock.Now().UTC().Truncate(time.Microsecond)
	if !until.After(req.AttemptedAt) {
		until = req.AttemptedAt.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	}
	if until.After(req.DeadlineAt) {
		until = req.DeadlineAt.UTC().Truncate(time.Microsecond)
	}
	if until.Before(req.AttemptedAt) {
		return fleetagent.ResponseTargetEvidenceReceipt{}, shared.ErrValidation
	}
	bindings, err := b.bindings.ListTelemetryAssetBindings(ctx)
	if err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("list target telemetry bindings: %w", err)
	}
	var source ports.TelemetryAssetBinding
	count := 0
	for _, candidate := range bindings {
		if candidate.TenantID == req.TenantID && candidate.AssetID == req.Target.ProcessAssetID {
			source = candidate
			count++
		}
	}
	if count == 0 {
		return pendingTargetEvidence("source_missing")
	}
	if count != 1 {
		return pendingTargetEvidence("source_ambiguous")
	}
	if source.AgentID != req.ExecutorAgentID {
		return pendingTargetEvidence("source_changed")
	}
	agent, err := b.agents.GetAgent(ctx, req.TenantID, source.AgentID)
	if errors.Is(err, shared.ErrNotFound) {
		return pendingTargetEvidence("source_missing")
	}
	if err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("read target source agent: %w", err)
	}
	if agent == nil || agent.State != fleetagent.StateActive || !agent.LastSeenAt.Add(b.staleAfter).After(b.clock.Now().UTC()) {
		return pendingTargetEvidence("source_stale")
	}
	session := shared.ID(fleetagent.CanonicalSessionID(source.AgentID))
	timeline, err := b.timeline.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: source.AssetID, SourceAgentID: source.AgentID, SourceAgentSessionID: session, From: req.AttemptedAt, To: until, Limit: targetReceiptTimelineLimit + 1})
	if err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("read target timeline: %w", err)
	}
	timelineSaturated := len(timeline) > targetReceiptTimelineLimit
	var original *fleetagent.ResponseOriginalProcessEvidence
	requiredID, requiredKind := req.Target.ProcessEntityID, endpoint.TimelineProcessExit
	if req.Reversal {
		if req.OriginalAttemptKey == "" || req.OriginalAttemptedAt.IsZero() || !req.OriginalAttemptedAt.Before(req.AttemptedAt) || !telemetry.ValidProcessEntityID(req.ReplacementProcessEntityID.String()) || req.ReplacementProcessEntityID == req.Target.ProcessEntityID {
			return pendingTargetEvidence("reversal_provenance_missing")
		}
		original, err = b.originalEvidence(ctx, req, source, session)
		if err != nil {
			return fleetagent.ResponseTargetEvidenceReceipt{}, err
		}
		requiredID, requiredKind = req.ReplacementProcessEntityID, endpoint.TimelineProcessExec
	}
	var exitAt time.Time
	for _, entry := range timeline {
		if entry.TenantID == req.TenantID && entry.AssetID == source.AssetID && entry.SourceAgentID == source.AgentID && entry.SourceAgentSessionID == session && entry.EntityKind == endpoint.EntityProcess && entry.EntityID == requiredID && entry.Kind == requiredKind && !entry.EventID.IsZero() && !entry.OccurredAt.Before(req.AttemptedAt) && !entry.OccurredAt.After(until) && (exitAt.IsZero() || entry.OccurredAt.Before(exitAt)) {
			exitAt = entry.OccurredAt
		}
	}
	if exitAt.IsZero() {
		return pendingTargetEvidence("required_lifecycle_event_missing")
	}
	cutoff := exitAt.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	if cutoff.Before(until) {
		until = cutoff
	}
	filtered := timeline[:0]
	for _, entry := range timeline {
		if !entry.OccurredAt.After(until) {
			filtered = append(filtered, entry)
		}
	}
	timeline = filtered
	windows, err := b.coverage.ListCoverageWindowsBounded(ctx, ports.CoverageWindowQuery{AgentID: source.AgentID, AssetID: source.AssetID, HostID: source.AgentID, Since: req.AttemptedAt, Until: until}, ports.MaxCoverageWindowLimit+1)
	if err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("read target coverage: %w", err)
	}
	sort.Slice(timeline, func(i, j int) bool {
		if !timeline[i].OccurredAt.Equal(timeline[j].OccurredAt) {
			return timeline[i].OccurredAt.Before(timeline[j].OccurredAt)
		}
		return timeline[i].EventID < timeline[j].EventID
	})
	sort.Slice(windows, func(i, j int) bool {
		if !windows[i].Since.Equal(windows[j].Since) {
			return windows[i].Since.Before(windows[j].Since)
		}
		if !windows[i].Until.Equal(windows[j].Until) {
			return windows[i].Until.Before(windows[j].Until)
		}
		return windows[i].Revision < windows[j].Revision
	})
	reasons := []string{}
	timelineComplete := !timelineSaturated
	if !timelineComplete {
		if len(timeline) > targetReceiptTimelineLimit {
			timeline = timeline[:targetReceiptTimelineLimit]
		}
		reasons = append(reasons, "timeline_saturated")
	}
	coverageComplete := len(windows) <= ports.MaxCoverageWindowLimit
	if !coverageComplete {
		windows = windows[:ports.MaxCoverageWindowLimit]
		reasons = append(reasons, "coverage_saturated")
	}
	if !continuousCoverage(req.AttemptedAt, until, windows) {
		coverageComplete = false
		reasons = append(reasons, "coverage_incomplete")
	}
	if len(reasons) != 0 {
		return pendingTargetEvidence(strings.Join(canonicalReceiptReasons(reasons), ","))
	}
	reasons = []string{"complete"}
	reasons = canonicalReceiptReasons(reasons)
	saturated := contains(reasons, "timeline_saturated") || contains(reasons, "coverage_saturated")
	receipt := fleetagent.ResponseTargetEvidenceReceipt{Version: fleetagent.ResponseTargetEvidenceReceiptVersion, ReceiptID: deterministicCommandID("synapse.response-target-evidence-receipt.v1", req.TenantID.String(), req.AttemptKey), TenantID: req.TenantID, EngagementID: req.EngagementID, ActionID: req.Action.ID, ActionDigest: receiptDigest(req.Action), AttemptKey: strings.TrimSpace(req.AttemptKey), VerificationChallenge: req.VerificationChallenge, Target: req.Target, Reversal: req.Reversal, AttemptedAt: req.AttemptedAt.UTC().Truncate(time.Microsecond), WindowUntil: until, RecordedAt: b.clock.Now().UTC().Truncate(time.Microsecond), SourceAgentID: source.AgentID, SourceAgentSessionID: session, SourceHostID: source.AgentID, Timeline: timeline, Coverage: windows, TimelineComplete: timelineComplete, CoverageComplete: coverageComplete, Saturated: saturated, Reasons: reasons}
	receipt.OriginalEvidence = original
	if req.Reversal {
		receipt.ReplacementProcessEntityID = req.ReplacementProcessEntityID
	}
	if receipt.RecordedAt.Before(until) {
		receipt.RecordedAt = until
	}
	receipt.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(receipt)
	stored, err := b.store.AppendResponseTargetEvidenceReceipt(ctx, receipt)
	if errors.Is(err, shared.ErrConflict) {
		// Concurrent builders may observe later coverage revisions; first finalized receipt wins.
		if existing, found, readErr := b.store.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey); readErr != nil {
			return fleetagent.ResponseTargetEvidenceReceipt{}, readErr
		} else if found {
			if validationErr := validateReceiptRequest(existing, req); validationErr != nil {
				return fleetagent.ResponseTargetEvidenceReceipt{}, validationErr
			}
			return existing, nil
		}
	}
	return stored, err
}
func canonicalReceiptReasons(reasons []string) []string {
	set := make(map[string]struct{}, len(reasons))
	for _, reason := range reasons {
		if reason = strings.TrimSpace(reason); reason != "" {
			set[reason] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for reason := range set {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

func validateReceiptRequest(receipt fleetagent.ResponseTargetEvidenceReceipt, req ports.ResponseVerificationRequest) error {
	if err := receipt.Validate(); err != nil {
		return fmt.Errorf("%w: persisted target evidence receipt is invalid: %v", shared.ErrConflict, err)
	}
	if receipt.TenantID != req.TenantID || receipt.EngagementID != req.EngagementID || receipt.ActionID != req.Action.ID || receipt.ActionDigest != receiptDigest(req.Action) ||
		receipt.AttemptKey != strings.TrimSpace(req.AttemptKey) || receipt.VerificationChallenge != req.VerificationChallenge || receipt.Target != req.Target || receipt.Reversal != req.Reversal ||
		!receipt.AttemptedAt.Equal(req.AttemptedAt.UTC().Truncate(time.Microsecond)) || receipt.WindowUntil.After(req.DeadlineAt.UTC().Truncate(time.Microsecond)) {
		return fmt.Errorf("%w: persisted target evidence receipt disagrees with current verification request", shared.ErrConflict)
	}
	if req.Reversal && (receipt.OriginalEvidence == nil || receipt.OriginalEvidence.AttemptKey != req.OriginalAttemptKey || !receipt.OriginalEvidence.AttemptedAt.Equal(req.OriginalAttemptedAt.UTC().Truncate(time.Microsecond)) || receipt.ReplacementProcessEntityID != req.ReplacementProcessEntityID) {
		return fmt.Errorf("%w: reversal provenance disagrees with current verification request", shared.ErrConflict)
	}
	return nil
}

func (b *TargetEvidenceReceiptBuilder) originalEvidence(ctx context.Context, req ports.ResponseVerificationRequest, source ports.TelemetryAssetBinding, session shared.ID) (*fleetagent.ResponseOriginalProcessEvidence, error) {
	prior, found, err := b.store.GetResponseTargetEvidenceReceipt(ctx, req.OriginalAttemptKey)
	if err != nil {
		return nil, err
	}
	var entries []endpoint.TimelineEntry
	var coverage []sensorstate.CoverageWindow
	if found && prior.Validate() == nil && !prior.Reversal && prior.TenantID == req.TenantID && prior.EngagementID == req.EngagementID && prior.ActionID == req.Action.ID && prior.ActionDigest == receiptDigest(req.Action) && prior.Target == req.Target && prior.VerificationChallenge == req.OriginalChallenge && prior.SourceAgentID == source.AgentID && prior.SourceHostID == source.AgentID && prior.SourceAgentSessionID == session && prior.AttemptedAt.Equal(req.OriginalAttemptedAt.UTC().Truncate(time.Microsecond)) && prior.TimelineComplete && prior.CoverageComplete && !prior.Saturated {
		entries, coverage = prior.Timeline, prior.Coverage
	} else {
		entries, err = b.timeline.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: source.AssetID, SourceAgentID: source.AgentID, SourceAgentSessionID: session, From: req.OriginalAttemptedAt, To: req.AttemptedAt, Limit: targetReceiptTimelineLimit + 1})
		if err != nil {
			return nil, fmt.Errorf("read original lifecycle timeline: %w", err)
		}
		if len(entries) > targetReceiptTimelineLimit {
			return nil, fmt.Errorf("%w: original timeline saturated", ErrTargetEvidencePending)
		}
	}
	var exit endpoint.TimelineEntry
	for _, entry := range entries {
		if entry.TenantID == req.TenantID && entry.AssetID == source.AssetID && entry.SourceAgentID == source.AgentID && entry.SourceAgentSessionID == session && entry.EntityKind == endpoint.EntityProcess && entry.EntityID == req.Target.ProcessEntityID && entry.Kind == endpoint.TimelineProcessExit && !entry.EventID.IsZero() && !entry.OccurredAt.Before(req.OriginalAttemptedAt) && !entry.OccurredAt.After(req.AttemptedAt) && (exit.EventID.IsZero() || entry.OccurredAt.Before(exit.OccurredAt)) {
			exit = entry
		}
	}
	if exit.EventID.IsZero() {
		return nil, fmt.Errorf("%w: original exit missing", ErrTargetEvidencePending)
	}
	cutoff := exit.OccurredAt.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	if coverage == nil {
		coverage, err = b.coverage.ListCoverageWindowsBounded(ctx, ports.CoverageWindowQuery{AgentID: source.AgentID, AssetID: source.AssetID, HostID: source.AgentID, Since: req.OriginalAttemptedAt, Until: cutoff}, ports.MaxCoverageWindowLimit+1)
		if err != nil {
			return nil, fmt.Errorf("read original coverage: %w", err)
		}
	}
	if len(coverage) > ports.MaxCoverageWindowLimit || !continuousCoverage(req.OriginalAttemptedAt, cutoff, coverage) {
		return nil, fmt.Errorf("%w: original coverage incomplete", ErrTargetEvidencePending)
	}
	return &fleetagent.ResponseOriginalProcessEvidence{AttemptKey: req.OriginalAttemptKey, AttemptedAt: req.OriginalAttemptedAt.UTC().Truncate(time.Microsecond), Exit: exit, Coverage: coverage}, nil
}

func continuousCoverage(from, to time.Time, windows []sensorstate.CoverageWindow) bool {
	latest := map[string]sensorstate.CoverageWindow{}
	for _, w := range windows {
		key := w.Since.String() + "/" + w.Until.String()
		if old, ok := latest[key]; !ok || w.CreatedAt.After(old.CreatedAt) || (w.CreatedAt.Equal(old.CreatedAt) && healthyProcessWindow(old) && !healthyProcessWindow(w)) {
			latest[key] = w
		}
	}
	ordered := make([]sensorstate.CoverageWindow, 0, len(latest))
	for _, w := range latest {
		ordered = append(ordered, w)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Since.Before(ordered[j].Since) })
	cursor := from
	for _, w := range ordered {
		if !healthyProcessWindow(w) {
			continue
		}
		if w.Until.Before(cursor) || w.Until.Equal(cursor) || w.Since.After(cursor) {
			continue
		}
		if w.Until.After(cursor) {
			cursor = w.Until
		}
		if !cursor.Before(to) {
			return true
		}
	}
	return false
}

func healthyProcessWindow(w sensorstate.CoverageWindow) bool {
	return w.Vector.Process == 100 && w.SampledCount == 0 && w.TruncatedCount == 0 && w.DroppedCount == 0 && w.GapCount == 0 && w.BatchCount > 0
}
