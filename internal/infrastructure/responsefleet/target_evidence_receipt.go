package responsefleet

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const targetReceiptTimelineLimit = 10000

type TargetEvidenceReceiptBuilder struct {
	bindings   ports.TelemetryAssetBindingLister
	timeline   ports.EndpointTimelineStore
	coverage   ports.BoundedCoverageWindowReader
	store      ports.ResponseTargetEvidenceReceiptStore
	clock      ports.Clock
	staleAfter time.Duration
}

func NewTargetEvidenceReceiptBuilder(bindings ports.TelemetryAssetBindingLister, timeline ports.EndpointTimelineStore, coverage ports.BoundedCoverageWindowReader, store ports.ResponseTargetEvidenceReceiptStore, clock ports.Clock) (*TargetEvidenceReceiptBuilder, error) {
	if bindings == nil || timeline == nil || coverage == nil || store == nil || clock == nil {
		return nil, fmt.Errorf("%w: target evidence receipt builder has incomplete dependencies", shared.ErrValidation)
	}
	return &TargetEvidenceReceiptBuilder{bindings: bindings, timeline: timeline, coverage: coverage, store: store, clock: clock, staleAfter: 5 * time.Minute}, nil
}
func receiptDigest(a rdom.Action) string { d, _ := rdom.CanonicalDigest(a); return d }
func (b *TargetEvidenceReceiptBuilder) incomplete(ctx context.Context, req ports.ResponseVerificationRequest, until time.Time, reasons []string) (fleetagent.ResponseTargetEvidenceReceipt, error) {
	reasons = canonicalReceiptReasons(reasons)
	if len(reasons) == 0 || contains(reasons, "complete") {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("%w: incomplete target evidence receipt has invalid reasons", shared.ErrValidation)
	}
	receipt := fleetagent.ResponseTargetEvidenceReceipt{Version: fleetagent.ResponseTargetEvidenceReceiptVersion, ReceiptID: deterministicCommandID("synapse.response-target-evidence-receipt.v1", req.TenantID.String(), req.AttemptKey), TenantID: req.TenantID, EngagementID: req.EngagementID, ActionID: req.Action.ID, ActionDigest: receiptDigest(req.Action), AttemptKey: strings.TrimSpace(req.AttemptKey), VerificationChallenge: req.VerificationChallenge, Target: req.Target, Reversal: req.Reversal, AttemptedAt: req.AttemptedAt.UTC().Truncate(time.Microsecond), WindowUntil: until, RecordedAt: b.clock.Now().UTC().Truncate(time.Microsecond), TimelineComplete: false, CoverageComplete: false, Saturated: contains(reasons, "timeline_saturated") || contains(reasons, "coverage_saturated"), Reasons: reasons}
	if receipt.RecordedAt.Before(until) {
		receipt.RecordedAt = until
	}
	receipt.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(receipt)
	return b.store.AppendResponseTargetEvidenceReceipt(ctx, receipt)
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
		if candidate.AssetID == req.Target.ProcessAssetID {
			source = candidate
			count++
		}
	}
	if count == 0 {
		return b.incomplete(ctx, req, until, []string{"source_missing"})
	}
	if count != 1 {
		return b.incomplete(ctx, req, until, []string{"source_ambiguous"})
	}
	if !source.UpdatedAt.Add(b.staleAfter).After(until) {
		return b.incomplete(ctx, req, until, []string{"source_stale"})
	}
	session := shared.ID(fleetagent.CanonicalSessionID(source.AgentID))
	timeline, err := b.timeline.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: source.AssetID, SourceAgentID: source.AgentID, SourceAgentSessionID: session, From: req.AttemptedAt, To: until, Limit: targetReceiptTimelineLimit + 1})
	if err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("read target timeline: %w", err)
	}
	windows, err := b.coverage.ListCoverageWindowsBounded(ctx, ports.CoverageWindowQuery{AgentID: source.AgentID, AssetID: source.AssetID, HostID: source.AssetID, Since: req.AttemptedAt, Until: until}, ports.MaxCoverageWindowLimit+1)
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
	timelineComplete := len(timeline) <= targetReceiptTimelineLimit
	if !timelineComplete {
		timeline = timeline[:targetReceiptTimelineLimit]
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
	if len(reasons) == 0 {
		reasons = []string{"complete"}
	}
	reasons = canonicalReceiptReasons(reasons)
	saturated := contains(reasons, "timeline_saturated") || contains(reasons, "coverage_saturated")
	receipt := fleetagent.ResponseTargetEvidenceReceipt{Version: fleetagent.ResponseTargetEvidenceReceiptVersion, ReceiptID: deterministicCommandID("synapse.response-target-evidence-receipt.v1", req.TenantID.String(), req.AttemptKey), TenantID: req.TenantID, EngagementID: req.EngagementID, ActionID: req.Action.ID, ActionDigest: receiptDigest(req.Action), AttemptKey: strings.TrimSpace(req.AttemptKey), VerificationChallenge: req.VerificationChallenge, Target: req.Target, Reversal: req.Reversal, AttemptedAt: req.AttemptedAt.UTC().Truncate(time.Microsecond), WindowUntil: until, RecordedAt: b.clock.Now().UTC().Truncate(time.Microsecond), SourceAgentID: source.AgentID, SourceAgentSessionID: session, SourceHostID: source.AssetID, Timeline: timeline, Coverage: windows, TimelineComplete: timelineComplete, CoverageComplete: coverageComplete, Saturated: saturated, Reasons: reasons}
	if receipt.RecordedAt.Before(until) {
		receipt.RecordedAt = until
	}
	receipt.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(receipt)
	return b.store.AppendResponseTargetEvidenceReceipt(ctx, receipt)
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
	return nil
}

func continuousCoverage(from, to time.Time, windows []sensorstate.CoverageWindow) bool {
	latest := map[string]sensorstate.CoverageWindow{}
	for _, w := range windows {
		if w.Vector.Process != 100 || w.SampledCount != 0 || w.TruncatedCount != 0 || w.DroppedCount != 0 || w.GapCount != 0 || w.BatchCount == 0 {
			continue
		}
		key := w.Since.String() + "/" + w.Until.String()
		if old, ok := latest[key]; !ok || old.Revision < w.Revision {
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
