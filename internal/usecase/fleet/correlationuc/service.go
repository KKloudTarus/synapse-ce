// Package correlationuc orchestrates durable, two-phase event-time correlation.
package correlationuc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type IncidentRecorder interface {
	RecordCorrelation(context.Context, []incident.IncidentEvent) ([]incident.Incident, []incident.Incident, error)
}
type RiskReassessor interface {
	Reassess(context.Context, string, shared.ID) (incident.Incident, error)
}
type IncidentNotifier interface {
	IncidentsCreated(context.Context, string, shared.ID, []incident.Incident)
}
type Result struct {
	Created        []incident.Incident
	Updated        []incident.Incident
	Reassessed     int
	ReassessFailed int
	Phase          correlation.Phase
	HasMore        bool
}

type Service struct {
	source       ports.CorrelationDetectionSource
	provenance   ports.CorrelationProvenanceSource
	timeline     ports.EndpointTimelineStore
	state        ports.CorrelationStateStore
	incidents    IncidentRecorder
	reassessor   RiskReassessor
	notifier     IncidentNotifier
	transactions ports.TenantTransactionRunner
	cfg          correlation.Config
	audit        ports.AuditLogger
	now          func() time.Time
}

func (s *Service) SetNotifier(n IncidentNotifier)                       { s.notifier = n }
func (s *Service) SetTransactionRunner(t ports.TenantTransactionRunner) { s.transactions = t }
func NewService(source ports.CorrelationDetectionSource, provenance ports.CorrelationProvenanceSource, timeline ports.EndpointTimelineStore, state ports.CorrelationStateStore, incidents IncidentRecorder, reassessor RiskReassessor, cfg correlation.Config, audit ports.AuditLogger, now func() time.Time) (*Service, error) {
	if source == nil || provenance == nil || timeline == nil || state == nil || incidents == nil || audit == nil || now == nil {
		return nil, fmt.Errorf("%w: correlation dependencies are required", shared.ErrValidation)
	}
	cfg = cfg.Normalize()
	if cfg.Window <= 0 || cfg.MaxPerIncident <= 0 || cfg.AllowedLateness < 0 || cfg.PageSize <= 0 || cfg.MaxActiveSessions <= 0 || cfg.MaxTimelineRefsPerDetection <= 0 || cfg.MaxTimelineRefsPerPage <= 0 {
		return nil, fmt.Errorf("%w: invalid incremental correlation configuration", shared.ErrValidation)
	}
	if cfg.MaxTimelineRefsPerDetection > cfg.MaxTimelineRefsPerPage || cfg.PageSize > 1000 || cfg.MaxActiveSessions > 10000 || cfg.MaxTimelineRefsPerDetection > 1000 || cfg.MaxTimelineRefsPerPage > 10000 {
		return nil, fmt.Errorf("%w: correlation bounds exceed maximum", shared.ErrValidation)
	}
	return &Service{source: source, provenance: provenance, timeline: timeline, state: state, incidents: incidents, reassessor: reassessor, cfg: cfg, audit: audit, now: now}, nil
}

// CorrelateEngagement performs exactly one bounded step. Source pages are only materialized;
// incident output is exclusively produced by the globally event-time ordered consume phase.
func (s *Service) CorrelateEngagement(ctx context.Context, actor string, engagementID shared.ID) (Result, error) {
	if actor == "" || engagementID.IsZero() {
		return Result{}, fmt.Errorf("%w: correlation requires actor and engagement", shared.ErrValidation)
	}
	var result Result
	for attempt := 0; attempt < 3; attempt++ {
		state, err := s.state.LoadCorrelationState(ctx, engagementID, nil, s.cfg.MaxActiveSessions)
		if err != nil {
			return Result{}, fmt.Errorf("load correlation state: %w", err)
		}
		if state.Checkpoint.Phase != "" && state.Checkpoint.PolicyDigest != policyDigest(s.cfg) {
			return Result{}, fmt.Errorf("%w: correlation policy changed during snapshot", shared.ErrConflict)
		}
		switch state.Checkpoint.Phase {
		case "":
			upper, found, err := s.source.CorrelationHighWater(ctx, engagementID, state.Checkpoint.Completed, s.now().UTC())
			if err != nil {
				return Result{}, fmt.Errorf("read correlation high-water: %w", err)
			}
			if !found {
				return s.auditResult(ctx, actor, engagementID, result, 0, 0)
			}
			if _, err := s.state.BeginCorrelationSnapshot(ctx, engagementID, state.Checkpoint.Revision, upper, s.now().UTC(), policyDigest(s.cfg)); err != nil {
				if errors.Is(err, shared.ErrConflict) {
					continue
				}
				return Result{}, fmt.Errorf("begin correlation snapshot: %w", err)
			}
			return s.auditResult(ctx, actor, engagementID, Result{Phase: correlation.PhaseSource, HasMore: true}, 0, 0)
		case correlation.PhaseSource:
			result, err = s.materialize(ctx, actor, engagementID, state)
		case correlation.PhaseConsume:
			result, err = s.consume(ctx, actor, engagementID, state)
		default:
			err = fmt.Errorf("%w: invalid correlation phase", shared.ErrValidation)
		}
		if errors.Is(err, shared.ErrConflict) {
			continue
		}
		if err != nil {
			return Result{}, err
		}
		return result, nil
	}
	return Result{}, fmt.Errorf("%w: correlation did not commit after retries", shared.ErrConflict)
}

func (s *Service) materialize(ctx context.Context, actor string, engagementID shared.ID, state correlation.State) (Result, error) {
	cp := state.Checkpoint
	records, more, err := s.source.ListCorrelationSourcePage(ctx, engagementID, cp.SourceCursor, cp.Snapshot, cp.RetentionAsOf, s.cfg.PageSize)
	if err != nil {
		return Result{}, fmt.Errorf("read correlation source page: %w", err)
	}
	if err := validateSourcePage(records, engagementID, cp.SourceCursor, cp.Snapshot, s.cfg.PageSize); err != nil {
		return Result{}, err
	}
	signals, err := s.sourceSignals(ctx, engagementID, records)
	if err != nil {
		return Result{}, err
	}
	next := cp
	next.Revision++
	if len(records) > 0 {
		last := records[len(records)-1]
		next.SourceCursor = correlation.SourcePosition{RecordedAt: last.RecordedAt.UTC(), ID: last.ID}
	}
	if !more {
		next.Phase = correlation.PhaseConsume
		next.StagedCursor = correlation.SignalPosition{}
	}
	if err := s.state.StageCorrelationSignals(ctx, engagementID, cp.Revision, next, signals); err != nil {
		return Result{}, fmt.Errorf("stage correlation source page: %w", err)
	}
	return s.auditResult(ctx, actor, engagementID, Result{Phase: next.Phase, HasMore: next.Phase != ""}, 0, 0)
}

func validateSourcePage(records []detection.Record, engagementID shared.ID, after, through correlation.SourcePosition, limit int) error {
	if len(records) > limit {
		return fmt.Errorf("%w: correlation source page exceeds limit", shared.ErrConflict)
	}
	previous := after
	for _, record := range records {
		position := correlation.SourcePosition{RecordedAt: record.RecordedAt.UTC(), ID: record.ID}
		if (record.EngagementID != "" && record.EngagementID != engagementID) || position.RecordedAt.IsZero() || position.ID.IsZero() || !sourcePositionAfter(position, previous) || sourcePositionAfter(position, through) {
			return fmt.Errorf("%w: invalid correlation source page order", shared.ErrConflict)
		}
		previous = position
	}
	return nil
}
func sourcePositionAfter(left, right correlation.SourcePosition) bool {
	return left.RecordedAt.After(right.RecordedAt) || (left.RecordedAt.Equal(right.RecordedAt) && left.ID > right.ID)
}

// signals is retained as the narrow page-normalization seam for focused tests.
func (s *Service) signals(ctx context.Context, engagementID shared.ID, records []detection.Record) ([]correlation.Signal, error) {
	return s.sourceSignals(ctx, engagementID, records)
}

func (s *Service) sourceSignals(ctx context.Context, engagementID shared.ID, records []detection.Record) ([]correlation.Signal, error) {
	ids := make([]shared.ID, len(records))
	byID := make(map[shared.ID]detection.Record, len(records))
	signals := signalsFromDetections(records)
	for i, r := range records {
		ids[i] = r.ID
		byID[r.ID] = r
	}
	transitions, err := s.provenance.LoadReceivedTransitions(ctx, engagementID, ids)
	if err != nil {
		return nil, fmt.Errorf("load received detection provenance: %w", err)
	}
	totalRefs := 0
	for _, transition := range transitions {
		record, ok := byID[transition.DetectionID]
		if !ok {
			return nil, fmt.Errorf("%w: received provenance outside source page", shared.ErrConflict)
		}
		if transition.AssetID != record.AssetID || transition.AgentID != record.AgentID {
			return nil, fmt.Errorf("%w: provenance identity contradicts detection %s", shared.ErrConflict, record.ID)
		}
		refs := telemetryIDs(transition)
		if len(refs) > s.cfg.MaxTimelineRefsPerDetection || totalRefs+len(refs) > s.cfg.MaxTimelineRefsPerPage {
			return nil, fmt.Errorf("%w: correlation causal timeline fanout exceeds limit", shared.ErrSaturated)
		}
		totalRefs += len(refs)
		entries, err := s.timeline.LoadTimelineEntries(ctx, record.AssetID, refs)
		if err != nil {
			return nil, fmt.Errorf("load causal endpoint timeline: %w", err)
		}
		wanted := make(map[shared.ID]struct{}, len(refs))
		for _, id := range refs {
			wanted[id] = struct{}{}
		}
		seen := make(map[shared.ID]struct{}, len(entries))
		if len(wanted) != len(refs) {
			return nil, fmt.Errorf("%w: duplicate causal telemetry reference", shared.ErrConflict)
		}
		for _, entry := range entries {
			if _, ok := wanted[entry.EventID]; !ok || entry.AssetID != record.AssetID || entry.SourceAgentID != transition.AgentID {
				return nil, fmt.Errorf("%w: endpoint timeline contradicts detection provenance", shared.ErrConflict)
			}
			if _, duplicate := seen[entry.EventID]; duplicate {
				return nil, fmt.Errorf("%w: duplicate causal endpoint timeline event", shared.ErrConflict)
			}
			seen[entry.EventID] = struct{}{}
			ref := incident.TimelineRef{EventID: entry.EventID, OccurredAt: entry.OccurredAt, Kind: string(entry.Kind), Summary: entry.Summary}
			signals = append(signals, correlation.Signal{ID: timelineSignalID(transition.DetectionID, entry.EventID), AssetID: entry.AssetID, EntityID: record.Detection.HostID, OccurredAt: entry.OccurredAt, Title: entry.Summary, Timeline: &ref})
		}
		if len(seen) != len(wanted) {
			return nil, fmt.Errorf("%w: missing causal endpoint timeline event", shared.ErrConflict)
		}
	}
	return signals, nil
}

func (s *Service) consume(ctx context.Context, actor string, engagementID shared.ID, state correlation.State) (Result, error) {
	cp := state.Checkpoint
	signals, more, err := s.state.ListStagedCorrelationSignals(ctx, engagementID, cp.Snapshot, cp.StagedCursor, s.cfg.PageSize)
	if err != nil {
		return Result{}, fmt.Errorf("read staged correlation page: %w", err)
	}
	ids := make([]shared.ID, len(signals))
	for i, signal := range signals {
		ids[i] = signal.ID
	}
	state, err = s.state.LoadCorrelationState(ctx, engagementID, ids, s.cfg.MaxActiveSessions)
	if err != nil {
		return Result{}, fmt.Errorf("load correlation consume state: %w", err)
	}
	if state.Checkpoint.Revision != cp.Revision || state.Checkpoint.Snapshot != cp.Snapshot || state.Checkpoint.StagedCursor != cp.StagedCursor || state.Checkpoint.Phase != correlation.PhaseConsume {
		return Result{}, fmt.Errorf("%w: correlation consume checkpoint changed", shared.ErrConflict)
	}
	if state.Checkpoint.PolicyDigest != policyDigest(s.cfg) {
		return Result{}, fmt.Errorf("%w: correlation policy changed during snapshot", shared.ErrConflict)
	}
	final := !more
	plan, err := correlation.CorrelateIncrementalPage(s.cfg, state, signals, s.now().UTC(), final)
	if err != nil {
		return Result{}, fmt.Errorf("correlate staged page: %w", err)
	}
	next := plan.Next
	if len(signals) > 0 {
		last := signals[len(signals)-1]
		next.StagedCursor = correlation.SignalPosition{OccurredAt: last.OccurredAt.UTC(), ID: last.ID}
	}
	if !final {
		next.Phase = correlation.PhaseConsume
	}
	next.Revision = state.Checkpoint.Revision + 1
	if final {
		next.Phase = ""
	}
	if len(plan.ActiveSessions) > s.cfg.MaxActiveSessions {
		return Result{}, fmt.Errorf("%w: correlation active-session limit exceeded", shared.ErrSaturated)
	}
	var created, updated []incident.Incident
	commit := func(commitCtx context.Context) error {
		var err error
		created, updated, err = s.incidents.RecordCorrelation(commitCtx, plan.Events)
		if err != nil {
			return fmt.Errorf("record correlation: %w", err)
		}
		if err = s.state.CommitCorrelationConsume(commitCtx, engagementID, state.Checkpoint.Revision, next, plan.Added, plan.ActiveSessions, cp.Snapshot, final); err != nil {
			return fmt.Errorf("commit correlation consume page: %w", err)
		}
		return nil
	}
	if s.transactions == nil {
		err = commit(ctx)
	} else {
		tenant, ok := shared.TenantFrom(ctx)
		if !ok || tenant.IsZero() {
			return Result{}, fmt.Errorf("%w: correlation transaction requires tenant", shared.ErrValidation)
		}
		err = s.transactions.Run(ctx, tenant, commit)
	}
	if err != nil {
		return Result{}, err
	}
	result := Result{Created: created, Updated: updated, Phase: next.Phase, HasMore: !final}
	for _, inc := range append(append([]incident.Incident(nil), created...), updated...) {
		if s.reassessor == nil {
			break
		}
		scored, err := s.reassessor.Reassess(ctx, actor, inc.ID)
		if err != nil {
			result.ReassessFailed++
			continue
		}
		if !replaceIncident(result.Created, scored) {
			replaceIncident(result.Updated, scored)
		}
		result.Reassessed++
	}
	if s.notifier != nil && len(result.Created) > 0 {
		s.notifier.IncidentsCreated(ctx, actor, engagementID, result.Created)
	}
	return s.auditResult(ctx, actor, engagementID, result, plan.TooLate, plan.Suppressed)
}

func (s *Service) auditResult(ctx context.Context, actor string, engagementID shared.ID, result Result, late, suppressed int) (Result, error) {
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "fleet.correlate_engagement", Target: engagementID.String(), At: s.now().UTC(), Metadata: map[string]string{"created": strconv.Itoa(len(result.Created)), "updated": strconv.Itoa(len(result.Updated)), "too_late": strconv.Itoa(late), "suppressed": strconv.Itoa(suppressed)}}); err != nil {
		return result, fmt.Errorf("audit correlate: %w", err)
	}
	return result, nil
}
func policyDigest(cfg correlation.Config) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("v1|%s|%d|%d|%d|%d|%d|%d", cfg.Window, cfg.MaxPerIncident, cfg.AllowedLateness, cfg.PageSize, cfg.MaxActiveSessions, cfg.MaxTimelineRefsPerDetection, cfg.MaxTimelineRefsPerPage)))
	return hex.EncodeToString(sum[:])
}
func telemetryIDs(t detectionprovenance.Transition) []shared.ID {
	ids := make([]shared.ID, 0, len(t.TelemetryRefs))
	for _, r := range t.TelemetryRefs {
		ids = append(ids, r.EventID)
	}
	return ids
}
func timelineSignalID(d, e shared.ID) shared.ID {
	return shared.ID("timeline:" + d.String() + ":" + e.String())
}
func replaceIncident(items []incident.Incident, replacement incident.Incident) bool {
	for i := range items {
		if items[i].ID == replacement.ID {
			items[i] = replacement
			return true
		}
	}
	return false
}
func signalsFromDetections(records []detection.Record) []correlation.Signal {
	signals := make([]correlation.Signal, 0, len(records))
	for _, r := range records {
		d := r.Detection
		signals = append(signals, correlation.Signal{ID: r.ID, AssetID: r.AssetID, EntityID: d.HostID, OccurredAt: d.Observed, Severity: d.Severity, RuleID: d.RuleID, Title: string(d.Class) + ": " + d.RuleID})
	}
	return signals
}
