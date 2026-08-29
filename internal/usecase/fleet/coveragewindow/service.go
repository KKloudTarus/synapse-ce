// Package coveragewindow composes immutable sensor, transport-accounting and
// loss facts into revisioned, tenant-scoped telemetry coverage windows.
package coveragewindow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	states  ports.CoverageSensorStateReader
	batches ports.TelemetryBatchAccountingReader
	gaps    ports.CoverageGapReader
	windows ports.CoverageWindowStore
	clock   ports.Clock
}

type ComposeRequest struct {
	AgentID shared.ID
	AssetID shared.ID
	HostID  shared.ID
	Since   time.Time
	Until   time.Time
}

func (r ComposeRequest) Validate() error {
	if r.AgentID.IsZero() || r.AssetID.IsZero() || r.HostID.IsZero() ||
		r.Since.IsZero() || r.Until.IsZero() || !r.Since.Before(r.Until) {
		return fmt.Errorf("%w: coverage composition requires identity and a non-empty half-open interval", shared.ErrValidation)
	}
	return nil
}

func NewService(
	states ports.CoverageSensorStateReader,
	batches ports.TelemetryBatchAccountingReader,
	gaps ports.CoverageGapReader,
	windows ports.CoverageWindowStore,
	clock ports.Clock,
) (*Service, error) {
	if states == nil || batches == nil || gaps == nil || windows == nil || clock == nil {
		return nil, fmt.Errorf("%w: coverage window service dependencies are required", shared.ErrValidation)
	}
	return &Service{states: states, batches: batches, gaps: gaps, windows: windows, clock: clock}, nil
}

func (s *Service) Compose(ctx context.Context, request ComposeRequest) (sensorstate.CoverageWindow, error) {
	if err := request.Validate(); err != nil {
		return sensorstate.CoverageWindow{}, err
	}
	request.Since = canonicalTime(request.Since)
	request.Until = canonicalTime(request.Until)

	observations, err := s.states.ListCoverageSensorStates(ctx, ports.CoverageSensorStateQuery{
		AgentID: request.AgentID, AssetID: request.AssetID, HostID: request.HostID,
		Since: request.Since, Until: request.Until,
	})
	if err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("read coverage sensor states: %w", err)
	}
	accounting, err := s.batches.QueryTelemetryBatchAccounting(ctx, ports.TelemetryBatchAccountingQuery{
		AgentID: request.AgentID, AssetID: request.AssetID, Since: request.Since, Until: request.Until,
	})
	if err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("read coverage telemetry accounting: %w", err)
	}
	gapFacts, err := s.gaps.ListCoverageGapFacts(ctx, ports.CoverageGapQuery{
		AgentID: request.AgentID, AssetID: request.AssetID, Since: request.Since, Until: request.Until,
	})
	if err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("read coverage gaps: %w", err)
	}
	if err := validateSources(request, observations, accounting, gapFacts); err != nil {
		return sensorstate.CoverageWindow{}, err
	}
	canonicalizeSources(observations, accounting, gapFacts)

	window := sensorstate.CoverageWindow{
		AssetID: request.AssetID, AgentID: request.AgentID, HostID: request.HostID,
		Since: request.Since, Until: request.Until, CreatedAt: canonicalTime(s.clock.Now()),
		States: conservativeStates(observations), BatchCount: len(accounting),
		GapCount: scoredGapCount(gapFacts),
	}
	for _, batch := range accounting {
		if !checkedAdd(&window.SampledCount, batch.SampledOutCount) ||
			!checkedAdd(&window.TruncatedCount, batch.TruncatedCount) ||
			!checkedAdd(&window.DroppedCount, batch.DroppedCount) {
			return sensorstate.CoverageWindow{}, fmt.Errorf("%w: coverage disposition counts overflow", shared.ErrValidation)
		}
	}
	window.InputDigest = inputDigest(observations, accounting, gapFacts)
	window.Vector = sensorstate.BuildCoverageVector(window)
	window.Revision = sensorstate.RevisionFor(window)
	if err := window.Validate(); err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("compose coverage window: %w", err)
	}
	stored, err := s.windows.AppendCoverageWindow(ctx, window)
	if err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("append coverage window: %w", err)
	}
	return stored, nil
}

const (
	// DefaultInterval is the deterministic UTC-aligned production coverage bucket.
	DefaultInterval = 5 * time.Minute
	// DefaultMaxAffectedWindows bounds one authenticated source fact so an extreme
	// time range cannot force unbounded synchronous recomposition.
	DefaultMaxAffectedWindows = 1000
)

// Reconciler maps a durable closed source-time span onto deterministic fixed
// half-open windows. Replaying the source fact recomposes the same windows, which
// repairs a prior append failure without a transaction across source stores.
type Reconciler struct {
	service            *Service
	interval           time.Duration
	maxAffectedWindows int
}

func NewReconciler(service *Service, interval time.Duration, maxAffectedWindows int) (*Reconciler, error) {
	if service == nil || interval <= 0 || maxAffectedWindows <= 0 {
		return nil, fmt.Errorf("%w: coverage reconciler requires a service, positive interval and positive window bound", shared.ErrValidation)
	}
	return &Reconciler{service: service, interval: interval, maxAffectedWindows: maxAffectedWindows}, nil
}

func (r *Reconciler) ReconcileCoverage(ctx context.Context, request ports.CoverageReconcileRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	from := canonicalTime(request.Since)
	to := canonicalTime(request.Until)
	windowStart := from.Truncate(r.interval)

	// Validate the complete affected range before composing any window. Source
	// persistence and coverage persistence are intentionally separate, but an
	// oversized reconciliation request must not partially append coverage
	// revisions before it is rejected.
	cursor := windowStart
	for count := 0; !cursor.After(to); count++ {
		if count >= r.maxAffectedWindows {
			return fmt.Errorf("%w: coverage source span affects more than %d fixed windows", shared.ErrValidation, r.maxAffectedWindows)
		}
		cursor = cursor.Add(r.interval)
	}

	for !windowStart.After(to) {
		if _, err := r.service.Compose(ctx, ComposeRequest{
			AgentID: request.AgentID,
			AssetID: request.AssetID,
			HostID:  request.HostID,
			Since:   windowStart,
			Until:   windowStart.Add(r.interval),
		}); err != nil {
			return fmt.Errorf("recompose coverage window starting %s: %w", windowStart.Format(time.RFC3339Nano), err)
		}
		windowStart = windowStart.Add(r.interval)
	}
	return nil
}

var _ ports.CoverageReconciler = (*Reconciler)(nil)

func validateSources(
	request ComposeRequest,
	observations []sensorstate.Observation,
	accounting []ports.TelemetryBatchAccounting,
	gaps []ports.CoverageGapFact,
) error {
	preWindowByClass := make(map[detection.Class]struct{})
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return fmt.Errorf("validate coverage sensor state: %w", err)
		}
		if observation.AgentID != request.AgentID || observation.AssetID != request.AssetID || observation.HostID != request.HostID ||
			!observation.ObservedAt.Before(request.Until) {
			return fmt.Errorf("%w: coverage sensor state is outside requested identity or interval", shared.ErrValidation)
		}
		if observation.ObservedAt.Before(request.Since) {
			for _, state := range observation.States {
				if _, exists := preWindowByClass[state.Class]; exists {
					return fmt.Errorf("%w: coverage sensor state reader returned multiple pre-window facts for class %q", shared.ErrValidation, state.Class)
				}
				preWindowByClass[state.Class] = struct{}{}
			}
		}
	}
	for _, batch := range accounting {
		if err := batch.Validate(); err != nil {
			return fmt.Errorf("validate coverage telemetry accounting: %w", err)
		}
		if batch.AgentID != request.AgentID || batch.AssetID != request.AssetID ||
			batch.ToAt.Before(request.Since) || !batch.FromAt.Before(request.Until) {
			return fmt.Errorf("%w: coverage accounting is outside requested identity or interval", shared.ErrValidation)
		}
	}
	for _, gap := range gaps {
		if err := gap.Validate(); err != nil {
			return fmt.Errorf("validate coverage gap: %w", err)
		}
		if gap.AgentID != request.AgentID || gap.AssetID != request.AssetID ||
			gap.ToAt.Before(request.Since) || !gap.FromAt.Before(request.Until) {
			return fmt.Errorf("%w: coverage gap is outside requested identity or interval", shared.ErrValidation)
		}
	}
	return nil
}

func canonicalizeSources(
	observations []sensorstate.Observation,
	accounting []ports.TelemetryBatchAccounting,
	gaps []ports.CoverageGapFact,
) {
	for i := range observations {
		observations[i] = sensorstate.NormalizeObservation(observations[i])
	}
	for i := range accounting {
		accounting[i].FromAt = canonicalTime(accounting[i].FromAt)
		accounting[i].ToAt = canonicalTime(accounting[i].ToAt)
	}
	for i := range gaps {
		gaps[i].FromAt = canonicalTime(gaps[i].FromAt)
		gaps[i].ToAt = canonicalTime(gaps[i].ToAt)
		gaps[i].RecordedAt = canonicalTime(gaps[i].RecordedAt)
	}
}

func canonicalTime(at time.Time) time.Time {
	return at.UTC().Truncate(time.Microsecond)
}

func checkedAdd(total *int, value int) bool {
	if value < 0 || *total > int(^uint(0)>>1)-value {
		return false
	}
	*total += value
	return true
}

func conservativeStates(observations []sensorstate.Observation) []detection.ClassCoverage {
	byClass := make(map[detection.Class]detection.ClassCoverage)
	for _, observation := range observations {
		for _, state := range observation.States {
			current, exists := byClass[state.Class]
			if !exists || coverageStateWorse(state, current) {
				byClass[state.Class] = state
			}
		}
	}
	states := make([]detection.ClassCoverage, 0, len(byClass))
	for _, state := range byClass {
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Class < states[j].Class })
	return states
}

func coverageStateWorse(candidate, current detection.ClassCoverage) bool {
	candidateRank := coverageStateRank(candidate.State)
	currentRank := coverageStateRank(current.State)
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}
	if !candidate.Since.Equal(current.Since) {
		return candidate.Since.Before(current.Since)
	}
	if candidate.Reason != current.Reason {
		return candidate.Reason < current.Reason
	}
	return candidate.AgentID < current.AgentID
}

func coverageStateRank(state detection.ClassState) int {
	switch state {
	case detection.StateFailed:
		return 4
	case detection.StateDisabled:
		return 3
	case detection.StateDegraded:
		return 2
	case detection.StateActive:
		return 1
	default:
		return 5
	}
}

func scoredGapCount(facts []ports.CoverageGapFact) int {
	seen := make(map[string]struct{}, len(facts))
	for _, fact := range facts {
		key := "fact:" + string(fact.Source) + ":" + fact.FactID.String()
		if fact.KnownSequence {
			key = strings.Join([]string{
				"coordinate", fact.AgentID.String(), fact.AssetID.String(), fact.StreamID.String(),
				strconv.Itoa(int(fact.Priority)), strconv.FormatUint(fact.Epoch, 10),
				strconv.FormatUint(fact.FromSequence, 10), strconv.FormatUint(fact.ToSequence, 10),
			}, "\x00")
		}
		seen[key] = struct{}{}
	}
	return len(seen)
}

func inputDigest(
	observations []sensorstate.Observation,
	accounting []ports.TelemetryBatchAccounting,
	gaps []ports.CoverageGapFact,
) string {
	facts := make([]string, 0, len(observations)+len(accounting)+len(gaps))
	for _, observation := range observations {
		states := append([]detection.ClassCoverage(nil), observation.States...)
		sort.Slice(states, func(i, j int) bool {
			if states[i].Class != states[j].Class {
				return states[i].Class < states[j].Class
			}
			return coverageStateCanonical(states[i]) < coverageStateCanonical(states[j])
		})
		parts := []string{
			"sensor", observation.ReportID.String(), observation.AgentID.String(), observation.AssetID.String(),
			observation.HostID.String(), string(observation.Kind), observation.ObservedAt.UTC().Format(time.RFC3339Nano),
			strconv.Itoa(observation.SchemaVersion), observation.PayloadDigest, observation.SignedContentDigest,
		}
		for _, state := range states {
			parts = append(parts, coverageStateCanonical(state))
		}
		facts = append(facts, strings.Join(parts, "\x00"))
	}
	for _, batch := range accounting {
		facts = append(facts, strings.Join([]string{
			"batch", batch.AgentID.String(), batch.AssetID.String(), batch.StreamID.String(), batch.BatchID.String(),
			strconv.Itoa(int(batch.Priority)), strconv.FormatUint(batch.Epoch, 10), strconv.FormatUint(batch.Sequence, 10),
			strconv.Itoa(batch.ObservedCount), strconv.Itoa(batch.KeptCount), strconv.Itoa(batch.SampledOutCount),
			strconv.Itoa(batch.TruncatedCount), strconv.Itoa(batch.DroppedCount), batch.SamplingPolicyDigest,
			batch.FromAt.UTC().Format(time.RFC3339Nano), batch.ToAt.UTC().Format(time.RFC3339Nano),
		}, "\x00"))
	}
	for _, gap := range gaps {
		facts = append(facts, strings.Join([]string{
			"gap", string(gap.Source), gap.FactID.String(), gap.AgentID.String(), gap.AssetID.String(), gap.StreamID.String(),
			strconv.Itoa(int(gap.Priority)), strconv.FormatUint(gap.Epoch, 10), strconv.FormatBool(gap.KnownSequence),
			strconv.FormatUint(gap.FromSequence, 10), strconv.FormatUint(gap.ToSequence, 10), strconv.FormatUint(gap.Count, 10),
			gap.Reason, gap.FromAt.UTC().Format(time.RFC3339Nano), gap.ToAt.UTC().Format(time.RFC3339Nano),
			gap.RecordedAt.UTC().Format(time.RFC3339Nano),
		}, "\x00"))
	}
	sort.Strings(facts)
	h := sha256.New()
	for _, fact := range facts {
		_, _ = h.Write([]byte(fact))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func coverageStateCanonical(state detection.ClassCoverage) string {
	return strings.Join([]string{
		string(state.Class), state.HostID.String(), state.AgentID.String(), string(state.State),
		state.Reason, state.Since.UTC().Format(time.RFC3339Nano),
	}, "\x00")
}
