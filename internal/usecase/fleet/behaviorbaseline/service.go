// Package behaviorbaseline turns the B5 per-host running-process projection plus the host's sealed
// runtime detections into the coverage-honest RiskContext.Behavior factor (#594 D). It maps a host's
// running processes to the process features of a baseline.Observation, and folds the per-class rate of
// the eBPF detections observed on that host in a recent window into the network / privilege / file
// features, so the statistical baseline scores anomalies over runtime telemetry rather than over
// process snapshots alone (#822). It LEARNS the asset's normal profile at report time (baselineuc.Observe,
// which scores-then-folds with anti-poisoning) and SCORES the current profile read-only at
// risk-assessment time (baselineuc.Score, no fold). Learning and scoring are separated so scoring never
// poisons the baseline, and the risk-assessment path (an incident is active) never learns.
package behaviorbaseline

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/baselineuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// defaultDetectionWindow bounds how far back the per-class detection rate is counted for an observation.
// A day balances "recent enough to reflect current behavior" against "long enough for a sparse host to
// register any runtime signal at all".
const defaultDetectionWindow = 24 * time.Hour

// BaselineEngine is the baselineuc surface this producer needs: Observe (learn+score) and Score (read-only).
type BaselineEngine interface {
	Observe(ctx context.Context, actor string, key baseline.Key, obs baseline.Observation, window baseline.LearnWindow) (baselineuc.Assessment, error)
	Score(ctx context.Context, key baseline.Key, obs baseline.Observation) (baselineuc.Assessment, error)
	Rebaseline(ctx context.Context, actor string, key baseline.Key) error
}

// ProcessLister returns an asset's currently-running processes. ports.EndpointProcessStore satisfies it.
type ProcessLister interface {
	ListRunningByAsset(ctx context.Context, assetID shared.ID) ([]ports.ProcessSnapshot, error)
}

// DetectionRates returns the count of sealed detections observed on an asset since a cutoff, grouped by
// telemetry class, tenant-scoped by ctx. It is OPTIONAL: a nil DetectionRates leaves the network,
// privilege and file features unobserved (0), which is the pre-#822 behavior. The memory and Postgres
// detection-record stores satisfy it.
type DetectionRates interface {
	ClassCountsByAsset(ctx context.Context, assetID shared.ID, since time.Time) (map[detection.Class]int, error)
}

// Factor is the coverage-honest Behavior factor for one asset.
type Factor struct {
	Behavior  int
	Scoreable bool
	Reasons   []string
}

// Service produces + learns the Behavior factor from process snapshots and runtime detection rates.
type Service struct {
	engine     BaselineEngine
	processes  ProcessLister
	detections DetectionRates // optional; nil leaves network/privilege/file features at 0
	now        func() time.Time
	window     time.Duration
}

// NewService constructs the producer. The engine and process lister are required. detections is optional
// (nil = process features only); now defaults to time.Now and window to a day when zero.
func NewService(engine BaselineEngine, processes ProcessLister, detections DetectionRates, now func() time.Time, window time.Duration) (*Service, error) {
	if engine == nil || processes == nil {
		return nil, fmt.Errorf("%w: behavior baseline needs a baseline engine and a process lister", shared.ErrValidation)
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if window <= 0 {
		window = defaultDetectionWindow
	}
	return &Service{engine: engine, processes: processes, detections: detections, now: now, window: window}, nil
}

// Learn folds the asset's current running-process profile into its behavior baseline. It is called at
// process-report time — NOT during incident reassessment — so the baseline learns from ordinary activity;
// baselineuc's anti-poisoning still refuses to fold an anomalous window. A learn failure is the caller's
// to treat as best-effort (the process report itself already succeeded).
func (s *Service) Learn(ctx context.Context, actor string, assetID shared.ID) error {
	key, obs, err := s.observe(ctx, assetID)
	if err != nil {
		return err
	}
	// The window: we just received a process snapshot, so process-class coverage was active for it; the
	// bad-condition flags are for the risk-assessment path, not ordinary reporting. Anti-poisoning in
	// Observe still refuses to fold an anomalous observation.
	window := baseline.LearnWindow{Coverage: 100, MinCoverage: 1}
	_, err = s.engine.Observe(ctx, actor, key, obs, window)
	return err
}

// BehaviorFor scores the asset's current running-process profile against its baseline, read-only. It is
// the assembler's Behavior producer: abstains until the baseline is active, and never learns (scoring on
// the incident path must not poison the baseline).
func (s *Service) BehaviorFor(ctx context.Context, assetID shared.ID) (Factor, error) {
	key, obs, err := s.observe(ctx, assetID)
	if err != nil {
		return Factor{}, err
	}
	a, err := s.engine.Score(ctx, key, obs)
	if err != nil {
		return Factor{}, err
	}
	return Factor{Behavior: int(a.Behavior), Scoreable: a.Scoreable, Reasons: a.Reasons}, nil
}

// Rebaseline drives a drifted or poisoned behavior baseline for one host asset through a clean
// re-baseline (reset_pending -> learning), so a baseline that latched on drift re-learns from fresh
// windows instead of abstaining forever. Audited by the underlying engine. It needs no process
// observation — it acts on the stored baseline for the asset's key.
func (s *Service) Rebaseline(ctx context.Context, actor string, assetID shared.ID) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant == "" {
		return fmt.Errorf("%w: behavior baseline requires a tenant in context", shared.ErrValidation)
	}
	if assetID.IsZero() {
		return fmt.Errorf("%w: behavior baseline requires an asset id", shared.ErrValidation)
	}
	return s.engine.Rebaseline(ctx, actor, baseline.Key{Tenant: tenant, Group: assetID.String()})
}

func (s *Service) observe(ctx context.Context, assetID shared.ID) (baseline.Key, baseline.Observation, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant == "" {
		return baseline.Key{}, baseline.Observation{}, fmt.Errorf("%w: behavior baseline requires a tenant in context", shared.ErrValidation)
	}
	if assetID.IsZero() {
		return baseline.Key{}, baseline.Observation{}, fmt.Errorf("%w: behavior baseline requires an asset id", shared.ErrValidation)
	}
	procs, err := s.processes.ListRunningByAsset(ctx, assetID)
	if err != nil {
		return baseline.Key{}, baseline.Observation{}, fmt.Errorf("list running processes: %w", err)
	}
	// Fold the recent per-class detection rate when a detection source is wired. A store hiccup is
	// best-effort: it must not blind the process-based baseline, so the counts fall back to nil (0).
	var counts map[detection.Class]int
	if s.detections != nil {
		if c, cerr := s.detections.ClassCountsByAsset(ctx, assetID, s.now().Add(-s.window)); cerr == nil {
			counts = c
		}
	}
	return baseline.Key{Tenant: tenant, Group: assetID.String()}, observationFrom(procs, counts), nil
}

// observationFrom maps running processes to the process features (count as a spawn-rate proxy, distinct
// exec paths) and the recent per-class detection rate to the network / privilege / file features. Values
// are clamped to the feature max. A nil counts map leaves the detection-fed features at 0.
func observationFrom(procs []ports.ProcessSnapshot, counts map[detection.Class]int) baseline.Observation {
	paths := make(map[string]struct{}, len(procs))
	for _, p := range procs {
		if p.Path != "" {
			paths[p.Path] = struct{}{}
		}
	}
	var o baseline.Observation
	o.Values[baseline.FeatureProcessSpawnRate] = clampFeature(int64(len(procs)))
	o.Values[baseline.FeatureNewExecPaths] = clampFeature(int64(len(paths)))
	if counts != nil {
		o.Values[baseline.FeatureNetworkFanout] = clampFeature(int64(counts[detection.ClassNetwork]))
		o.Values[baseline.FeaturePrivilegeEvents] = clampFeature(int64(counts[detection.ClassPrivilege]))
		o.Values[baseline.FeatureFileWriteBreadth] = clampFeature(int64(counts[detection.ClassFile]))
	}
	return o
}

func clampFeature(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > baseline.MaxFeatureValue {
		return baseline.MaxFeatureValue
	}
	return v
}
