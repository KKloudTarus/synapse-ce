// Package behaviorbaseline turns the B5 per-host running-process projection into the coverage-honest
// RiskContext.Behavior factor (#594 D). It maps a host's running processes to a baseline.Observation,
// LEARNS the asset's normal process profile at report time (baselineuc.Observe — which scores-then-folds
// with anti-poisoning), and SCORES the current profile read-only at risk-assessment time
// (baselineuc.Score, no fold). Learning and scoring are separated so scoring never poisons the baseline —
// and, critically, the risk-assessment path (an incident is active) never learns.
//
// It observes only the two features a process snapshot honestly carries — process count (spawn-rate proxy)
// and distinct exec paths — leaving the network/privilege/file features at 0 (unobserved from processes),
// so the baseline never invents a signal it did not measure.
package behaviorbaseline

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/baselineuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// BaselineEngine is the baselineuc surface this producer needs: Observe (learn+score) and Score (read-only).
type BaselineEngine interface {
	Observe(ctx context.Context, actor string, key baseline.Key, obs baseline.Observation, window baseline.LearnWindow) (baselineuc.Assessment, error)
	Score(ctx context.Context, key baseline.Key, obs baseline.Observation) (baselineuc.Assessment, error)
}

// ProcessLister returns an asset's currently-running processes. ports.EndpointProcessStore satisfies it.
type ProcessLister interface {
	ListRunningByAsset(ctx context.Context, assetID shared.ID) ([]ports.ProcessSnapshot, error)
}

// Factor is the coverage-honest Behavior factor for one asset.
type Factor struct {
	Behavior  int
	Scoreable bool
	Reasons   []string
}

// Service produces + learns the Behavior factor from process snapshots.
type Service struct {
	engine    BaselineEngine
	processes ProcessLister
}

// NewService constructs the producer. Both collaborators are required.
func NewService(engine BaselineEngine, processes ProcessLister) (*Service, error) {
	if engine == nil || processes == nil {
		return nil, fmt.Errorf("%w: behavior baseline needs a baseline engine and a process lister", shared.ErrValidation)
	}
	return &Service{engine: engine, processes: processes}, nil
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
	return baseline.Key{Tenant: tenant, Group: assetID.String()}, observationFrom(procs), nil
}

// observationFrom maps running processes to the two baseline features a process snapshot honestly carries:
// process count (spawn-rate proxy) and distinct exec paths. Values are clamped to the feature max.
func observationFrom(procs []ports.ProcessSnapshot) baseline.Observation {
	paths := make(map[string]struct{}, len(procs))
	for _, p := range procs {
		if p.Path != "" {
			paths[p.Path] = struct{}{}
		}
	}
	var o baseline.Observation
	o.Values[baseline.FeatureProcessSpawnRate] = clampFeature(int64(len(procs)))
	o.Values[baseline.FeatureNewExecPaths] = clampFeature(int64(len(paths)))
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
