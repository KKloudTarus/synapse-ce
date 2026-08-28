package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type CoverageWindowStore struct {
	mu   sync.Mutex
	rows map[shared.ID]map[string]sensorstate.CoverageWindow
}

var _ ports.CoverageWindowStore = (*CoverageWindowStore)(nil)

func NewCoverageWindowStore() *CoverageWindowStore {
	return &CoverageWindowStore{rows: map[shared.ID]map[string]sensorstate.CoverageWindow{}}
}

func (s *CoverageWindowStore) AppendCoverageWindow(ctx context.Context, window sensorstate.CoverageWindow) (sensorstate.CoverageWindow, error) {
	window = normalizeMemoryCoverageWindow(window)
	if err := window.Validate(); err != nil {
		return sensorstate.CoverageWindow{}, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return sensorstate.CoverageWindow{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[tenant] == nil {
		s.rows[tenant] = map[string]sensorstate.CoverageWindow{}
	}
	if current, exists := s.rows[tenant][window.Revision]; exists {
		if !sameCoverageWindowFacts(current, window) {
			return sensorstate.CoverageWindow{}, fmt.Errorf("%w: coverage revision is already committed to different facts", shared.ErrConflict)
		}
		return cloneCoverageWindow(current), nil
	}
	s.rows[tenant][window.Revision] = cloneCoverageWindow(window)
	return cloneCoverageWindow(window), nil
}

func (s *CoverageWindowStore) ListCoverageWindows(ctx context.Context, q ports.CoverageWindowQuery) ([]sensorstate.CoverageWindow, error) {
	if !q.Valid() {
		return nil, fmt.Errorf("%w: coverage window query has invalid interval or limit", shared.ErrValidation)
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sensorstate.CoverageWindow, 0)
	for _, window := range s.rows[tenant] {
		if (!q.AgentID.IsZero() && window.AgentID != q.AgentID) ||
			(!q.AssetID.IsZero() && window.AssetID != q.AssetID) ||
			(!q.HostID.IsZero() && window.HostID != q.HostID) ||
			(!q.Since.IsZero() && !window.Until.After(q.Since.UTC())) ||
			(!q.Until.IsZero() && !window.Since.Before(q.Until.UTC())) {
			continue
		}
		out = append(out, cloneCoverageWindow(window))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Since.Equal(out[j].Since) {
			return out[i].Since.After(out[j].Since)
		}
		if !out[i].Until.Equal(out[j].Until) {
			return out[i].Until.After(out[j].Until)
		}
		return out[i].Revision > out[j].Revision
	})
	limit := q.EffectiveLimit()
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func normalizeMemoryCoverageWindow(window sensorstate.CoverageWindow) sensorstate.CoverageWindow {
	window.CreatedAt = window.CreatedAt.UTC().Truncate(time.Microsecond)
	return window
}

func sameCoverageWindowFacts(a, b sensorstate.CoverageWindow) bool {
	return a.AssetID == b.AssetID && a.AgentID == b.AgentID && a.HostID == b.HostID &&
		a.Since.Equal(b.Since) && a.Until.Equal(b.Until) && a.InputDigest == b.InputDigest &&
		a.Revision == b.Revision && a.SampledCount == b.SampledCount &&
		a.TruncatedCount == b.TruncatedCount && a.DroppedCount == b.DroppedCount &&
		a.GapCount == b.GapCount && a.BatchCount == b.BatchCount &&
		sameCoverageStates(a.States, b.States) && sameCoverageVector(a, b)
}

func sameCoverageStates(a, b []detection.ClassCoverage) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]detection.ClassCoverage(nil), a...)
	right := append([]detection.ClassCoverage(nil), b...)
	sortCoverageStates := func(states []detection.ClassCoverage) {
		sort.Slice(states, func(i, j int) bool {
			if states[i].Class != states[j].Class {
				return states[i].Class < states[j].Class
			}
			if !states[i].Since.Equal(states[j].Since) {
				return states[i].Since.Before(states[j].Since)
			}
			if states[i].State != states[j].State {
				return states[i].State < states[j].State
			}
			return states[i].Reason < states[j].Reason
		})
	}
	sortCoverageStates(left)
	sortCoverageStates(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sameCoverageVector(a, b sensorstate.CoverageWindow) bool {
	if a.Vector.Process != b.Vector.Process || a.Vector.Network != b.Vector.Network ||
		a.Vector.File != b.Vector.File || a.Vector.Privilege != b.Vector.Privilege ||
		len(a.Vector.Reasons) != len(b.Vector.Reasons) {
		return false
	}
	for i := range a.Vector.Reasons {
		if a.Vector.Reasons[i] != b.Vector.Reasons[i] {
			return false
		}
	}
	return true
}

func cloneCoverageWindow(window sensorstate.CoverageWindow) sensorstate.CoverageWindow {
	window.States = append([]detection.ClassCoverage(nil), window.States...)
	window.Vector.Reasons = append([]string(nil), window.Vector.Reasons...)
	return window
}
