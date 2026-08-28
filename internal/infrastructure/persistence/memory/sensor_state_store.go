package memory

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type SensorStateStore struct {
	mu            sync.Mutex
	rows          map[shared.ID]map[shared.ID]sensorstate.Observation
	auditIntents  map[fleetAuditKey]ports.FleetAuditIntent
	auditComplete map[fleetAuditKey]bool
}

var _ ports.SensorStateStore = (*SensorStateStore)(nil)
var _ ports.CoverageSensorStateReader = (*SensorStateStore)(nil)
var _ ports.SensorStateAuditStore = (*SensorStateStore)(nil)

func NewSensorStateStore() *SensorStateStore {
	return &SensorStateStore{
		rows:          map[shared.ID]map[shared.ID]sensorstate.Observation{},
		auditIntents:  make(map[fleetAuditKey]ports.FleetAuditIntent),
		auditComplete: make(map[fleetAuditKey]bool),
	}
}

func (s *SensorStateStore) AppendSensorState(ctx context.Context, observation sensorstate.Observation) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[tenant] == nil {
		s.rows[tenant] = map[shared.ID]sensorstate.Observation{}
	}
	observation = sensorstate.NormalizeObservation(observation)
	if previous, exists := s.rows[tenant][observation.ReportID]; exists {
		if !sensorstate.SameSignedObservation(previous, observation) {
			return fmt.Errorf("%w: sensor-state report id is already committed to different signed content", shared.ErrConflict)
		}
		return nil
	}
	s.rows[tenant][observation.ReportID] = observation
	return nil
}

func (s *SensorStateStore) AppendSensorStateWithAudit(
	ctx context.Context,
	observation sensorstate.Observation,
	intent ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	if err := observation.Validate(); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	intent, err = validateSensorStateAuditIntent(intent)
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	observation = sensorstate.NormalizeObservation(observation)
	auditKey := fleetAuditKey{tenant: tenant, id: intent.ID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existingIntent, ok := s.auditIntents[auditKey]; ok {
		intent.Entry.At = existingIntent.Entry.At
		if !sensorStateAuditIntentEqual(existingIntent, intent) {
			return ports.FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention id already has different immutable content", shared.ErrConflict)
		}
	}
	if s.rows[tenant] == nil {
		s.rows[tenant] = map[shared.ID]sensorstate.Observation{}
	}
	if previous, exists := s.rows[tenant][observation.ReportID]; exists {
		if !sensorstate.SameSignedObservation(previous, observation) {
			return ports.FleetAuditIntent{}, fmt.Errorf("%w: sensor-state report id is already committed to different signed content", shared.ErrConflict)
		}
	} else {
		s.rows[tenant][observation.ReportID] = observation
	}
	s.auditIntents[auditKey] = cloneSensorStateAuditIntent(intent)
	return cloneSensorStateAuditIntent(intent), nil
}

func (s *SensorStateStore) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.FleetAuditIntent, 0)
	for key, intent := range s.auditIntents {
		if key.tenant == tenant && !s.auditComplete[key] {
			out = append(out, cloneSensorStateAuditIntent(intent))
		}
	}
	slices.SortFunc(out, func(left, right ports.FleetAuditIntent) int {
		if order := left.Entry.At.Compare(right.Entry.At); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	return out, nil
}

func (s *SensorStateStore) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: fleet audit intention id is required", shared.ErrValidation)
	}
	key := fleetAuditKey{tenant: tenant, id: id}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.auditIntents[key]; !ok {
		return shared.ErrNotFound
	}
	s.auditComplete[key] = true
	return nil
}

// The sensor-state outbox shares the package-wide helpers rather than repeating
// them: three divergent copies of the same canonicalization is how one obligation
// ends up hashing differently in different code paths.
func validateSensorStateAuditIntent(intent ports.FleetAuditIntent) (ports.FleetAuditIntent, error) {
	return intent.Normalize()
}

func cloneSensorStateAuditIntent(intent ports.FleetAuditIntent) ports.FleetAuditIntent {
	return cloneMemoryFleetAuditIntent(intent)
}

func sensorStateAuditIntentEqual(left, right ports.FleetAuditIntent) bool {
	return ports.SameFleetAuditIntent(left, right)
}

func (s *SensorStateStore) ListSensorStates(ctx context.Context, q ports.SensorStateQuery) ([]sensorstate.Observation, error) {
	if !q.Valid() {
		return nil, fmt.Errorf("%w: sensor-state query until precedes since", shared.ErrValidation)
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sensorstate.Observation, 0)
	for _, observation := range s.rows[tenant] {
		if (!q.AgentID.IsZero() && observation.AgentID != q.AgentID) ||
			(!q.AssetID.IsZero() && observation.AssetID != q.AssetID) ||
			(!q.HostID.IsZero() && observation.HostID != q.HostID) ||
			(!q.Since.IsZero() && observation.ObservedAt.Before(q.Since.UTC())) ||
			(!q.Until.IsZero() && !observation.ObservedAt.Before(q.Until.UTC())) {
			continue
		}
		out = append(out, cloneSensorStateObservation(observation))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ReportID < out[j].ReportID
		}
		return out[i].ObservedAt.Before(out[j].ObservedAt)
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (s *SensorStateStore) ListCoverageSensorStates(ctx context.Context, q ports.CoverageSensorStateQuery) ([]sensorstate.Observation, error) {
	if !q.Valid() {
		return nil, fmt.Errorf("%w: coverage sensor-state query has invalid identity or half-open interval", shared.ErrValidation)
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	effectiveByClass := make(map[detection.Class]sensorstate.Observation)
	inWindow := make([]sensorstate.Observation, 0)
	for _, observation := range s.rows[tenant] {
		if observation.AgentID != q.AgentID || observation.AssetID != q.AssetID || observation.HostID != q.HostID {
			continue
		}
		at := observation.ObservedAt.UTC()
		if at.Before(q.Since.UTC()) {
			for _, state := range observation.States {
				effective, ok := effectiveByClass[state.Class]
				if !ok || effective.ObservedAt.Before(at) ||
					(effective.ObservedAt.Equal(at) && effective.ReportID < observation.ReportID) {
					effectiveByClass[state.Class] = cloneSensorStateObservation(observation)
				}
			}
			continue
		}
		if at.Before(q.Until.UTC()) {
			inWindow = append(inWindow, cloneSensorStateObservation(observation))
		}
	}

	effectiveByReport := make(map[shared.ID]sensorstate.Observation, len(effectiveByClass))
	for _, observation := range effectiveByClass {
		effectiveByReport[observation.ReportID] = observation
	}
	effective := make([]sensorstate.Observation, 0, len(effectiveByReport))
	for _, observation := range effectiveByReport {
		effective = append(effective, observation)
	}
	sort.Slice(effective, func(i, j int) bool {
		if effective[i].ObservedAt.Equal(effective[j].ObservedAt) {
			return effective[i].ReportID < effective[j].ReportID
		}
		return effective[i].ObservedAt.Before(effective[j].ObservedAt)
	})
	sort.Slice(inWindow, func(i, j int) bool {
		if inWindow[i].ObservedAt.Equal(inWindow[j].ObservedAt) {
			return inWindow[i].ReportID < inWindow[j].ReportID
		}
		return inWindow[i].ObservedAt.Before(inWindow[j].ObservedAt)
	})
	return append(effective, inWindow...), nil
}

func cloneSensorStateObservation(observation sensorstate.Observation) sensorstate.Observation {
	observation.States = append([]detection.ClassCoverage(nil), observation.States...)
	return observation
}
