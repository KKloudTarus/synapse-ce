package memory

import (
	"context"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type cloudObservation struct {
	active     bool
	evidenceID shared.ID
}

// CloudObservationStore tracks producer-owned active observations in local development.
type CloudObservationStore struct {
	mu   sync.Mutex
	data map[string]cloudObservation
}

var _ ports.CloudObservationStore = (*CloudObservationStore)(nil)

func NewCloudObservationStore() *CloudObservationStore {
	return &CloudObservationStore{data: map[string]cloudObservation{}}
}

func memoryIDsToStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i := range ids {
		out[i] = ids[i].String()
	}
	return out
}

func (s *CloudObservationStore) FindingActive(tenantID, engagementID, findingID shared.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := tenantID.String() + "\x00" + engagementID.String() + "\x00"
	suffix := "\x00finding\x00" + findingID.String()
	for key, observation := range s.data {
		if strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix) && observation.active {
			return true
		}
	}
	return false
}

func (s *CloudObservationStore) ReconcileCloudObservations(_ context.Context, tenantID, engagementID shared.ID, producer string, evidenceID shared.ID, assets, findings []shared.ID, edges []string, complete bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := tenantID.String() + "\x00" + engagementID.String() + "\x00" + producer + "\x00"
	if complete {
		for key, observation := range s.data {
			if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
				observation.active = false
				s.data[key] = observation
			}
		}
	}
	for _, pair := range []struct {
		kind string
		ids  []string
	}{{"asset", memoryIDsToStrings(assets)}, {"finding", memoryIDsToStrings(findings)}, {"edge", edges}} {
		for _, id := range pair.ids {
			s.data[prefix+pair.kind+"\x00"+id] = cloudObservation{active: true, evidenceID: evidenceID}
		}
	}
	return nil
}
