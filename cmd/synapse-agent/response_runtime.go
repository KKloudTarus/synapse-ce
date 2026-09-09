package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responseactuator"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsejournal"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsekey"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseexecute"
)

// endpointResponseRuntime owns process-lifetime trust, pidfds, and journal dependencies. The service
// identity is bound later, after enrollment has returned the canonical agent and asset IDs.
type endpointResponseRuntime struct {
	mu       sync.Mutex
	keys     *responsekey.Resolver
	journal  *responsejournal.Store
	registry *responseactuator.Registry
	actuator *responseactuator.Actuator
	executor responseCommandExecutor
	agentID  shared.ID
	assetID  shared.ID
}

func newEndpointResponseRuntime(cfg config) (*endpointResponseRuntime, error) {
	if !cfg.responseEnabled {
		return nil, nil
	}
	classes, err := parseDetectClasses(cfg.detectClasses)
	if err != nil {
		return nil, err
	}
	processCoverage := false
	for _, class := range classes {
		if class == detection.ClassProcess {
			processCoverage = true
			break
		}
	}
	if !processCoverage {
		return nil, fmt.Errorf("%w: live process response requires SYNAPSE_DETECT_CLASSES to include process", shared.ErrValidation)
	}
	keys, err := responsekey.LoadFile(cfg.responseTrustFile)
	if err != nil {
		return nil, err
	}
	journal, err := responsejournal.New(cfg.stateDir)
	if err != nil {
		return nil, err
	}
	registry, err := responseactuator.NewRegistry()
	if err != nil {
		return nil, err
	}
	actuator, err := responseactuator.New(registry)
	if err != nil {
		_ = registry.Close()
		return nil, err
	}
	return &endpointResponseRuntime{keys: keys, journal: journal, registry: registry, actuator: actuator}, nil
}

func (r *endpointResponseRuntime) executorFor(agentID, assetID shared.ID) (responseCommandExecutor, error) {
	if r == nil || r.keys == nil || r.journal == nil || r.registry == nil || r.actuator == nil {
		return nil, fmt.Errorf("%w: endpoint response runtime is incomplete", shared.ErrValidation)
	}
	if agentID.IsZero() || assetID.IsZero() {
		return nil, fmt.Errorf("%w: endpoint response identity is incomplete", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.executor != nil {
		if r.agentID != agentID || r.assetID != assetID {
			return nil, fmt.Errorf("%w: endpoint response identity changed after runtime binding", shared.ErrConflict)
		}
		return r.executor, nil
	}
	executor, err := responseexecute.NewService(agentID, assetID, r.keys, r.journal, r.actuator, idgen.SystemClock{})
	if err != nil {
		return nil, err
	}
	r.executor, r.agentID, r.assetID = executor, agentID, assetID
	return executor, nil
}

func (r *endpointResponseRuntime) Close() error {
	if r == nil || r.registry == nil {
		return nil
	}
	return r.registry.Close()
}

func envEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
