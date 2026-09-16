//go:build linux

package main

import (
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responseactuator"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsejournal"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsekey"
)

func assembleEndpointResponseRuntime(keys *responsekey.Resolver, journal *responsejournal.Store) (*endpointResponseRuntime, error) {
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
