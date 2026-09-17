//go:build !linux

package main

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsejournal"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsekey"
)

func assembleEndpointResponseRuntime(*responsekey.Resolver, *responsejournal.Store) (*endpointResponseRuntime, error) {
	return nil, fmt.Errorf("%w: live process response is supported only on Linux", shared.ErrForbidden)
}
