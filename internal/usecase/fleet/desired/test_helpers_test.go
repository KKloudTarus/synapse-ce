package fleetdesired_test

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type testIDGenerator struct {
	calls int
}

func (g *testIDGenerator) NewID() shared.ID {
	g.calls++
	return shared.ID(fmt.Sprintf("policy-%d", g.calls))
}
