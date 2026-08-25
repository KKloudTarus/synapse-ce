package agentspool

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (c *captureSpool) AckGap(context.Context, ports.SpoolGap) (bool, error) {
	return true, nil
}
