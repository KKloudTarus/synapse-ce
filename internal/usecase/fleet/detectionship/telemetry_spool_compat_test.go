package detectionship

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (m *memorySpool) AckGap(context.Context, ports.SpoolGap) (bool, error) {
	return true, nil
}
