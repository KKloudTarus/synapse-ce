package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/gobinbenchmark"
	analysisuc "github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestCurrentGoBinaryBindingBenchmark(t *testing.T) {
	gobinbenchmark.AssertMainCalls(t, "configureAPIGoBinaryReachability")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gobinbenchmark.Run(t, "api", func(scaService *scauc.Service, judgmentSvc *analysisuc.Service, audit ports.AuditLogger, clock ports.Clock, enabled, judgmentsEnabled bool) error {
		if !judgmentsEnabled {
			judgmentSvc = nil
		}
		return configureAPIGoBinaryReachability(config.Config{GoBinaryReachabilityEnabled: enabled, JudgmentsEnabled: judgmentsEnabled}, scaService, judgmentSvc, audit, clock, log)
	})
}
