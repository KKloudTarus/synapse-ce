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
	gobinbenchmark.AssertMainCalls(t, "configureWorkerJudgmentScanners")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gobinbenchmark.Run(t, "worker", func(scaService *scauc.Service, judgmentSvc *analysisuc.Service, audit ports.AuditLogger, clock ports.Clock, enabled, judgmentsEnabled bool) error {
		return configureWorkerJudgmentScanners(scaService, config.Config{GoBinaryReachabilityEnabled: enabled, JudgmentsEnabled: judgmentsEnabled}, nil, func() (*analysisuc.Service, error) {
			return judgmentSvc, nil
		}, audit, clock, log)
	})
}
