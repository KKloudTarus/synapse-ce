package scacompose

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jvmreach"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// reachabilityLifecycle is the judgment-service slice needed by the reachproof coordinator. The existing
// ConfigureJudgmentScanners parameter is intentionally only the narrower TaintProposer; the concrete
// analysis.Service supplied by API/worker satisfies both, and this type assertion keeps the taint contract
// from widening just because JVM reachability needs verify/list.
type reachabilityLifecycle interface {
	TaintProposer
	Verify(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error)
	List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

func configureJVMTier2(svc *scauc.Service, cfg config.Config, proposer TaintProposer, audit ports.AuditLogger, clock ports.Clock, log *slog.Logger) error {
	if svc == nil || proposer == nil || !cfg.JVMReachabilityEnabled {
		return nil
	}
	recorder, ok := proposer.(reachabilityLifecycle)
	if !ok {
		return fmt.Errorf("JVM Tier-2 reachability requires the full judgment lifecycle")
	}
	pointsTo := cfg.JVMTier2PointsToEnabled()
	coord, err := reachproof.NewJVMTier2Coordinator(jvmreach.NewTier2(pointsTo), recorder, audit, clock)
	if err != nil {
		return fmt.Errorf("JVM Tier-2 reachability init: %w", err)
	}
	// Do not replace the Go Tier-2 recorder if it is already configured. The SCA service composes both and
	// runs them independently over the same affected-symbol set; each language engine ignores what it cannot
	// positively prove.
	svc.AddReachabilityRecorder(coord)
	mode := "CHA"
	if pointsTo {
		mode = "CHA + opt-in Andersen points-to"
	}
	if log != nil {
		log.Info("JVM TIER-2 bytecode reachability ENABLED (raise-only; never not_affected)", "dispatch", mode)
	}
	return nil
}
