// Command synapse-mcp exposes Synapse's agent tool catalog to external AI clients over the
// Model Context Protocol. It is a composition root only: it builds the
// read-only catalog over the SAME repos as the API, bearer-locks the endpoint (role "mcp"),
// pins it to one engagement, and serves JSON-RPC over Streamable HTTP. It coexists with the
// API + worker via a role-scoped single-instance lock. The MCP path has no executor and no
// safety gate, so it can only read + propose – never run a tool.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/mcpserver"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/file"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	recontools "github.com/KKloudTarus/synapse-ce/internal/infrastructure/recon"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/httpserver"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func main() {
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	log.Info("starting synapse-mcp", "env", cfg.Environment)

	// Fail closed: a token + a target engagement are required (no anonymous, no global scope).
	if cfg.MCPToken == "" {
		log.Error("synapse-mcp requires SYNAPSE_MCP_TOKEN (bearer auth, role-locked)")
		os.Exit(1)
	}
	if cfg.MCPEngagementID == "" {
		log.Error("synapse-mcp requires SYNAPSE_MCP_ENGAGEMENT_ID (the engagement it is scoped to)")
		os.Exit(1)
	}

	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}

	// Read-only catalog dependencies: findings + evidence + audit. Postgres (shared with the
	// API) when configured, else in-memory/file for dev.
	var findingRepo ports.FindingRepository
	var evidenceStore ports.EvidenceStore
	var auditLog ports.AuditLogger
	if cfg.DBDSN != "" {
		startup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := postgres.Migrate(startup, cfg.DBDSN); err != nil {
			log.Error("db migrate failed", "err", err)
			os.Exit(1)
		}
		pool, err := postgres.Connect(startup, cfg.DBDSN)
		if err != nil {
			log.Error("db connect failed", "err", err)
			os.Exit(1)
		}
		defer pool.Close()
		lockConn, ok, lerr := postgres.AcquireSingletonLock(startup, pool, "mcp")
		if lerr != nil {
			log.Error("mcp single-instance lock check failed", "err", lerr)
			os.Exit(1)
		}
		if !ok {
			log.Error("another synapse-mcp holds the single-instance lock – run ONE per role")
			os.Exit(1)
		}
		defer lockConn.Release()
		findingRepo = postgres.NewFindingRepository(pool)
		evidenceStore = postgres.NewEvidenceStore(pool)
		auditLog = postgres.NewAuditLog(pool)
		log.Info("persistence: postgres")
	} else {
		findingRepo = memory.NewFindingRepository()
		evidenceStore = memory.NewEvidenceStore()
		auditLog = file.NewAuditLog(cfg.AuditFile)
		log.Warn("persistence: in-memory (set SYNAPSE_DB_DSN to serve the API's data)")
	}

	reconToolList := make([]ports.ReconTool, 0, len(recontools.Registry()))
	for _, t := range recontools.Registry() {
		reconToolList = append(reconToolList, t)
	}
	catalog, err := agenttools.New(findingRepo, evidenceStore, reconToolList, auditLog, clock, ids)
	if err != nil {
		log.Error("agent catalog init failed", "err", err)
		os.Exit(1)
	}
	srv, err := mcpserver.New(catalog, shared.ID(cfg.MCPEngagementID), cfg.MCPToken, buildinfo.App(), log)
	if err != nil {
		log.Error("mcp server init failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("synapse-mcp listening", "addr", cfg.MCPAddr, "engagement", cfg.MCPEngagementID)
	if err := httpserver.Run(ctx, cfg.MCPAddr, srv.Handler(), log); err != nil {
		log.Error("mcp server error", "err", err)
		os.Exit(1)
	}
	log.Info("synapse-mcp stopped")
}
