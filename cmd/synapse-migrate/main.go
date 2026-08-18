// Command synapse-migrate applies the embedded PostgreSQL migration set once.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
)

func main() {
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	if cfg.DBDSN == "" {
		log.Error("synapse-migrate requires SYNAPSE_DB_DSN")
		os.Exit(1)
	}

	migrationDSN := cfg.MigrationDSN()
	if cfg.IsProduction() {
		if cfg.DBMigrationDSN == "" {
			log.Error("SYNAPSE_DB_MIGRATION_DSN is required with SYNAPSE_DB_DSN outside development")
			os.Exit(1)
		}
		if err := postgres.ValidateMigrationRoleSeparation(migrationDSN, cfg.DBDSN); err != nil {
			log.Error("database migration configuration invalid", "err", fmt.Errorf("validate migration and runtime database roles: %w", err))
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	started := time.Now()
	if err := postgres.MigrateLocked(ctx, migrationDSN); err != nil {
		log.Error("db migrate failed", "err", err)
		os.Exit(1)
	}
	if migrationDSN != cfg.DBDSN {
		if err := postgres.GrantRuntimePrivileges(ctx, migrationDSN, cfg.DBDSN); err != nil {
			log.Error("db runtime role grant failed", "err", err)
			os.Exit(1)
		}
	}
	log.Info("db migrations complete", "duration", time.Since(started))
}
