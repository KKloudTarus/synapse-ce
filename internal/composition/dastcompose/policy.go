// Package dastcompose shares the configured authenticated-scan policy between service roots.
package dastcompose

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastconfig"
)

type ScanPolicy struct {
	HelperPath   string
	HelperSHA256 string
	Ceilings     dastconfig.ScanCeilings
}

// ConfiguredScanPolicy reads authority from operator configuration, never a worker request.
// The API does not need to install or execute the worker's configured helper.
func ConfiguredScanPolicy(cfg *config.Config) (ScanPolicy, error) {
	if !filepath.IsAbs(cfg.DASTHelperBin) || filepath.Clean(cfg.DASTHelperBin) != cfg.DASTHelperBin {
		return ScanPolicy{}, fmt.Errorf("%w: authenticated DAST requires a canonical absolute helper path", shared.ErrValidation)
	}
	pin, ok := cfg.ToolHashes[cfg.DASTHelperBin]
	if !ok {
		pin = cfg.ToolHashes[filepath.Base(cfg.DASTHelperBin)]
	}
	if len(pin) != 64 || strings.ToLower(pin) != pin {
		return ScanPolicy{}, fmt.Errorf("%w: authenticated DAST requires an authoritative SHA-256 helper pin", shared.ErrValidation)
	}
	if _, err := hex.DecodeString(pin); err != nil {
		return ScanPolicy{}, fmt.Errorf("%w: invalid authenticated DAST helper pin", shared.ErrValidation)
	}
	ceilings := dastconfig.DefaultScanCeilings()
	ceilings.MaxReauth, ceilings.RatePerSec, ceilings.Concurrency = cfg.DASTMaxReauth, cfg.DASTRatePerSec, cfg.DASTConcurrency
	ceilings.Limits.Depth, ceilings.Limits.Pages, ceilings.Limits.Requests, ceilings.Limits.WallClock = cfg.DASTMaxDepth, cfg.DASTMaxPages, cfg.DASTMaxRequests, cfg.DASTMaxWallClock
	return ScanPolicy{HelperPath: cfg.DASTHelperBin, HelperSHA256: pin, Ceilings: ceilings}, nil
}
