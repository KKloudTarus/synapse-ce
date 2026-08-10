package config

import (
	"os"
	"path/filepath"
	"strings"
)

// projectSourceArtifactDir returns an operator-owned absolute default outside the process working
// tree. An explicit environment value is preserved so write adapters can fail closed on a relative
// configuration instead of silently rebasing it into an attacker-controlled checkout.
func projectSourceArtifactDir() string {
	if configured := strings.TrimSpace(os.Getenv("SYNAPSE_PROJECT_SOURCE_ARTIFACT_DIR")); configured != "" {
		return configured
	}
	if cache, err := os.UserCacheDir(); err == nil && filepath.IsAbs(cache) {
		return filepath.Join(cache, "synapse", "project-source-artifacts")
	}
	if tmp := os.TempDir(); filepath.IsAbs(tmp) {
		return filepath.Join(tmp, "synapse", "project-source-artifacts")
	}
	// filepath.Abs is the final portability fallback. It should be unreachable on supported hosts,
	// but still guarantees the downstream write-root invariant instead of returning a relative path.
	absolute, err := filepath.Abs(filepath.Join("data", "project-source-artifacts"))
	if err != nil {
		return ""
	}
	return absolute
}
