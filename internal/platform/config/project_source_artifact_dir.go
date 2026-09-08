package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Uploaded archives are original evidence, not a disposable source-preview cache.
// Keep the default in persistent application data outside scanned workspaces.
func engagementSourceDir() string {
	if configured := strings.TrimSpace(os.Getenv("SYNAPSE_ENGAGEMENT_SOURCE_DIR")); configured != "" {
		return configured
	}
	if root, err := os.UserConfigDir(); err == nil && filepath.IsAbs(root) {
		return filepath.Join(root, "synapse", "engagement-sources")
	}
	// No temporary-directory fallback: an unavailable durable root must surface
	// as a configuration error, not silently lose uploads on restart.
	return ""
}

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
