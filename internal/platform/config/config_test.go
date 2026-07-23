package config

import (
	"testing"
	"time"
)

// TestIsProductionFailsClosed pins the env-gate hardening: IsProduction normalizes
// (trim + lowercase) and treats anything that is NOT an explicitly recognized
// non-production environment as production, so a misconfigured/misspelled env lands in
// the strict security gates (vault key, signing, sandbox) instead of silently failing
// open to ephemeral-key dev behavior. No caller may compare cfg.Environment directly.
func TestIsProductionFailsClosed(t *testing.T) {
	production := []string{
		"production", "Production", "PRODUCTION", " production ", "production\n",
		"prod", "PROD", "staging", "preprod", "prdo", "typo-env", "",
	}
	for _, e := range production {
		if !(Config{Environment: e}).IsProduction() {
			t.Errorf("env %q must be treated as production (fail closed)", e)
		}
	}
	nonProduction := []string{"development", "DEVELOPMENT", " dev ", "dev", "local", "test", "ci"}
	for _, e := range nonProduction {
		if (Config{Environment: e}).IsProduction() {
			t.Errorf("env %q must be treated as non-production", e)
		}
	}
}

// TestLoadNormalizesEnvironment confirms Load canonicalizes the env so logs + any reader
// see one form.
func TestLoadNormalizesEnvironment(t *testing.T) {
	t.Setenv("SYNAPSE_ENV", "  Production  ")
	if got := Load().Environment; got != "production" {
		t.Fatalf("Load must normalize SYNAPSE_ENV to %q, got %q", "production", got)
	}
}

// TestFindingMinSeverityDefaultsToInfo pins the default vuln severity floor at "info" so EVERY
// detected vulnerability is promoted to a finding (matching Grype/Trivy/OSV-Scanner). A higher
// default silently hides detected vulns and reads as "missing vulns"; prioritization is by risk
// priority (KEV→EPSS×CVSS), not by dropping findings. Do not raise this default.
func TestFindingMinSeverityDefaultsToInfo(t *testing.T) {
	t.Setenv("SYNAPSE_FINDING_MIN_SEVERITY", "")
	if got := Load().FindingMinSeverity; got != "info" {
		t.Fatalf("default FindingMinSeverity = %q, want \"info\" (promote all detected vulns)", got)
	}
	t.Setenv("SYNAPSE_FINDING_MIN_SEVERITY", "high")
	if got := Load().FindingMinSeverity; got != "high" {
		t.Fatalf("override = %q, want \"high\"", got)
	}
}

// TestLoadReachability confirms the Tier-2 reachability proof is ON by default (effective-by-default
// policy), that it can be opted out, and the govulncheck binary defaults sensibly.
func TestLoadReachability(t *testing.T) {
	t.Setenv("SYNAPSE_REACHABILITY_ENABLED", "")
	t.Setenv("SYNAPSE_GOVULNCHECK_BIN", "") // hermetic: ignore any binary override in the runner env
	if c := Load(); !c.ReachabilityEnabled {
		t.Error("reachability must be ON by default (effective-by-default)")
	}
	if got := Load().GovulncheckBin; got != "govulncheck" {
		t.Errorf("GovulncheckBin default = %q, want govulncheck", got)
	}
	t.Setenv("SYNAPSE_REACHABILITY_ENABLED", "false")
	if Load().ReachabilityEnabled {
		t.Error("SYNAPSE_REACHABILITY_ENABLED=false must disable it")
	}
}

// analysisDefaultOnEnv is the set of deterministic, best-effort capability flags that default ON so
// the tool is fully effective out of the box (the UI and a bare scan get the full feature set).
var analysisDefaultOnEnv = []string{
	"SYNAPSE_JUDGMENTS_ENABLED", "SYNAPSE_SAST_ENABLED", "SYNAPSE_SECRET_SCAN_ENABLED",
	"SYNAPSE_MISCONFIG_ENABLED", "SYNAPSE_SUPPRESSION_ENABLED", "SYNAPSE_VEX_ENABLED",
	"SYNAPSE_COMPLIANCE_ENABLED", "SYNAPSE_SCAN_CACHE_ENABLED", "SYNAPSE_IMAGE_ROOTFS_ENABLED",
	"SYNAPSE_OWNED_ADVISORY", "SYNAPSE_REACHABILITY_ENABLED", "SYNAPSE_CROSSCHECK_ENABLED",
	"SYNAPSE_SBOM_CROSSCHECK_ENABLED", "SYNAPSE_GOMODGRAPH_ENABLED", "SYNAPSE_JVM_REACHABILITY_ENABLED",
}

// TestAnalysisDefaultsOn pins the effective-by-default policy: every deterministic, best-effort
// analysis capability is ON unless the operator opts out. A regression that silently flips one back
// to opt-in would make the UI quietly stop running that scanner.
func TestAnalysisDefaultsOn(t *testing.T) {
	for _, k := range analysisDefaultOnEnv {
		t.Setenv(k, "") // hermetic: no override from the runner env
	}
	c := Load()
	on := map[string]bool{
		"Judgments": c.JudgmentsEnabled, "SAST": c.SASTEnabled, "SecretScan": c.SecretScanEnabled,
		"Misconfig": c.MisconfigEnabled, "Suppression": c.SuppressionEnabled, "VEX": c.VEXEnabled,
		"Compliance": c.ComplianceEnabled, "ScanCache": c.ScanCacheEnabled, "ImageRootFS": c.ImageRootFSEnabled,
		"OwnedAdvisory": c.OwnedAdvisoryEnabled, "Reachability": c.ReachabilityEnabled,
		"CrossCheck": c.CrossCheckEnabled, "SBOMCrossCheck": c.SBOMCrossCheckEnabled,
		"GoModGraph": c.GoModGraphEnabled, "JVMReachability": c.JVMReachabilityEnabled,
	}
	for name, v := range on {
		if !v {
			t.Errorf("%s must default ON (effective-by-default policy)", name)
		}
	}
	// And it stays opt-out-able.
	t.Setenv("SYNAPSE_SAST_ENABLED", "false")
	if Load().SASTEnabled {
		t.Error("SYNAPSE_SAST_ENABLED=false must disable it")
	}
}

// TestExternalSetupDefaultsOff pins that capabilities needing external setup, or unsafe when
// unsandboxed, stay OFF by default: a fresh server starts cleanly and never runs untrusted build
// logic or contacts an LLM without an explicit opt-in.
func TestExternalSetupDefaultsOff(t *testing.T) {
	for _, k := range []string{
		"SYNAPSE_SANDBOX_ENABLED", "SYNAPSE_AGENT_ENABLED", "SYNAPSE_TAINT_ENABLED",
		"SYNAPSE_MAVEN_RESOLVE_ENABLED", "SYNAPSE_GRADLE_RESOLVE_ENABLED", "SYNAPSE_JARHASH_ONLINE_ENABLED",
		"SYNAPSE_WRITEUP_DRAFTS_ENABLED", "SYNAPSE_OFFLINE", "SYNAPSE_IGNORE_UNFIXED",
	} {
		t.Setenv(k, "")
	}
	c := Load()
	off := map[string]bool{
		"Sandbox": c.SandboxEnabled, "Agent": c.AgentEnabled, "Taint": c.TaintEnabled,
		"MavenResolve": c.MavenResolveEnabled, "GradleResolve": c.GradleResolveEnabled,
		"JarHashOnline": c.JarHashOnlineEnabled, "WriteupDrafts": c.WriteupDraftsEnabled,
		"Offline": c.Offline, "IgnoreUnfixed": c.IgnoreUnfixed,
	}
	for name, v := range off {
		if v {
			t.Errorf("%s must default OFF (needs external setup / opt-in)", name)
		}
	}
}

// TestLoadSBOMProducer confirms the SBOM producer defaults to syft and honors the env override.
func TestLoadSBOMProducer(t *testing.T) {
	t.Setenv("SYNAPSE_SBOM_PRODUCER", "")
	if got := Load().SBOMProducer; got != "syft" {
		t.Errorf("SBOMProducer default = %q, want syft", got)
	}
	t.Setenv("SYNAPSE_SBOM_PRODUCER", "ownsbom")
	if got := Load().SBOMProducer; got != "ownsbom" {
		t.Errorf("SBOMProducer from env = %q, want ownsbom", got)
	}
}

// TestLoadMaxWorkspaceBytes confirms the acquire workspace cap defaults to 2 GiB and honors a
// byte override (including values beyond int32) via SYNAPSE_MAX_WORKSPACE_BYTES.
func TestProjectSourceCaptureDefaults(t *testing.T) {
	for _, key := range []string{
		"SYNAPSE_PROJECT_SOURCE_ARTIFACT_DIR", "SYNAPSE_PROJECT_SOURCE_RETENTION",
		"SYNAPSE_PROJECT_SOURCE_MAX_FILE_BYTES", "SYNAPSE_PROJECT_SOURCE_MAX_FILES", "SYNAPSE_PROJECT_SOURCE_MAX_BYTES",
	} {
		t.Setenv(key, "")
	}
	cfg := Load()
	if cfg.ProjectSourceArtifactDir != "data/project-source-artifacts" || cfg.ProjectSourceRetention != 90*24*time.Hour || cfg.ProjectSourceMaxFileBytes != 2<<20 || cfg.ProjectSourceMaxFiles != 10_000 || cfg.ProjectSourceMaxBytes != 500<<20 {
		t.Fatalf("source capture defaults = %+v", cfg)
	}
}

func TestProjectAnalysisCompletionTimeout(t *testing.T) {
	t.Setenv("SYNAPSE_SCAN_TIMEOUT", "2m")
	t.Setenv("SYNAPSE_PROJECT_ANALYSIS_COMPLETION_TIMEOUT", "")
	if got := Load().ProjectAnalysisCompletionTimeout; got != 2*time.Minute {
		t.Fatalf("default completion timeout=%s, want 2m", got)
	}
	t.Setenv("SYNAPSE_PROJECT_ANALYSIS_COMPLETION_TIMEOUT", "45s")
	if got := Load().ProjectAnalysisCompletionTimeout; got != 45*time.Second {
		t.Fatalf("override completion timeout=%s, want 45s", got)
	}
	t.Setenv("SYNAPSE_SCAN_TIMEOUT", "0s")
	t.Setenv("SYNAPSE_PROJECT_ANALYSIS_COMPLETION_TIMEOUT", "0s")
	if got := Load().ProjectAnalysisCompletionTimeout; got != time.Minute {
		t.Fatalf("disabled timeout fallback=%s, want 1m", got)
	}
}

func TestLoadMaxWorkspaceBytes(t *testing.T) {
	t.Setenv("SYNAPSE_MAX_WORKSPACE_BYTES", "")
	if got := Load().MaxWorkspaceBytes; got != 2<<30 {
		t.Errorf("MaxWorkspaceBytes default = %d, want %d", got, int64(2<<30))
	}
	t.Setenv("SYNAPSE_MAX_WORKSPACE_BYTES", "8589934592") // 8 GiB, exceeds int32
	if got := Load().MaxWorkspaceBytes; got != 8589934592 {
		t.Errorf("MaxWorkspaceBytes from env = %d, want 8589934592", got)
	}
}
