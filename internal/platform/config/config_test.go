package config

import (
	"path/filepath"
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

// TestLoadAttackPathBounds pins the bounded traversal defaults and environment overrides.
func TestLoadAttackPathBounds(t *testing.T) {
	for _, key := range []string{
		"SYNAPSE_ATTACKPATH_MAX_LEN",
		"SYNAPSE_ATTACKPATH_MAX_PATHS",
		"SYNAPSE_ATTACKPATH_WALLCLOCK",
	} {
		t.Setenv(key, "")
	}
	c := Load()
	if c.AttackPathMaxLen != 12 || c.AttackPathMaxPaths != 100 || c.AttackPathWallClock != 2*time.Second {
		t.Fatalf("attack-path defaults = (%d, %d, %s), want (12, 100, 2s)", c.AttackPathMaxLen, c.AttackPathMaxPaths, c.AttackPathWallClock)
	}

	t.Setenv("SYNAPSE_ATTACKPATH_MAX_LEN", "7")
	t.Setenv("SYNAPSE_ATTACKPATH_MAX_PATHS", "25")
	t.Setenv("SYNAPSE_ATTACKPATH_WALLCLOCK", "750ms")
	c = Load()
	if c.AttackPathMaxLen != 7 || c.AttackPathMaxPaths != 25 || c.AttackPathWallClock != 750*time.Millisecond {
		t.Fatalf("attack-path overrides = (%d, %d, %s), want (7, 25, 750ms)", c.AttackPathMaxLen, c.AttackPathMaxPaths, c.AttackPathWallClock)
	}
}

func TestLoadCSPMDefaultsAndBounds(t *testing.T) {
	for _, key := range []string{"SYNAPSE_CSPM_ENABLED", "SYNAPSE_CSPM_PROVIDERS", "SYNAPSE_CSPM_RATE"} {
		t.Setenv(key, "")
	}
	cfg := Load()
	if cfg.CSPMEnabled || len(cfg.CSPMProviders) != 0 || cfg.CSPMRate != 0 {
		t.Fatalf("CSPM defaults = (%v,%v,%d)", cfg.CSPMEnabled, cfg.CSPMProviders, cfg.CSPMRate)
	}
	t.Setenv("SYNAPSE_CSPM_ENABLED", "true")
	t.Setenv("SYNAPSE_CSPM_PROVIDERS", "aws,azure,gcp")
	t.Setenv("SYNAPSE_CSPM_RATE", "25")
	cfg = Load()
	if !cfg.CSPMEnabled || len(cfg.CSPMProviders) != 3 || cfg.CSPMRate != 25 {
		t.Fatalf("CSPM override = (%v,%v,%d)", cfg.CSPMEnabled, cfg.CSPMProviders, cfg.CSPMRate)
	}
	t.Setenv("SYNAPSE_CSPM_RATE", "101")
	if got := Load().CSPMRate; got != 0 {
		t.Fatalf("invalid CSPM rate = %d, want provider default", got)
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

func TestFPTriageModeDefaultsToShadow(t *testing.T) {
	t.Setenv("SYNAPSE_FP_TRIAGE_MODE", "")
	if got := Load().FPTriageMode; got != "shadow" {
		t.Fatalf("default FP triage mode = %q, want shadow", got)
	}
	t.Setenv("SYNAPSE_FP_TRIAGE_MODE", "  ENFORCE ")
	if got := Load().FPTriageMode; got != "enforce" {
		t.Fatalf("normalized FP triage mode = %q, want enforce", got)
	}
	t.Setenv("SYNAPSE_FP_TRIAGE_MODE", "automatic")
	if got := Load().FPTriageMode; got != "shadow" {
		t.Fatalf("unknown FP triage mode = %q, want fail-closed shadow", got)
	}
}

func TestFPTriageBudgetDefaultsAndBounds(t *testing.T) {
	t.Setenv("SYNAPSE_FP_TRIAGE_MAX_FINDINGS", "")
	t.Setenv("SYNAPSE_FP_TRIAGE_CONCURRENCY", "")
	cfg := Load()
	if cfg.FPTriageMaxFindings != defaultFPTriageMaxFindings || cfg.FPTriageConcurrency != defaultFPTriageConcurrency {
		t.Fatalf("default FP triage budget = (%d,%d), want (%d,%d)", cfg.FPTriageMaxFindings, cfg.FPTriageConcurrency, defaultFPTriageMaxFindings, defaultFPTriageConcurrency)
	}

	t.Setenv("SYNAPSE_FP_TRIAGE_MAX_FINDINGS", "25")
	t.Setenv("SYNAPSE_FP_TRIAGE_CONCURRENCY", "3")
	cfg = Load()
	if cfg.FPTriageMaxFindings != 25 || cfg.FPTriageConcurrency != 3 {
		t.Fatalf("configured FP triage budget = (%d,%d), want (25,3)", cfg.FPTriageMaxFindings, cfg.FPTriageConcurrency)
	}

	for _, tc := range []struct {
		maxFindings string
		concurrency string
	}{
		{"0", "0"},
		{"-1", "-1"},
		{"1001", "33"},
		{"not-a-number", "not-a-number"},
	} {
		t.Setenv("SYNAPSE_FP_TRIAGE_MAX_FINDINGS", tc.maxFindings)
		t.Setenv("SYNAPSE_FP_TRIAGE_CONCURRENCY", tc.concurrency)
		cfg = Load()
		if cfg.FPTriageMaxFindings != defaultFPTriageMaxFindings || cfg.FPTriageConcurrency != defaultFPTriageConcurrency {
			t.Errorf("invalid FP triage budget (%q,%q) = (%d,%d), want safe defaults", tc.maxFindings, tc.concurrency, cfg.FPTriageMaxFindings, cfg.FPTriageConcurrency)
		}
	}
}

func TestFPTriageOperationalBudgetAndCircuitConfig(t *testing.T) {
	for _, key := range []string{"SYNAPSE_FP_TRIAGE_MAX_TOKENS", "SYNAPSE_FP_TRIAGE_MAX_COST_MICRO_USD", "SYNAPSE_FP_TRIAGE_CIRCUIT_FAILURES", "SYNAPSE_FP_TRIAGE_CIRCUIT_COOLDOWN"} {
		t.Setenv(key, "")
	}
	cfg := Load()
	if cfg.FPTriageMaxTokens != defaultFPTriageMaxTokens || cfg.FPTriageMaxCostMicroUSD != 0 || cfg.FPTriageCircuitFailures != defaultFPTriageCircuitFailures || cfg.FPTriageCircuitCooldown != time.Minute {
		t.Fatalf("operational defaults = tokens:%d cost:%d failures:%d cooldown:%s", cfg.FPTriageMaxTokens, cfg.FPTriageMaxCostMicroUSD, cfg.FPTriageCircuitFailures, cfg.FPTriageCircuitCooldown)
	}
	t.Setenv("SYNAPSE_FP_TRIAGE_MAX_TOKENS", "25000")
	t.Setenv("SYNAPSE_FP_TRIAGE_MAX_COST_MICRO_USD", "4000")
	t.Setenv("SYNAPSE_FP_TRIAGE_CIRCUIT_FAILURES", "3")
	t.Setenv("SYNAPSE_FP_TRIAGE_CIRCUIT_COOLDOWN", "30s")
	cfg = Load()
	if cfg.FPTriageMaxTokens != 25000 || cfg.FPTriageMaxCostMicroUSD != 4000 || cfg.FPTriageCircuitFailures != 3 || cfg.FPTriageCircuitCooldown != 30*time.Second {
		t.Fatalf("operational config = tokens:%d cost:%d failures:%d cooldown:%s", cfg.FPTriageMaxTokens, cfg.FPTriageMaxCostMicroUSD, cfg.FPTriageCircuitFailures, cfg.FPTriageCircuitCooldown)
	}
}

func TestFPTriageVerifierIdentityConfig(t *testing.T) {
	for _, key := range []string{
		"SYNAPSE_LLM_BASE_URL", "SYNAPSE_LLM_API_KEY", "SYNAPSE_LLM_PROVIDER", "SYNAPSE_FP_TRIAGE_PROVIDER",
		"SYNAPSE_VERIFIER_BASE_URL", "SYNAPSE_VERIFIER_API_KEY", "SYNAPSE_VERIFIER_PROVIDER",
		"SYNAPSE_FP_TRIAGE_INDEPENDENCE",
	} {
		t.Setenv(key, "")
	}
	cfg := Load()
	if cfg.VerifierBaseURL != cfg.LLMBaseURL || cfg.VerifierAPIKey != cfg.LLMAPIKey ||
		cfg.VerifierProvider != cfg.LLMProvider || cfg.FPTriageProvider != cfg.LLMProvider || cfg.LLMProvider != "openai-compatible" {
		t.Fatal("verifier transport defaults must follow proposer without losing provider metadata")
	}
	if cfg.FPTriageIndependence != "model_family" {
		t.Fatalf("default independence = %q, want model_family", cfg.FPTriageIndependence)
	}

	t.Setenv("SYNAPSE_LLM_BASE_URL", "https://proposer.example/v1")
	t.Setenv("SYNAPSE_LLM_API_KEY", "proposer-secret")
	t.Setenv("SYNAPSE_LLM_PROVIDER", " OpenAI ")
	t.Setenv("SYNAPSE_FP_TRIAGE_PROVIDER", " Azure-OpenAI ")
	t.Setenv("SYNAPSE_VERIFIER_PROVIDER", "")
	if got := Load().VerifierProvider; got != "azure-openai" {
		t.Fatalf("implicit verifier provider = %q, want fail-closed proposer provider", got)
	}
	t.Setenv("SYNAPSE_VERIFIER_BASE_URL", "https://verifier.example/v1")
	t.Setenv("SYNAPSE_VERIFIER_API_KEY", "verifier-secret")
	t.Setenv("SYNAPSE_VERIFIER_PROVIDER", " Anthropic ")
	t.Setenv("SYNAPSE_FP_TRIAGE_INDEPENDENCE", " PROVIDER ")
	cfg = Load()
	if cfg.VerifierBaseURL != "https://verifier.example/v1" || cfg.VerifierAPIKey != "verifier-secret" ||
		cfg.LLMProvider != "openai" || cfg.FPTriageProvider != "azure-openai" || cfg.VerifierProvider != "anthropic" || cfg.FPTriageIndependence != "provider" {
		t.Fatal("independent verifier configuration was not preserved")
	}

	t.Setenv("SYNAPSE_FP_TRIAGE_INDEPENDENCE", "different-ish")
	if got := Load().FPTriageIndependence; got != "disabled" {
		t.Fatalf("unknown independence policy = %q, want fail-closed disabled", got)
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
	if !filepath.IsAbs(cfg.ProjectSourceArtifactDir) || cfg.ProjectSourceRetention != 90*24*time.Hour || cfg.ProjectSourceMaxFileBytes != 2<<20 || cfg.ProjectSourceMaxFiles != 10_000 || cfg.ProjectSourceMaxBytes != 500<<20 {
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

func TestLoadDASTCeilingsFailClosed(t *testing.T) {
	t.Setenv("SYNAPSE_DAST_MAX_REAUTH", "3")
	t.Setenv("SYNAPSE_DAST_RATE_PER_SEC", "6")
	t.Setenv("SYNAPSE_DAST_CONCURRENCY", "5")
	t.Setenv("SYNAPSE_DAST_MAX_DEPTH", "9")
	t.Setenv("SYNAPSE_DAST_MAX_PAGES", "2001")
	t.Setenv("SYNAPSE_DAST_MAX_REQUESTS", "20001")
	t.Setenv("SYNAPSE_DAST_MAX_WALL_CLOCK", "31m")
	config := Load()
	if config.DASTMaxReauth != 2 || config.DASTRatePerSec != 5 || config.DASTConcurrency != 4 || config.DASTMaxDepth != 8 || config.DASTMaxPages != 2000 || config.DASTMaxRequests != 20000 || config.DASTMaxWallClock != 30*time.Minute {
		t.Fatalf("DAST ceilings did not fail closed: %+v", config)
	}
}
