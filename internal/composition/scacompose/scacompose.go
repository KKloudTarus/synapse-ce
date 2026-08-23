// Package scacompose shares SCA execution composition between API and worker roots.
package scacompose

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/cache/fptriagecache"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/cache/sbomcache"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourcesnippet"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/bincat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gomodgraph"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gradleresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/grype"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ignorefile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarchecksum"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarhash"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarlicense"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jvmreach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/licensefile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/manifest"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/manifestresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/mavencoord"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/mavenresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/misconfig"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/msi"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/npmresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/nvd"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ospkg"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/osv"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/sast"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/secretscan"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/syft"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/vexfile"
	"github.com/KKloudTarus/synapse-ce/internal/platform/binregistry"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fptriage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// Execution holds the concrete SCA execution adapters. Sandbox and SyftGen are
// exposed because the composition root still needs them (taint call-graph, SBOM cross-check).
type Execution struct {
	Sandbox  *sandbox.Runner
	SyftGen  *syft.Generator
	Acquirer ports.Acquirer
	SBOMGen  ports.SBOMGenerator
	Sources  []ports.DetectionSource
}

// BuildExecution constructs the SCA tool adapters: syft, grype, the SCA sandbox
// (fail-closed when SYNAPSE_SANDBOX_ENABLED), sandboxed acquisition, the SBOM producer
// select, and the detection sources.
func validateProductionNetworkedTools(cfg config.Config) error {
	if !cfg.IsProduction() {
		return nil
	}
	var enabled []string
	for name, on := range map[string]bool{
		"SYNAPSE_MAVEN_RESOLVE_ENABLED":    cfg.MavenResolveEnabled,
		"SYNAPSE_GRADLE_RESOLVE_ENABLED":   cfg.GradleResolveEnabled,
		"SYNAPSE_NPM_RESOLVE_ENABLED":      cfg.NPMResolveEnabled,
		"SYNAPSE_MANIFEST_RESOLVE_ENABLED": cfg.ManifestResolveEnabled,
	} {
		if on {
			enabled = append(enabled, name)
		}
	}
	if len(enabled) == 0 {
		return nil
	}
	slices.Sort(enabled)
	return fmt.Errorf("production networked SCA tools require authoritative signed scan grants and are not yet supported: %s", strings.Join(enabled, ", "))
}

func BuildExecution(cfg config.Config, log *slog.Logger, advisoryStore ports.AdvisoryStore) (Execution, error) {
	if err := validateProductionNetworkedTools(cfg); err != nil {
		return Execution{}, err
	}
	localAcquirer := acquire.New().WithMaxWorkspaceBytes(cfg.MaxWorkspaceBytes).WithImageRootFS(cfg.ImageRootFSEnabled).WithComparisonDepth(cfg.ProjectGitComparisonDepth)
	var acquirer ports.Acquirer = localAcquirer
	var scaSandbox *sandbox.Runner
	var sbomGen ports.SBOMGenerator
	var detectionSources []ports.DetectionSource
	// SCA tool sandboxing (closes audit finding D2): syft + grype are offline, so
	// when the sandbox is enabled they run in an ISOLATED sandbox (read-only FS, no
	// network, dropped caps) – no egress/vault needed. Build/parse output is unchanged.
	syftGen := syft.New(cfg.SyftBin)
	grypeSrc := grype.New(cfg.GrypeBin, cfg.GrypeDBDir)
	if cfg.SandboxEnabled {
		sb, serr := sandbox.NewRunner(cfg.ScanTimeout, cfg.ReconMaxOutput, cfg.SandboxMemMax, cfg.SandboxPidsMax)
		if serr != nil {
			// Fail CLOSED (re-audit fix): the operator explicitly asked for the sandbox
			// (SYNAPSE_SANDBOX_ENABLED=true); if it cannot be built we must NOT silently
			// degrade to a direct host exec of syft/grype/git/crane. Refuse to start –
			// mirrors the worker (which os.Exit's) and the prod-vault-key hardening.
			return Execution{}, fmt.Errorf("SYNAPSE_SANDBOX_ENABLED is set but the sandbox is unavailable – refusing to run SCA/acquisition UNSANDBOXED; install bubblewrap or unset the flag: %w", serr)
		}
		scaSandbox = sb
		// Syft and Grype carry no EgressPolicy, so they remain network-isolated. Remote
		// acquisition is still attached to this exact runner, but its legacy HostNetwork
		// request is rejected before Bubblewrap starts until scan grants have an authoritative
		// execution aggregate and issuer branch.
		scaSandbox.SetBinaryRegistry(binregistry.New(cfg.ToolHashes, true))
		syftGen = syftGen.WithRunner(scaSandbox)
		grypeSrc = grypeSrc.WithRunner(scaSandbox)
		localAcquirer = localAcquirer.WithSandbox(scaSandbox, false)
		acquirer = localAcquirer
		log.Info("SCA tools (syft/grype) run sandboxed-isolated; network acquisition is fail-closed pending signed scan grants")
	} else {
		log.Warn("SANDBOX DISABLED (SYNAPSE_SANDBOX_ENABLED is off) – syft/grype/git/crane run UNSANDBOXED with NO seccomp/rootfs/egress/cgroup containment; dev only, never production")
	}
	// SBOM producer select: default Syft (pinned binary, full coverage + CycloneDX
	// dep-graph edges) or the detection-independent owned parsers. ownsbom is pure-Go (no exec) so it
	// needs no sandbox; its SBOM is components-only (no edges) over Tier-1 ecosystems – which OSV and
	// grype both accept (grype reconstructs a CycloneDX from the components when there is no Raw).
	sbomGen = syftGen
	switch cfg.SBOMProducer {
	case "", "syft":
		log.Info("SBOM producer = syft (pinned binary; full ecosystem coverage + CycloneDX dep-graph edges)") // default, wired above
	case "ownsbom":
		reg, rerr := ownsbom.DefaultRegistry()
		if rerr != nil {
			return Execution{}, fmt.Errorf("build ownsbom SBOM producer: %w", rerr)
		}
		sbomGen = reg
		log.Info("SBOM producer = ownsbom (detection-independent owned parsers; no third-party scanner; components-only over Tier-1 ecosystems)")
	default:
		return Execution{}, fmt.Errorf("invalid SYNAPSE_SBOM_PRODUCER (want 'syft' or 'ownsbom'): %s", cfg.SBOMProducer)
	}
	// Detection sources: Grype (offline DB) always; live OSV unless SYNAPSE_OFFLINE (air-gapped /
	// fast path – no per-scan network egress). The owned advisory store is opt-in
	// and offline, so it runs in both modes (detection independence).
	detectionSources = []ports.DetectionSource{grypeSrc}
	if !cfg.Offline {
		detectionSources = append([]ports.DetectionSource{osv.New(cfg.OSVBaseURL, nil)}, detectionSources...)
	} else {
		log.Info("SYNAPSE_OFFLINE: live OSV source disabled; detecting with offline sources only", "grype", true, "owned_advisory", cfg.OwnedAdvisoryEnabled)
	}
	if cfg.OwnedAdvisoryEnabled {
		detectionSources = append(detectionSources, ownadvisory.New(advisoryStore))
		log.Info("owned advisory DetectionSource ENABLED (offline match against the owned store, alongside OSV/Grype) – ensure the store is populated; an empty store yields no findings until the advisory ingester runs")
	}
	return Execution{Sandbox: scaSandbox, SyftGen: syftGen, Acquirer: acquirer, SBOMGen: sbomGen, Sources: detectionSources}, nil
}

// Configure applies every scan-pipeline setting that must match between an in-process
// API scan and a worker-executed scan: license/coord/hash resolvers, severity enrichment,
// transitive resolvers, analyzers, AI false-positive triage, caches, and feature gates.
// The returned cleanup closes the optional offline JAR hash database.
func Configure(svc *scauc.Service, cfg config.Config, sb *sandbox.Runner, log *slog.Logger) func() {
	cleanup := func() {}
	svc.SetGateDecoder(qualityprofile.LoadGateBytes)
	svc.SetSBOMEnricher(manifest.New())
	svc.SetArtifactCataloger(msi.New())           // recover Windows Installer (.msi) product identity into the SBOM
	svc.SetMavenCoordResolver(mavencoord.New())   // recover real Maven coords from JAR pom.properties (offline) before license lookup
	svc.SetJarChecksumResolver(jarchecksum.New()) // capture JAR artifact SHA-1 from the workspace (Syft omits it from CycloneDX)
	// SHA-1 coordinate recovery for shaded/metadata-less JARs: offline trivy-java-db-format
	// index first (if configured), online Maven Central as the fallback. Best-effort.
	var jhResolvers []ports.JarHashResolver
	if cfg.JarHashDBPath != "" {
		if off, err := jarhash.NewOffline(cfg.JarHashDBPath); err != nil {
			log.Warn("JAR SHA-1 offline DB not usable – falling back to online only if enabled", "path", cfg.JarHashDBPath, "err", err)
		} else {
			cleanup = func() { _ = off.Close() } // release the read-only DB handle at shutdown
			jhResolvers = append(jhResolvers, off)
			log.Info("JAR SHA-1 coordinate recovery: OFFLINE index ENABLED (air-gap; no rate limit)", "path", cfg.JarHashDBPath)
		}
	}
	if cfg.JarHashOnlineEnabled {
		// An egress call to Maven Central; on the sandbox it needs search.maven.org in the egress allow-list.
		jhResolvers = append(jhResolvers, jarhash.New(cfg.JarHashBaseURL, nil))
		log.Info("JAR SHA-1 coordinate recovery: ONLINE Maven Central ENABLED (best-effort; fallback after offline)")
	}
	if len(jhResolvers) > 0 {
		svc.SetJarHashResolver(jarhash.NewChain(jhResolvers...))
	}
	// Backfill unknown vuln severities from NVD CVSS (best-effort; set SYNAPSE_NVD_API_KEY for throughput).
	svc.SetSeverityEnricher(nvd.New(cfg.NVDAPIURL, cfg.NVDAPIKey, nil).WithBudget(cfg.NVDBudget))
	svc.SetIgnoreUnfixed(cfg.IgnoreUnfixed) // SYNAPSE_IGNORE_UNFIXED: suppress no-upstream-fix vulns (distro-noise reducer)
	// Offline license-text fallback: JAR-embedded licenses (jarlicense) + workspace LICENSE
	// files for every ecosystem.
	svc.SetLicenseFileResolver(licensefile.NewChain(jarlicense.New(), licensefile.New()))
	// Transitive Go dependency edges via `go mod graph`, opt-in + best-effort. Sandboxed when the
	// SCA sandbox is on (low-risk: go mod graph only reads go.mod files, never compiles); a non-Go target /
	// no module cache adds no edges and never fails the scan.
	if cfg.GoModGraphEnabled {
		gmg := gomodgraph.New(cfg.GoBin)
		if sb != nil {
			gmg = gmg.WithRunner(sb)
		} else {
			// dev only (prod attaches the sandbox above): the direct path still pins GOPROXY=off +
			// GOTOOLCHAIN=local, but runs `go` outside the bwrap confinement – make that explicit.
			log.Warn("go mod graph runs UNSANDBOXED (SCA sandbox off; dev only)")
		}
		svc.SetGraphResolver(gmg)
		log.Info("Go transitive-edge resolution ENABLED (go mod graph; best-effort, sandboxed when available)")
	}
	// Maven full-tree resolution (`mvn dependency:list`): resolves managed versions + the transitive tree
	// a from-source pom.xml scan can't, so Maven projects stop under-reporting. HIGHER RISK than go mod
	// graph – it RUNS the Maven toolchain (POM + parent-POM + plugin resolution) over UNTRUSTED project
	// config and reaches the Maven repo. The SERVER therefore enables it ONLY when the SCA sandbox is
	// present (egress confined to Maven Central) and FAILS CLOSED otherwise – it never host-execs mvn over
	// an untrusted target. Direct-exec is left to synapse-cli, the trusted-local dogfood path. Opt-in.
	if cfg.MavenResolveEnabled {
		if sb == nil {
			log.Warn("SYNAPSE_MAVEN_RESOLVE_ENABLED ignored: it requires the SCA sandbox (mvn would otherwise run untrusted POM config on the host). Enable the sandbox to use it.")
		} else {
			svc.SetMavenResolver(mavenresolve.New(cfg.MvnBin).WithRunner(sb).
				WithRepoHosts(cfg.MavenRepoHosts).WithLocalRepo(cfg.MavenLocalRepo))
			log.Info("Maven transitive-tree resolution ENABLED (mvn dependency:list, sandbox-confined; best-effort)", "extra_repo_hosts", len(cfg.MavenRepoHosts), "persistent_cache", cfg.MavenLocalRepo != "")
		}
	}
	// Gradle full-tree resolution (`gradle dependencies`): same gap as Maven, but evaluating build.gradle
	// runs arbitrary build logic – so the SERVER enables it ONLY with the SCA sandbox and FAILS CLOSED
	// otherwise (never host-execs gradle over an untrusted target). A pinned gradle, never./gradlew.
	if cfg.GradleResolveEnabled {
		if sb == nil {
			log.Warn("SYNAPSE_GRADLE_RESOLVE_ENABLED ignored: it requires the SCA sandbox (gradle would otherwise run untrusted build logic on the host). Enable the sandbox to use it.")
		} else {
			svc.SetGradleResolver(gradleresolve.New(cfg.GradleBin).WithRunner(sb).
				WithRepoHosts(cfg.MavenRepoHosts).WithGradleHome(cfg.GradleHome))
			log.Info("Gradle transitive-tree resolution ENABLED (gradle dependencies, sandbox-confined; best-effort)", "extra_repo_hosts", len(cfg.MavenRepoHosts), "persistent_cache", cfg.GradleHome != "")
		}
	}
	// npm resolution for a lockfile-less package.json (`npm install --package-lock-only --ignore-scripts`):
	// reaches the registry over an untrusted manifest, so the SERVER enables it ONLY with the SCA sandbox
	// and FAILS CLOSED otherwise (never host-execs npm over an untrusted target). --ignore-scripts + a
	// throwaway copy mean no project code runs and the source is never mutated. Opt-in.
	if cfg.NPMResolveEnabled {
		if sb == nil {
			log.Warn("SYNAPSE_NPM_RESOLVE_ENABLED ignored: it requires the SCA sandbox (npm would otherwise reach the network over an untrusted manifest on the host). Enable the sandbox to use it.")
		} else {
			svc.SetNPMResolver(npmresolve.New(cfg.NPMBin).WithRunner(sb).WithRegistryHosts(cfg.NPMRegistryHosts))
			log.Info("npm resolution ENABLED (npm install --package-lock-only, sandbox-confined; best-effort)", "extra_registry_hosts", len(cfg.NPMRegistryHosts))
		}
	}
	// Lockfile-less manifest resolvers (composer.json / Gemfile / pyproject.toml): each runs its ecosystem
	// tool over an untrusted manifest and reaches the registry, so the SERVER enables them ONLY with the SCA
	// sandbox and FAILS CLOSED otherwise. Lock-only + no-scripts + a throwaway copy mean no project code runs.
	if cfg.ManifestResolveEnabled {
		if sb == nil {
			log.Warn("SYNAPSE_MANIFEST_RESOLVE_ENABLED ignored: it requires the SCA sandbox (composer/bundle/poetry would otherwise reach the network over an untrusted manifest on the host). Enable the sandbox to use it.")
		} else {
			binOf := map[string]string{"composer": cfg.ComposerBin, "gem": cfg.BundleBin, "poetry": cfg.PoetryBin}
			for _, eco := range []string{"composer", "gem", "poetry"} {
				svc.AddManifestResolver(manifestresolve.New(eco, binOf[eco]).WithRunner(sb).WithRegistryHosts(cfg.ManifestRegistryHosts))
			}
			log.Info("lockfile-less manifest resolution ENABLED (composer/gem/poetry, sandbox-confined; best-effort)", "extra_registry_hosts", len(cfg.ManifestRegistryHosts))
		}
	}
	if cfg.JVMReachabilityEnabled {
		// Read-only bytecode parsing (no exec, no ToolRunner needed) – tags JVM components reachable/
		// unreferenced from the app's compiled closure. Best-effort; a not-built target tags nothing.
		svc.SetJVMReachability(jvmreach.New())
		log.Info("coarse JVM class-reachability ENABLED (deprioritizes findings on unreferenced deps)")
	}
	if cfg.SASTEnabled {
		svc.SetSASTAnalyzer(sast.New()) // deterministic pattern-SAST in the scan pipeline
		log.Info("pattern-SAST ENABLED (weak crypto / hardcoded secrets / insecure config)")
	}
	if cfg.SecretScanEnabled {
		svc.SetSecretScanner(secretscan.New()) // deterministic, redacted secret scan in the scan pipeline
		log.Info("secret scanning ENABLED (hardcoded credentials; matches redacted)")
	}
	if cfg.ImageRootFSEnabled {
		svc.SetOSPackageCataloger(ospkg.New())         // owned dpkg/apk cataloging from the materialized image rootfs
		svc.SetInstalledPackageCataloger(bincat.New()) // owned Go-binary + Python dist-info cataloging from the rootfs
		log.Info("image-rootfs cataloging ENABLED (dpkg + apk OS packages; Go binaries + Python dist-info)")
	}
	if cfg.MisconfigEnabled {
		// Helm chart rendering shells out `helm template` over an UNTRUSTED chart; like the maven/gradle
		// resolvers it must be sandbox-confined on the API host (a crafted chart's Sprig getHostByName is an
		// SSRF vector). Wire it through the SCA sandbox when present; otherwise leave Helm rendering OFF.
		mc := misconfig.New()
		helmMode := "Helm rendering OFF (no SCA sandbox; a chart runs untrusted templates on the host)"
		if sb != nil {
			mc = mc.WithHelmRunner(sb)
			helmMode = "Helm charts rendered sandboxed (egress-denied)"
		}
		svc.SetMisconfigScanner(mc) // deterministic IaC/config misconfig scan in the scan pipeline
		log.Info("misconfig scanning ENABLED (Dockerfile + Kubernetes + Terraform); " + helmMode)
	}
	// AI false-positive triage in the scan pipeline (opt-in, best-effort, PROPOSE-ONLY). Independent of
	// the agent: it critiques production-scope source findings. Single-model output is advisory-only; a
	// distinct verifier is required before the deterministic high-risk floor may grant a gate exemption.
	if cfg.FPTriageEnabled && strings.TrimSpace(cfg.FPTriageModel) != "" {
		svc.SetFPTriageMode(cfg.FPTriageMode)
		svc.SetFPTriageMaxFindings(cfg.FPTriageMaxFindings)
		svc.SetFPTriageIndependence(cfg.FPTriageIndependence)
		svc.SetFPTriageAlertPolicy(cfg.FPTriageAlertMinSamples, cfg.FPTriageDisagreeBaseBPS,
			cfg.FPTriageExemptBaseBPS, cfg.FPTriageParseFailBaseBPS, cfg.FPTriageAlertDeltaBPS)
		if tllm, terr := openai.New(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.FPTriageModel, cfg.LLMTimeout); terr != nil {
			log.Warn("AI false-positive triage DISABLED (LLM unavailable)", "err", terr)
		} else {
			coord := fptriage.NewWithIdentity(tllm, cfg.FPTriageProvider, cfg.FPTriageModel).
				WithConcurrency(cfg.FPTriageConcurrency).
				WithOperationalPolicy(ports.FPTriageOperationalPolicy{
					MaxTokens: cfg.FPTriageMaxTokens, MaxCostMicroUSD: cfg.FPTriageMaxCostMicroUSD,
					ProposerInputMicroUSDPerMillion:  cfg.FPTriageProposerInputRate,
					ProposerOutputMicroUSDPerMillion: cfg.FPTriageProposerOutputRate,
					VerifierInputMicroUSDPerMillion:  cfg.FPTriageVerifierInputRate,
					VerifierOutputMicroUSDPerMillion: cfg.FPTriageVerifierOutputRate,
					CircuitFailureThreshold:          cfg.FPTriageCircuitFailures, CircuitCooldown: cfg.FPTriageCircuitCooldown,
				})
			mode := "advisory-only (distinct verifier required for gate exemption)"
			if strings.TrimSpace(cfg.VerifierModel) != "" {
				if !agent.IndependentLLMs(cfg.FPTriageProvider, cfg.FPTriageModel, cfg.VerifierProvider, cfg.VerifierModel, cfg.FPTriageIndependence) {
					log.Warn("AI FP-triage verifier independence cannot be established; triage remains advisory-only",
						"proposer_provider", cfg.FPTriageProvider, "proposer_model", cfg.FPTriageModel,
						"verifier_provider", cfg.VerifierProvider, "verifier_model", cfg.VerifierModel,
						"independence_policy", cfg.FPTriageIndependence)
				} else if vllm, verr := openai.New(cfg.VerifierBaseURL, cfg.VerifierAPIKey, cfg.VerifierModel, cfg.LLMTimeout); verr == nil {
					coord.WithIndependentVerifier(vllm, cfg.VerifierProvider, cfg.VerifierModel, ports.AIIndependencePolicy(cfg.FPTriageIndependence))
					if coord.VerifierModel() != "" {
						mode = "verified by " + coord.VerifierProvider() + "/" + coord.VerifierModel()
					}
				} else {
					log.Warn("AI FP-triage verifier unavailable; triage remains advisory-only", "err", verr)
				}
			}
			triager := fptriage.NewTriager(coord, func(root string) ports.SourceSnippetReader {
				return sourcesnippet.Reader{Root: root}
			})
			if cfg.ScanCacheEnabled {
				if dir := cfg.ResolveScanCacheDir(); dir != "" {
					cacheDir := filepath.Join(dir, "ai-triage")
					triager.WithCache(fptriagecache.New(cacheDir), scauc.EvaluationPolicyVersion())
					log.Info("AI false-positive triage cache ENABLED", "dir", cacheDir)
				}
			}
			svc.SetFPTriage(triager)
			log.Info("AI false-positive triage ENABLED ("+mode+")", "model", cfg.FPTriageModel,
				"triage_mode", cfg.FPTriageMode, "max_findings", cfg.FPTriageMaxFindings, "max_tokens", cfg.FPTriageMaxTokens,
				"max_cost_micro_usd", cfg.FPTriageMaxCostMicroUSD, "concurrency", cfg.FPTriageConcurrency)
		}
	}
	if cfg.SuppressionEnabled {
		svc.SetSuppressionLoader(ignorefile.New()) // repo-committed .synapseignore accepted-risk policy
		log.Info("suppression ENABLED (.synapseignore; suppressed findings retained + surfaced)")
	}
	if cfg.VEXEnabled {
		svc.SetVEXLoader(vexfile.New()) // in-repo OpenVEX (.synapse.vex.json) accepted-risk assertions
		log.Info("in-scan VEX ENABLED (.synapse.vex.json; not_affected/fixed gate-exempt, still reported + sealed)")
	}
	svc.SetDBMaxAgeDays(cfg.DBMaxAgeDays) // warn on stale reference DBs (KEV/EPSS/vuln-DB); 0 disables
	// Validate the configured detection priority once at startup: an invalid value would otherwise make
	// EVERY API scan return 400. Warn + fall back to comprehensive rather than crash a long-running server.
	detPriority := cfg.DetectionPriority
	if detPriority != "" {
		if _, err := scauc.NormalizeScanOptions(scauc.ScanOptions{Mode: scauc.ScanModeFull, DetectionPriority: detPriority}); err != nil {
			log.Warn("invalid SYNAPSE_DETECTION_PRIORITY; falling back to comprehensive", "value", detPriority, "err", err)
			detPriority = ""
		}
	}
	svc.SetDetectionPriority(detPriority) // server default (comprehensive|precise); the API scan path has no per-request priority
	if cfg.ScanCacheEnabled {
		if dir := cfg.ResolveScanCacheDir(); dir != "" {
			svc.SetSBOMCache(sbomcache.New(dir)) // content+version-addressed generated-SBOM cache
			log.Info("SBOM cache ENABLED", "dir", dir)
		}
	}
	return cleanup
}
