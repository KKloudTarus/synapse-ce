package main

import (
	"os"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

// scanEgress records which optional parts of the `scan` pipeline are allowed to reach the network.
//
// --offline (and SYNAPSE_OFFLINE) used to switch off only the live OSV.dev detection source, while the
// npm and composer/poetry resolvers still ran `npm install --package-lock-only` and the equivalent
// lock-only resolves, and the KEV/EPSS/NVD/deps.dev enrichers still made HTTP calls. An operator on an
// air-gapped runner reads "offline" as "this scan makes no outbound connection", so offline now clears
// every field here. What survives is genuinely local: Grype's pre-synced DB, Syft, the owned advisory
// store, the offline JAR SHA-1 index, and a local NVD CVSS DB.
type scanEgress struct {
	OSV             bool // live OSV.dev detection source
	NPMResolve      bool // `npm install --package-lock-only` against the registry
	ManifestResolve bool // composer / poetry lock-only resolve against their registries
	BundlerResolve  bool // `bundle lock` against rubygems
	MavenResolve    bool // `mvn dependency:list` against the configured repos
	GradleResolve   bool // `gradle dependencies` against the configured repos
	JarHashOnline   bool // Maven Central SHA-1 coordinate lookup
	LicenseMetadata bool // deps.dev + PyPI license metadata
	NVDSeverity     bool // online NVD CVSS backfill
	RiskFeeds       bool // CISA KEV catalog + FIRST EPSS
	AITriage        bool // LLM false-positive triage
}

// newScanEgress resolves the egress policy for one scan. offlineFlag is --offline; cfg.Offline is
// SYNAPSE_OFFLINE; either one is enough. lookupEnv is injected for tests and is os.LookupEnv in
// production: npm and manifest resolution are default-ON for the CLI (trusted local project), which is
// expressed as "config default unless the variable was set explicitly", so the policy has to see the
// environment rather than the config value alone.
func newScanEgress(cfg config.Config, offlineFlag bool, lookupEnv func(string) (string, bool)) scanEgress {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if offlineFlag || cfg.Offline {
		return scanEgress{}
	}
	npm := cfg.NPMResolveEnabled
	if _, set := lookupEnv("SYNAPSE_NPM_RESOLVE_ENABLED"); !set {
		npm = true
	}
	manifest := cfg.ManifestResolveEnabled
	if _, set := lookupEnv("SYNAPSE_MANIFEST_RESOLVE_ENABLED"); !set {
		manifest = true
	}
	return scanEgress{
		OSV:             true,
		NPMResolve:      npm,
		ManifestResolve: manifest,
		BundlerResolve:  cfg.BundlerResolveEnabled,
		MavenResolve:    cfg.MavenResolveEnabled,
		GradleResolve:   cfg.GradleResolveEnabled,
		JarHashOnline:   cfg.JarHashOnlineEnabled,
		LicenseMetadata: true,
		NVDSeverity:     true,
		RiskFeeds:       true,
		AITriage:        true,
	}
}

// offline reports whether the policy forbids all network egress.
func (e scanEgress) offline() bool { return e == scanEgress{} }
