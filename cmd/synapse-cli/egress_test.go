package main

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

// noEnv is a lookupEnv that reports every variable as unset, which is the "fresh CI runner" case where
// npm and manifest resolution default ON.
func noEnv(string) (string, bool) { return "", false }

// envSet reports the named variables as explicitly set (to "false"; only the presence matters here).
func envSet(names ...string) func(string) (string, bool) {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return func(k string) (string, bool) {
		_, ok := set[k]
		return "false", ok
	}
}

// TestNewScanEgressOfflineDisablesEveryNetworkComponent is the regression guard for the flag's meaning:
// --offline used to leave the npm and composer/poetry resolvers running `npm install --package-lock-only`
// and the equivalent lock-only resolves, plus the KEV/EPSS/NVD/deps.dev HTTP enrichers, while only the
// live OSV source was dropped. Offline now means every one of them is off, whichever way it was enabled.
func TestNewScanEgressOfflineDisablesEveryNetworkComponent(t *testing.T) {
	// Everything an operator could switch on, so no field can stay true by having been opted in.
	all := config.Config{
		NPMResolveEnabled:      true,
		ManifestResolveEnabled: true,
		BundlerResolveEnabled:  true,
		MavenResolveEnabled:    true,
		GradleResolveEnabled:   true,
		JarHashOnlineEnabled:   true,
	}
	tests := []struct {
		name string
		cfg  config.Config
		flag bool
	}{
		{name: "offline flag", cfg: all, flag: true},
		{name: "SYNAPSE_OFFLINE", cfg: func() config.Config { c := all; c.Offline = true; return c }(), flag: false},
		{name: "both", cfg: func() config.Config { c := all; c.Offline = true; return c }(), flag: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newScanEgress(tc.cfg, tc.flag, noEnv)
			if !got.offline() {
				t.Fatalf("offline() = false for %+v", got)
			}
			v := reflect.ValueOf(got)
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).Bool() {
					t.Errorf("%s = true, want false in offline mode", v.Type().Field(i).Name)
				}
			}
		})
	}
}

// TestNewScanEgressOnline pins the online defaults, including the CLI's "npm and manifest resolution are
// ON unless the variable was set explicitly" rule.
func TestNewScanEgressOnline(t *testing.T) {
	tests := []struct {
		name      string
		cfg       config.Config
		lookupEnv func(string) (string, bool)
		want      scanEgress
	}{
		{
			name:      "defaults",
			cfg:       config.Config{},
			lookupEnv: noEnv,
			want: scanEgress{
				OSV: true, NPMResolve: true, ManifestResolve: true,
				LicenseMetadata: true, NVDSeverity: true, RiskFeeds: true, AITriage: true,
			},
		},
		{
			name:      "npm and manifest opted out explicitly",
			cfg:       config.Config{},
			lookupEnv: envSet("SYNAPSE_NPM_RESOLVE_ENABLED", "SYNAPSE_MANIFEST_RESOLVE_ENABLED"),
			want: scanEgress{
				OSV: true, LicenseMetadata: true, NVDSeverity: true, RiskFeeds: true, AITriage: true,
			},
		},
		{
			name: "opt-in resolvers on",
			cfg: config.Config{
				BundlerResolveEnabled: true, MavenResolveEnabled: true,
				GradleResolveEnabled: true, JarHashOnlineEnabled: true,
			},
			lookupEnv: noEnv,
			want: scanEgress{
				OSV: true, NPMResolve: true, ManifestResolve: true,
				BundlerResolve: true, MavenResolve: true, GradleResolve: true, JarHashOnline: true,
				LicenseMetadata: true, NVDSeverity: true, RiskFeeds: true, AITriage: true,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newScanEgress(tc.cfg, false, tc.lookupEnv)
			if got != tc.want {
				t.Fatalf("newScanEgress = %+v, want %+v", got, tc.want)
			}
			if got.offline() {
				t.Error("offline() = true for an online policy")
			}
		})
	}
}

// TestNewScanEgressNilLookupUsesEnv keeps the production default (os.LookupEnv) wired when no lookup is
// injected, so a caller passing nil cannot silently get a different policy.
func TestNewScanEgressNilLookupUsesEnv(t *testing.T) {
	t.Setenv("SYNAPSE_NPM_RESOLVE_ENABLED", "false")
	got := newScanEgress(config.Config{}, false, nil)
	if got.NPMResolve {
		t.Error("NPMResolve = true, want false when SYNAPSE_NPM_RESOLVE_ENABLED is set to false")
	}
	if !got.ManifestResolve {
		t.Error("ManifestResolve = false, want true when its variable is unset")
	}
}
