package postgres

import "testing"

func TestBuildPoolConfigSIEMCaptureFlag(t *testing.T) {
	const dsn = "postgres://user:password@localhost/synapse?sslmode=disable"
	for _, tc := range []struct {
		name    string
		enabled *bool
		want    string
	}{
		{name: "default on", want: "on"},
		{name: "explicit on", enabled: boolPointer(true), want: "on"},
		{name: "explicit off", enabled: boolPointer(false), want: "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := buildPoolConfig(dsn, PoolConfig{SIEMCaptureEnabled: tc.enabled})
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.ConnConfig.RuntimeParams["app.siem_capture_enabled"]; got != tc.want {
				t.Fatalf("capture setting = %q, want %q", got, tc.want)
			}
		})
	}
}

func boolPointer(value bool) *bool { return &value }

// TestSingletonLockKeyDistinctPerRole covers that the API and the worker get DIFFERENT
// advisory-lock keys, so they coexist (each a singleton in its own role) – while the same
// role yields the same key (a second same-role instance is refused).
func TestSingletonLockKeyDistinctPerRole(t *testing.T) {
	api, worker := singletonLockKey("api"), singletonLockKey("worker")
	if api == worker {
		t.Fatalf("api and worker must get distinct lock keys, both = %d", api)
	}
	if singletonLockKey("api") != api {
		t.Error("the same role must yield the same key (stable)")
	}
}
