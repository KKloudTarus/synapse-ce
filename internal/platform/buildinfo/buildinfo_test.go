package buildinfo

import "testing"

// A release build injects the tag into the package-level version via ldflags; App must prefer it over
// the compiled build metadata so a released binary reports its real version (recorded for scan
// reproducibility) rather than "devel".
func TestAppPrefersInjectedVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "v1.2.3"
	if got := App(); got != "v1.2.3" {
		t.Errorf("App() = %q, want the injected v1.2.3", got)
	}
}

// With no injected version (go run / go build / go test), App falls back to build metadata and must
// never return an empty string.
func TestAppFallsBackWithoutInjectedVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = ""
	if got := App(); got == "" {
		t.Error("App() returned empty; want a non-empty fallback (e.g. \"devel\")")
	}
}
