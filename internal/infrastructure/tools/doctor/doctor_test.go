package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
)

func TestProbePackageJSONWithoutLockReportsNPMGap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"app","version":"1.0.0"}`)

	rep, err := Probe(context.Background(), dir, Options{
		LookPath:     fakeLookPath(map[string]string{"npm": "/bin/npm"}),
		Version:      fakeVersion("9.8.0"),
		JavaHomePath: filepath.Join(dir, "missing-java-home"),
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !hasMarker(rep.Inventory.Markers, "package.json") {
		t.Fatalf("package.json marker not detected: %#v", rep.Inventory.Markers)
	}
	sca := dimension(rep, "sca")
	if sca.Status != StatusPartial || !strings.Contains(sca.Reason, "npm is available") {
		t.Fatalf("SCA readiness = %#v, want partial npm-available gap", sca)
	}
}

func TestProbeGradleWithoutJDKReportsJDKGap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), `plugins { id 'java' }`)

	rep, err := Probe(context.Background(), dir, Options{
		LookPath:     fakeLookPath(map[string]string{"gradle": "/bin/gradle"}),
		Version:      fakeVersion("Gradle 9.0"),
		JavaHomePath: filepath.Join(dir, "missing-java-home"),
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	sca := dimension(rep, "sca")
	if sca.Status != StatusPartial || !strings.Contains(sca.NextStep, "Install a JDK") {
		t.Fatalf("SCA readiness = %#v, want JDK next step", sca)
	}
}

func TestProbePyprojectWithRegistryPythonLockIsFull(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pyproject.toml"), `[project]`)
	writeFile(t, filepath.Join(dir, "uv.lock"), `[[package]]`)

	rep, err := Probe(context.Background(), dir, Options{
		LookPath:     fakeLookPath(nil),
		Version:      fakeVersion(""),
		JavaHomePath: filepath.Join(dir, "missing-java-home"),
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !hasMarker(rep.Inventory.Markers, "pyproject.toml") || !hasMarker(rep.Inventory.Markers, "uv.lock") {
		t.Fatalf("python markers not detected: %#v", rep.Inventory.Markers)
	}
	if sca := dimension(rep, "sca"); sca.Status != StatusFull {
		t.Fatalf("SCA readiness = %#v, want full for pyproject.toml + uv.lock", sca)
	}
}

func TestProbeSkipsVendorAndUsesRootLockfile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3}`)
	writeFile(t, filepath.Join(dir, "vendor", "package-lock.json"), `{"lockfileVersion":3}`)

	rep, err := Probe(context.Background(), dir, Options{
		LookPath:     fakeLookPath(nil),
		Version:      fakeVersion(""),
		JavaHomePath: filepath.Join(dir, "missing-java-home"),
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := len(rep.Inventory.Markers); got != 1 {
		t.Fatalf("markers = %d (%#v), want only root lockfile", got, rep.Inventory.Markers)
	}
	if sca := dimension(rep, "sca"); sca.Status != StatusFull {
		t.Fatalf("SCA readiness = %#v, want full", sca)
	}
}

func TestProbeCodeQualitySidecarPartialWhenMissing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")

	rep, err := Probe(context.Background(), dir, Options{
		LookPath:     fakeLookPath(nil),
		Version:      fakeVersion(""),
		JavaHomePath: filepath.Join(dir, "missing-java-home"),
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	cq := dimension(rep, "code-quality")
	if cq.Status != StatusPartial || !strings.Contains(cq.NextStep, "SYNAPSE_AST_BIN") {
		t.Fatalf("code-quality readiness = %#v, want sidecar guidance", cq)
	}
}

func TestProbeEmptyInventoryUsesStableJSONArrays(t *testing.T) {
	dir := t.TempDir()

	rep, err := Probe(context.Background(), dir, Options{
		LookPath:     fakeLookPath(nil),
		Version:      fakeVersion(""),
		JavaHomePath: filepath.Join(dir, "missing-java-home"),
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if rep.Inventory.Markers == nil {
		t.Fatal("Inventory.Markers is nil, want empty slice")
	}
	b, err := json.Marshal(rep.Inventory)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	if !strings.Contains(string(b), `"markers":[]`) {
		t.Fatalf("inventory JSON = %s, want markers: []", b)
	}
}

func TestProbeTruncatesOnDirectoryEntryCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 4; i++ {
		if err := os.MkdirAll(filepath.Join(dir, "empty", string(rune('a'+i))), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	rep, err := Probe(context.Background(), dir, Options{
		LookPath:     fakeLookPath(nil),
		Version:      fakeVersion(""),
		JavaHomePath: filepath.Join(dir, "missing-java-home"),
		MaxEntries:   2,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !rep.Inventory.Truncated {
		t.Fatal("Inventory.Truncated = false, want true when directory entry cap is exceeded")
	}
}

func TestPythonLockMarkersStayRegistryKnown(t *testing.T) {
	reg, err := ownsbom.DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}
	registryMarkers := reg.MarkerEcosystems()
	for _, marker := range pythonLockMarkers() {
		if _, ok := registryMarkers[strings.ToLower(marker)]; !ok {
			t.Fatalf("python lock marker %q is not claimed by the ownsbom registry", marker)
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func fakeLookPath(found map[string]string) func(string) (string, error) {
	return func(name string) (string, error) {
		if p, ok := found[name]; ok {
			return p, nil
		}
		return "", errors.New("not found")
	}
}

func fakeVersion(v string) func(context.Context, string, ...string) (string, error) {
	return func(context.Context, string, ...string) (string, error) {
		return v, nil
	}
}

func hasMarker(markers []MarkerHit, name string) bool {
	for _, m := range markers {
		if strings.EqualFold(m.Name, name) {
			return true
		}
	}
	return false
}

func dimension(rep Report, name string) DimensionReadiness {
	for _, d := range rep.Dimensions {
		if d.Dimension == name {
			return d
		}
	}
	return DimensionReadiness{}
}
