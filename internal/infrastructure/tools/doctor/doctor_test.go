package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

func TestProbeMisconfigRendererReadiness(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		tools    map[string]string
		want     Status
		nextTool string
	}{
		{"chart missing helm", map[string]string{"Chart.yaml": "apiVersion: v2\nname: app\n"}, nil, StatusPartial, "helm"},
		{"chart with helm", map[string]string{"Chart.yaml": "apiVersion: v2\nname: app\n"}, map[string]string{"helm": "/bin/helm"}, StatusFull, ""},
		{"overlay missing kustomize", map[string]string{"overlay/kustomization.yaml": "resources:\n- ../base\n"}, nil, StatusPartial, "kustomize"},
		{"overlay with kustomize", map[string]string{"overlay/Kustomization": "resources: []\n"}, map[string]string{"kustomize": "/bin/kustomize"}, StatusFull, ""},
		{"ordinary manifests", map[string]string{"pod.yaml": "kind: Pod\n", "config.json": "{}", "main.tf": "terraform {}\n"}, nil, StatusFull, ""},
		{"library only", map[string]string{"Chart.yaml": "type: library\n"}, nil, StatusFull, ""},
		{"invalid metadata is a gap", map[string]string{"Chart.yaml": "type: [\n"}, nil, StatusPartial, "helm"},
		{"vendored chart only", map[string]string{"charts/child/Chart.yaml": "name: child\n"}, nil, StatusFull, ""},
		{"nested independent chart", map[string]string{"app/Chart.yaml": "name: app\n", "app/charts/child/Chart.yaml": "name: child\n"}, nil, StatusPartial, "helm"},
		{"both renderers missing", map[string]string{"Chart.yaml": "name: app\n", "overlay/kustomization.yml": "resources: []\n"}, nil, StatusPartial, "helm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tt.files {
				writeFile(t, filepath.Join(dir, name), body)
			}
			rep, err := Probe(context.Background(), dir, Options{
				LookPath: fakeLookPath(tt.tools), Version: fakeVersion("v1"),
				JavaHomePath: filepath.Join(dir, "missing-java-home"),
			})
			if err != nil {
				t.Fatal(err)
			}
			got := dimension(rep, "misconfig")
			if got.Status != tt.want || (tt.nextTool != "" && !strings.Contains(strings.ToLower(got.NextStep), tt.nextTool)) {
				t.Fatalf("misconfig = %#v, want %s and guidance for %q", got, tt.want, tt.nextTool)
			}
			if hasMarker(rep.Inventory.Markers, "Chart.yaml") {
				t.Fatal("Chart.yaml must not become a dependency marker")
			}
			if sca := dimension(rep, "sca"); sca.Status != StatusUnavailable {
				t.Fatalf("SCA readiness changed by render inputs: %#v", sca)
			}
		})
	}
}

func TestProbeMisconfigRendererExecutionReadiness(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renderer fixtures require POSIX executable scripts")
	}
	for _, renderer := range []struct {
		name   string
		marker string
		body   string
	}{
		{"helm", "Chart.yaml", "name: app\n"},
		{"kustomize", "kustomization.yaml", "resources: []\n"},
	} {
		for _, fixture := range []struct {
			name string
			body string
			want Status
		}{
			{"invalid executable", "not an executable image\n", StatusPartial},
			{"nonzero exit", "#!/bin/sh\nprintf 'secret renderer output\\n' >&2\nexit 1\n", StatusPartial},
			{"timeout", "#!/bin/sh\nexec sleep 10\n", StatusPartial},
			{"successful empty version", "#!/bin/sh\nexit 0\n", StatusFull},
		} {
			t.Run(renderer.name+"/"+fixture.name, func(t *testing.T) {
				dir := t.TempDir()
				writeFile(t, filepath.Join(dir, renderer.marker), renderer.body)
				executable := filepath.Join(t.TempDir(), renderer.name)
				if err := os.WriteFile(executable, []byte(fixture.body), 0o755); err != nil {
					t.Fatal(err)
				}
				rep, err := Probe(context.Background(), dir, Options{
					LookPath:     fakeLookPath(map[string]string{renderer.name: executable}),
					JavaHomePath: filepath.Join(dir, "missing-java-home"),
				})
				if err != nil {
					t.Fatal(err)
				}
				tool := toolByName(rep.Tools, renderer.name)
				got := dimension(rep, "misconfig")
				if !tool.Found || tool.Path != executable || got.Status != fixture.want {
					t.Fatalf("tool = %#v, misconfig = %#v; want found path and %s", tool, got, fixture.want)
				}
				if fixture.want == StatusPartial && (!strings.Contains(strings.ToLower(got.NextStep), renderer.name) || tool.Detail == "") {
					t.Fatalf("unusable renderer needs detail and actionable guidance: tool = %#v, misconfig = %#v", tool, got)
				}
				if strings.Contains(tool.Detail+got.Reason+got.NextStep, "secret renderer output") {
					t.Fatal("renderer output leaked into readiness report")
				}
				if fixture.want == StatusPartial {
					if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
						t.Fatal(err)
					}
					restored, err := Probe(context.Background(), dir, Options{
						LookPath:     fakeLookPath(map[string]string{renderer.name: executable}),
						JavaHomePath: filepath.Join(dir, "missing-java-home"),
					})
					if err != nil {
						t.Fatal(err)
					}
					if got := dimension(restored, "misconfig"); got.Status != StatusFull {
						t.Fatalf("repaired renderer must restore readiness: %#v", got)
					}
				}
			})
		}
	}
}

func TestProbePlainManifestsIgnoreUnusableRenderers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renderer fixtures require POSIX executable scripts")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pod.yaml"), "kind: Pod\n")
	executable := filepath.Join(t.TempDir(), "broken")
	if err := os.WriteFile(executable, []byte("invalid executable image\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rep, err := Probe(context.Background(), dir, Options{
		LookPath:     fakeLookPath(map[string]string{"helm": executable, "kustomize": executable}),
		JavaHomePath: filepath.Join(dir, "missing-java-home"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := dimension(rep, "misconfig"); got.Status != StatusFull {
		t.Fatalf("plain manifests do not need renderers: %#v", got)
	}
}

func TestProbeMisconfigTruncatedInventoryIsPartial(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.yaml"), "kind: Pod\n")
	writeFile(t, filepath.Join(dir, "z", "Chart.yaml"), "name: app\n")
	rep, err := Probe(context.Background(), dir, Options{
		LookPath: fakeLookPath(nil), Version: fakeVersion(""),
		JavaHomePath: filepath.Join(dir, "missing-java-home"), MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Inventory.Truncated || dimension(rep, "misconfig").Status != StatusPartial {
		t.Fatalf("truncated inventory must not imply full readiness: %#v", rep)
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
