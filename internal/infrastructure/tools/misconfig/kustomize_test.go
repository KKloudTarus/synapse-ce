package misconfig

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// mockKustomizeRunner returns a fixed rendered manifest for `kustomize build`, so the render->scan path is
// testable without the kustomize binary on the host.
type mockKustomizeRunner struct{ rendered []byte }

func (m mockKustomizeRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if len(spec.Args) >= 2 && spec.Args[0] == "build" {
		return ports.ToolResult{Stdout: m.rendered, ExitCode: 0}, nil
	}
	return ports.ToolResult{ExitCode: 1}, nil
}

const privilegedDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            privileged: true
`

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func countRule(fs []ports.MisconfigRawFinding, rule string) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	for _, f := range fs {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

// TestKustomizeRendersRootOnlyNoDoubleCount is the soundness test: an overlay references a base, so only the
// overlay is rendered (the base is not a render root), and the base's raw manifests are NOT scanned again, so
// a privileged container in the base is reported EXACTLY ONCE (from the render), never double-counted.
func TestKustomizeRendersRootOnlyNoDoubleCount(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"base/kustomization.yaml":          "resources:\n  - deployment.yaml\n",
		"base/deployment.yaml":             privilegedDeployment,
		"overlays/prod/kustomization.yaml": "resources:\n  - ../../base\n",
	})
	sc := New().WithKustomizeRunner(mockKustomizeRunner{rendered: []byte(privilegedDeployment)})
	got, err := sc.ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	priv := countRule(got, "kubernetes-privileged")
	if len(priv) != 1 {
		t.Fatalf("want exactly 1 privileged finding (render only, no double-count), got %d: %+v", len(priv), priv)
	}
	if !strings.Contains(priv[0].File, filepath.Join("overlays", "prod")) {
		t.Errorf("finding must be attributed to the rendered root overlay, got %q", priv[0].File)
	}
}

// TestKustomizeDisabledScansRaw confirms the default (no runner, not trusted-local) does not render and
// scans the manifests as ordinary Kubernetes YAML, so behavior is unchanged when kustomize is off.
func TestKustomizeDisabledScansRaw(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"base/kustomization.yaml": "resources:\n  - deployment.yaml\n",
		"base/deployment.yaml":    privilegedDeployment,
	})
	got, err := New().ScanConfigs(context.Background(), root) // kustomize disabled
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	priv := countRule(got, "kubernetes-privileged")
	if len(priv) != 1 {
		t.Fatalf("with kustomize disabled the raw manifest must be scanned once, got %d: %+v", len(priv), priv)
	}
	if !strings.Contains(priv[0].File, filepath.Join("base", "deployment.yaml")) {
		t.Errorf("disabled scan should attribute to the raw file, got %q", priv[0].File)
	}
}

// TestCollectKustomizationsRootsAndClosure verifies root detection and the transitive file closure: a base
// referenced by an overlay is not a root, and the overlay's closure covers the base's manifests (so they are
// not double-scanned), while a standalone kustomization is its own root.
func TestCollectKustomizationsRootsAndClosure(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"base/kustomization.yaml":          "resources:\n  - deployment.yaml\n",
		"base/deployment.yaml":             "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n",
		"overlays/prod/kustomization.yaml": "resources:\n  - ../../base\n",
		"standalone/kustomization.yaml":    "resources:\n  - svc.yaml\n",
		"standalone/svc.yaml":              "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n",
	})
	index, roots := collectKustomizations(context.Background(), root)
	rootSet := map[string]bool{}
	for _, r := range roots {
		rootSet[r] = true
	}
	overlay := filepath.Join(root, "overlays", "prod")
	base := filepath.Join(root, "base")
	standalone := filepath.Join(root, "standalone")
	if !rootSet[overlay] || rootSet[base] || !rootSet[standalone] {
		t.Fatalf("roots wrong: want overlay+standalone, not base; got %v", roots)
	}
	// The overlay's closure must reach the base's manifest (transitively) so it is skipped from the raw scan.
	closure := coveredFiles(overlay, index)
	if !closure[filepath.Join(base, "deployment.yaml")] {
		t.Errorf("overlay closure must cover the base's deployment.yaml; got %v", closure)
	}
	if !closure[filepath.Join(base, "kustomization.yaml")] {
		t.Errorf("overlay closure must cover the base kustomization file; got %v", closure)
	}
}

// TestKustomizeRenderFailureNoSuppression is the #1-bar guard: if a render FAILS (the runner errors), the raw
// scan of the would-be-covered manifests must still run, so a real finding is never hidden by a failed render.
func TestKustomizeRenderFailureNoSuppression(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"base/kustomization.yaml": "resources:\n  - deployment.yaml\n",
		"base/deployment.yaml":    privilegedDeployment,
	})
	// A runner that always fails to render.
	sc := New().WithKustomizeRunner(failingRunner{})
	got, err := sc.ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	priv := countRule(got, "kubernetes-privileged")
	if len(priv) != 1 {
		t.Fatalf("a failed render must NOT suppress the raw scan; want 1 privileged finding, got %d: %+v", len(priv), priv)
	}
	if !strings.Contains(priv[0].File, filepath.Join("base", "deployment.yaml")) {
		t.Errorf("finding must come from the raw scan of the source file, got %q", priv[0].File)
	}
}

// TestKustomizeExternalResourceNoDoubleCount confirms an overlay that references a manifest FILE outside its
// own directory (../../base/deployment.yaml) skips that file from the raw scan, so it is reported once.
func TestKustomizeExternalResourceNoDoubleCount(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"base/deployment.yaml":             privilegedDeployment, // a bare manifest, NOT its own kustomization
		"overlays/prod/kustomization.yaml": "resources:\n  - ../../base/deployment.yaml\n",
	})
	sc := New().WithKustomizeRunner(mockKustomizeRunner{rendered: []byte(privilegedDeployment)})
	got, err := sc.ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	priv := countRule(got, "kubernetes-privileged")
	if len(priv) != 1 {
		t.Fatalf("an externally-referenced manifest must be reported once (render only), got %d: %+v", len(priv), priv)
	}
}

// TestKustomizeNonReferencedFileStillScanned confirms a manifest that lives near a kustomization but is NOT
// one of its resources is still scanned raw (not silently skipped), so real findings are never missed.
func TestKustomizeNonReferencedFileStillScanned(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"app/kustomization.yaml": "resources:\n  - referenced.yaml\n",
		"app/referenced.yaml":    "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n",
		"app/orphan.yaml":        privilegedDeployment, // present in the dir but NOT a resource of the kustomization
	})
	sc := New().WithKustomizeRunner(mockKustomizeRunner{rendered: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n")})
	got, err := sc.ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	priv := countRule(got, "kubernetes-privileged")
	if len(priv) != 1 || !strings.Contains(priv[0].File, "orphan.yaml") {
		t.Fatalf("a non-referenced manifest must still be scanned raw; got %d: %+v", len(priv), priv)
	}
}

// failingRunner always reports a render failure.
type failingRunner struct{}

func (failingRunner) Run(_ context.Context, _ ports.ToolSpec) (ports.ToolResult, error) {
	return ports.ToolResult{ExitCode: 1}, nil
}

// TestKustomizePatchEffectRealBinary is an integration test with the real kustomize binary (skipped when it
// is not installed). It proves the value of rendering: an overlay's strategic-merge patch turns a safe base
// container into a privileged one, a misconfiguration that NEITHER the base manifest nor the patch file
// shows as a complete resource. Only the rendered output reveals it.
func TestKustomizePatchEffectRealBinary(t *testing.T) {
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize binary not on PATH")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"base/kustomization.yaml": "resources:\n  - deployment.yaml\n",
		"base/deployment.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            privileged: false
`,
		"overlays/prod/kustomization.yaml": `resources:
  - ../../base
patches:
  - target:
      kind: Deployment
      name: app
    patch: |
      - op: replace
        path: /spec/template/spec/containers/0/securityContext/privileged
        value: true
`,
	})
	got, err := New().WithKustomizeDirect().ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	priv := countRule(got, "kubernetes-privileged")
	if len(priv) != 1 {
		t.Fatalf("the overlay patch makes the container privileged; the render must flag it exactly once, got %d: %+v", len(priv), priv)
	}
}

// truncatingRunner reports a successful exit but TRUNCATED output.
type truncatingRunner struct{ rendered []byte }

func (r truncatingRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if len(spec.Args) >= 2 && spec.Args[0] == "build" {
		return ports.ToolResult{Stdout: r.rendered, ExitCode: 0, Truncated: true}, nil
	}
	return ports.ToolResult{ExitCode: 1}, nil
}

// TestKustomizeTruncatedRenderNoSuppression confirms a truncated render (trailing manifests dropped) is
// treated as a failure, so the source manifests fall back to the raw scan instead of being hidden.
func TestKustomizeTruncatedRenderNoSuppression(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"base/kustomization.yaml": "resources:\n  - deployment.yaml\n",
		"base/deployment.yaml":    privilegedDeployment,
	})
	sc := New().WithKustomizeRunner(truncatingRunner{rendered: []byte(privilegedDeployment)})
	got, err := sc.ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	priv := countRule(got, "kubernetes-privileged")
	if len(priv) != 1 || !strings.Contains(priv[0].File, filepath.Join("base", "deployment.yaml")) {
		t.Fatalf("a truncated render must fall back to the raw scan (no suppression); got %d: %+v", len(priv), priv)
	}
}

// selectiveRunner fails the build for a directory whose path ends with failSuffix, else renders successfully.
type selectiveRunner struct {
	rendered   []byte
	failSuffix string
}

func (r selectiveRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if len(spec.Args) >= 2 && spec.Args[0] == "build" {
		if r.failSuffix != "" && strings.HasSuffix(spec.Args[1], r.failSuffix) {
			return ports.ToolResult{ExitCode: 1}, nil
		}
		return ports.ToolResult{Stdout: r.rendered, ExitCode: 0}, nil
	}
	return ports.ToolResult{ExitCode: 1}, nil
}

// TestKustomizeSharedBaseFailedOverlayNoSuppression confirms that when two overlays share a base and one
// overlay FAILS to render, the shared base's manifests are still scanned raw (never suppressed by the other
// overlay's success), even at the cost of a harmless double count.
func TestKustomizeSharedBaseFailedOverlayNoSuppression(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"base/kustomization.yaml":       "resources:\n  - deployment.yaml\n",
		"base/deployment.yaml":          privilegedDeployment,
		"overlays/a/kustomization.yaml": "resources:\n  - ../../base\n",
		"overlays/b/kustomization.yaml": "resources:\n  - ../../base\n",
	})
	sc := New().WithKustomizeRunner(selectiveRunner{rendered: []byte(privilegedDeployment), failSuffix: filepath.Join("overlays", "b")})
	got, err := sc.ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	rawScanned := false
	for _, f := range countRule(got, "kubernetes-privileged") {
		if strings.Contains(f.File, filepath.Join("base", "deployment.yaml")) {
			rawScanned = true
		}
	}
	if !rawScanned {
		t.Fatalf("a base shared with a FAILED overlay must still be scanned raw (no suppression); findings=%+v", countRule(got, "kubernetes-privileged"))
	}
}
