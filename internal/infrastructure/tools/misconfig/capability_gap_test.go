package misconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Kubernetes resource is the resource it declares, whichever syntax declared it. The JSON form used to
// pass the sniff that only recognised YAML, so an identical privileged Pod produced no finding at all.
func TestKubernetesJSONProducesTheSameFindings(t *testing.T) {
	yamlPod := `apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: prod
spec:
  containers:
    - name: app
      image: app@sha256:0000000000000000000000000000000000000000000000000000000000000000
      securityContext:
        privileged: true
`
	jsonPod := `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "app", "namespace": "prod"},
  "spec": {
    "containers": [
      {
        "name": "app",
        "image": "app@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "securityContext": {"privileged": true}
      }
    ]
  }
}
`
	fromYAML := ruleIDs(scan(t, map[string]string{"pod.yaml": yamlPod}))
	fromJSON := ruleIDs(scan(t, map[string]string{"pod.json": jsonPod}))
	if _, ok := fromJSON["kubernetes-privileged"]; !ok {
		t.Fatalf("a privileged Pod authored as JSON must be reported, got %v", keys(fromJSON))
	}
	for id := range fromYAML {
		if _, ok := fromJSON[id]; !ok {
			t.Errorf("the JSON manifest must produce %q just as the YAML one does, got %v", id, keys(fromJSON))
		}
	}
}

// A chart nobody rendered is not a chart with nothing wrong. With rendering off, its values were never
// applied, and the report has to say so rather than return an empty, clean-looking result.
func TestHelmRenderingDisabledIsACoverageGap(t *testing.T) {
	root := t.TempDir()
	chart := filepath.Join(root, "app")
	if err := os.MkdirAll(filepath.Join(chart, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"Chart.yaml":            "apiVersion: v2\nname: app\nversion: 0.1.0\n",
		"values.yaml":           "privileged: true\n",
		"templates/deploy.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n  containers:\n    - name: app\n      image: app:1\n      securityContext:\n        privileged: {{ .Values.privileged }}\n",
	} {
		if err := os.WriteFile(filepath.Join(chart, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report, err := New().ScanConfigsReport(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.UnrenderedCharts != 1 {
		t.Fatalf("a chart left unrendered must be counted, got %d", report.UnrenderedCharts)
	}
	if len(report.ChartRenderReasons) == 0 || !strings.Contains(report.ChartRenderReasons[0], "not enabled") {
		t.Fatalf("the reason must say rendering was not enabled, got %v", report.ChartRenderReasons)
	}
}

// An overlay nobody rendered has unapplied patches. The base manifests are still scanned raw, so this is a
// coverage gap and not a lost scan.
func TestKustomizeRenderingDisabledIsACoverageGap(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "overlay"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"base/kustomization.yaml": "resources:\n  - pod.yaml\n",
		"base/pod.yaml": `apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: prod
spec:
  containers:
    - name: app
      image: app@sha256:0000000000000000000000000000000000000000000000000000000000000000
`,
		"overlay/kustomization.yaml": "resources:\n  - ../base\npatches:\n  - path: privileged.yaml\n",
	}
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report, err := New().ScanConfigsReport(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.UnassessedInputs != 2 {
		t.Fatalf("both kustomizations must be reported as unassessed, got %d", report.UnassessedInputs)
	}
	if len(report.UnassessedReasons) == 0 || !strings.Contains(report.UnassessedReasons[0], "not enabled") {
		t.Fatalf("the reason must say rendering was not enabled, got %v", report.UnassessedReasons)
	}
	if len(report.Findings) == 0 {
		t.Fatal("the base manifest must still be scanned raw")
	}
}

// A tree with no templated input has no capability gap, or the warning becomes noise on every repository.
func TestNoTemplatedInputMeansNoCapabilityGap(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(`apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: prod
spec:
  containers:
    - name: app
      image: app@sha256:0000000000000000000000000000000000000000000000000000000000000000
`), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := New().ScanConfigsReport(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.UnassessedInputs != 0 || report.UnrenderedCharts != 0 {
		t.Fatalf("a plain manifest tree has no capability gap, got %d unassessed / %d unrendered",
			report.UnassessedInputs, report.UnrenderedCharts)
	}
}
