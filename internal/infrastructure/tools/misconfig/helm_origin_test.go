package misconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// Every finding a chart produces used to carry the chart's Chart.yaml and a line number into the rendered
// stream, which is the one path a reader cannot open to fix anything: a chart with forty templates reported
// forty templates' findings at one file. `helm template` already prints the answer above each document.
func TestHelmOriginMapsAFindingToItsTemplate(t *testing.T) {
	chartDir := t.TempDir()
	mustWrite(t, filepath.Join(chartDir, "Chart.yaml"), "apiVersion: v2\nname: app\nversion: 0.1.0\n")
	mustWrite(t, filepath.Join(chartDir, "templates", "deployment.yaml"), "# rendered by helm\n")
	mustWrite(t, filepath.Join(chartDir, "templates", "rbac.yaml"), "# rendered by helm\n")

	rendered := []byte(`---
# Source: app/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
---
# Source: app/templates/rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: api
`)
	origin := helmOriginIndex(chartDir, "charts/app", rendered)
	if origin == nil {
		t.Fatal("a render naming its sources must produce an origin index")
	}
	deployment := k8sDoc{Kind: "Deployment"}
	deployment.Metadata.Name = "api"
	deployment.Metadata.Namespace = "prod"
	if got := origin(deployment); got != "charts/app/templates/deployment.yaml" {
		t.Errorf("the Deployment must map to its own template, got %q", got)
	}
	role := k8sDoc{Kind: "ClusterRole"}
	role.Metadata.Name = "api"
	if got := origin(role); got != "charts/app/templates/rbac.yaml" {
		t.Errorf("the ClusterRole must map to its own template, got %q", got)
	}
}

// A dependency declared with an alias renders under the alias, so the Source path names a directory that does
// not exist. The alias is resolved back to the directory the subchart was vendored under.
func TestHelmOriginResolvesASubchartAlias(t *testing.T) {
	chartDir := t.TempDir()
	mustWrite(t, filepath.Join(chartDir, "Chart.yaml"),
		"apiVersion: v2\nname: parent\nversion: 0.1.0\ndependencies:\n  - name: real-operator\n    version: 1.0.0\n    alias: operator\n")
	mustWrite(t, filepath.Join(chartDir, "charts", "real-operator", "templates", "clusterrole.yaml"), "# rendered\n")

	rendered := []byte(`---
# Source: parent/charts/operator/templates/clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: operator
`)
	origin := helmOriginIndex(chartDir, "base/parent", rendered)
	if origin == nil {
		t.Fatal("an aliased subchart must still produce an origin index")
	}
	role := k8sDoc{Kind: "ClusterRole"}
	role.Metadata.Name = "operator"
	want := "base/parent/charts/real-operator/templates/clusterrole.yaml"
	if got := origin(role); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// A Source path this does not understand must leave the finding on the aggregator path rather than move it to
// a path that opens nothing, and a path escaping the chart directory is refused outright.
func TestHelmOriginRefusesAPathItCannotOpen(t *testing.T) {
	chartDir := t.TempDir()
	mustWrite(t, filepath.Join(chartDir, "Chart.yaml"), "apiVersion: v2\nname: app\nversion: 0.1.0\n")

	absent := []byte(`---
# Source: app/templates/gone.yaml
apiVersion: v1
kind: Service
metadata:
  name: api
`)
	if origin := helmOriginIndex(chartDir, "charts/app", absent); origin != nil {
		t.Error("a Source naming a file that is not on disk must contribute no origin")
	}

	escaping := []byte(`---
# Source: app/../../etc/passwd
apiVersion: v1
kind: Service
metadata:
  name: api
`)
	if got := helmSourceComment(escaping); got != "" {
		t.Errorf("a Source climbing out of the chart must be refused, got %q", got)
	}
	if got := helmSourceComment([]byte("apiVersion: v1\nkind: Service\n# Source: app/templates/x.yaml\n")); got != "" {
		t.Errorf("only the leading comment block can name a source, got %q", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
