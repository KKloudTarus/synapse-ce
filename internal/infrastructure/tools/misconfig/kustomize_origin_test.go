package misconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// TestKustomizeOriginIndexResolvesRenderedDocuments pins the attribution fix. `kustomize build` merges
// every resource into one stream, so a finding from the render used to carry kustomization.yaml, the one
// file a reader cannot open to fix anything. Found on a real service where six manifests contributed
// findings and all of them were reported against the aggregator.
func TestKustomizeOriginIndexResolvesRenderedDocuments(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "deploy", "k8s")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - api.yaml\n  - worker.yaml\n")
	write("api.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: prod\n")
	write("worker.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: worker\n")

	origin := kustomizeOriginIndex(root, dir)
	if origin == nil {
		t.Fatal("no origin index built from a kustomization that references two manifests")
	}

	api := k8sDoc{Kind: "Deployment"}
	api.Metadata.Name, api.Metadata.Namespace = "api", "prod"
	got, line := origin(api)
	if got != "deploy/k8s/api.yaml" {
		t.Errorf("api Deployment resolved to %q, want deploy/k8s/api.yaml", got)
	}
	// The line is the one that file declares the document on, never a position in the render stream.
	if line <= 0 {
		t.Errorf("a remapped document must carry a line of its own file, got %d", line)
	}

	// An omitted namespace keys as "default", matching how the scanner reads a manifest.
	worker := k8sDoc{Kind: "Deployment"}
	worker.Metadata.Name = "worker"
	if got, _ := origin(worker); got != "deploy/k8s/worker.yaml" {
		t.Errorf("worker Deployment resolved to %q, want deploy/k8s/worker.yaml", got)
	}

	// A document no referenced file declares, which is what a configMapGenerator or a patch-renamed
	// resource looks like, must resolve to nothing so the caller keeps the aggregator path rather than
	// being handed a wrong file.
	generated := k8sDoc{Kind: "ConfigMap"}
	generated.Metadata.Name = "generated-settings"
	if got, _ := origin(generated); got != "" {
		t.Errorf("a document no file declares resolved to %q, want the empty string", got)
	}
}

// TestK8sDocKeyRefusesAnUnnamedDocument pins that an unnamed document cannot collide with another.
func TestK8sDocKeyRefusesAnUnnamedDocument(t *testing.T) {
	var unnamed k8sDoc
	unnamed.Kind = "Deployment"
	if k := k8sDocKey(unnamed); k != "" {
		t.Errorf("unnamed document keyed as %q; it must not be matchable", k)
	}
	var kindless k8sDoc
	kindless.Metadata.Name = "x"
	if k := k8sDocKey(kindless); k != "" {
		t.Errorf("kindless document keyed as %q; it must not be matchable", k)
	}
}
