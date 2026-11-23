package sca

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/cache/sbomcache"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMavenExternalRepositoryChangesRegenerateInventory(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	repo := filepath.Join(t.TempDir(), "repository")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("MAVEN_REPO_LOCAL", repo)
	projectDir := filepath.Join(workspace, "nested")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	project := `<project><groupId>g</groupId><artifactId>app</artifactId><version>1.0</version><dependencies><dependency><groupId>g</groupId><artifactId>widget</artifactId><version>1.0</version></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(projectDir, "pom.xml"), []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}
	registry, err := ownsbom.DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	producer := &countedRealProducer{generator: registry, identity: registry}
	cache := &observedRealCache{cache: sbomcache.New(t.TempDir())}
	svc := NewService(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: workspace}, &fakeDetector{}, producer, nil, nil, fakeLic{}, nil)
	svc.SetSBOMCache(cache)
	scan := func(wantLeaf string) {
		t.Helper()
		result, err := svc.Scan(ctx, "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
		if err != nil {
			t.Fatal(err)
		}
		doc := result.SBOM
		if doc == nil || doc.Source != "ownsbom" || doc.GeneratorVersion == "" || result.ToolVersions[sbomGeneratorKey] != doc.GeneratorVersion || result.Manifest.ToolVersions[sbomGeneratorKey] != doc.GeneratorVersion {
			t.Fatalf("incorrect producer provenance: SBOM=%+v tools=%v manifest=%v", doc, result.ToolVersions, result.Manifest.ToolVersions)
		}
		widget, leaf, edge := false, false, false
		for _, c := range doc.Components {
			if c.Name == "g:widget" && c.Version == "1.0" {
				widget = true
			}
			if c.Name == "g:leaf" && c.Version == wantLeaf {
				leaf = true
			}
			if c.Name == "g:leaf" && c.Version != wantLeaf {
				t.Fatalf("stale leaf: %+v", c)
			}
		}
		for _, d := range doc.Dependencies {
			if d.Ref == "pkg:maven/g/widget@1.0" {
				for _, to := range d.DependsOn {
					if to == "pkg:maven/g/leaf@"+wantLeaf {
						edge = true
					}
				}
			}
		}
		if !widget || (wantLeaf == "" && (leaf || edge)) || (wantLeaf != "" && (!leaf || !edge)) {
			t.Fatalf("want leaf %q: components=%+v dependencies=%+v", wantLeaf, doc.Components, doc.Dependencies)
		}
	}
	scan("")
	pomPath := filepath.Join(repo, "g", "widget", "1.0", "widget-1.0.pom")
	if err := os.MkdirAll(filepath.Dir(pomPath), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"2.0", "3.0"} {
		pom := fmt.Sprintf(`<project><groupId>g</groupId><artifactId>widget</artifactId><version>1.0</version><dependencies><dependency><groupId>g</groupId><artifactId>leaf</artifactId><version>%s</version></dependency></dependencies></project>`, version)
		if err := os.WriteFile(pomPath, []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}
		scan(version)
	}
	if producer.calls != 3 || cache.loads != 0 || cache.stores != 0 || cache.hits != 0 || len(cache.errs) != 0 {
		t.Fatalf("Maven scans must bypass cache: calls=%d cache=%+v", producer.calls, cache)
	}
}

func TestOwnedNPMInventoryRemainsCacheable(t *testing.T) {
	workspace := t.TempDir()
	lock := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4"}},"node_modules/lodash":{"version":"4.17.0"}}}`
	if err := os.WriteFile(filepath.Join(workspace, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	registry, err := ownsbom.DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	producer := &countedRealProducer{generator: registry, identity: registry}
	cache := &observedRealCache{cache: sbomcache.New(t.TempDir())}
	svc := NewService(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: workspace}, &fakeDetector{}, producer, nil, nil, fakeLic{}, nil)
	svc.SetSBOMCache(cache)
	for range 2 {
		result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range result.SBOM.Components {
			if c.Name == "lodash" && c.Version == "4.17.0" {
				found = true
			}
		}
		if !found || result.SBOM.Source != "ownsbom" || result.ToolVersions[sbomGeneratorKey] != result.SBOM.GeneratorVersion || result.Manifest.ToolVersions[sbomGeneratorKey] != result.SBOM.GeneratorVersion {
			t.Fatalf("incorrect cached npm inventory or provenance: %+v", result)
		}
	}
	if producer.calls != 1 || cache.loads != 2 || cache.hits != 1 || cache.stores != 1 || len(cache.errs) != 0 {
		t.Fatalf("npm cache behavior: calls=%d cache=%+v", producer.calls, cache)
	}
}
