package bincat

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/license"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

type catalogAcceptanceClock struct{}

func (catalogAcceptanceClock) Now() time.Time { return time.Unix(0, 0).UTC() }

type catalogAcceptanceAudit struct{}

func (catalogAcceptanceAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type catalogAcceptanceAcquirer struct{ dir, root string }

func (a catalogAcceptanceAcquirer) Acquire(context.Context, ports.AcquireRequest) (*ports.Workspace, error) {
	return &ports.Workspace{Dir: a.dir, RootFS: a.root, Image: &sbom.ImageInfo{}, Cleanup: func() error { return nil }}, nil
}

type catalogAcceptanceDetector struct{}

func (catalogAcceptanceDetector) Detect(context.Context, string) ([]ports.DetectedLanguage, error) {
	return nil, nil
}

func catalogAcceptanceScan(t *testing.T, root string) *sca.ScanResult {
	t.Helper()
	ctx := context.Background()
	e, err := engagement.New("e1", "", "test", "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	e.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetRepo, Value: "myrepo"}}}
	repo := memory.NewEngagementRepository()
	if err := repo.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	registry, err := ownsbom.DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	svc := sca.NewService(repo, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{},
		catalogAcceptanceClock{}, catalogAcceptanceAudit{}, shared.SeverityHigh, 0,
		catalogAcceptanceAcquirer{dir: t.TempDir(), root: root}, catalogAcceptanceDetector{}, registry,
		nil, nil, license.New(), nil)
	svc.SetInstalledPackageCataloger(Cataloger{})
	result, err := svc.Scan(ctx, "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestServiceInstalledCatalogBoundsAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name       string
		files      int
		components int
		want       int
		bound      string
	}{
		{name: "file bound", files: 1, components: 100, want: 1, bound: "file-walk cap"},
		{name: "component bound", files: 100, components: 1, want: 1, bound: "component cap"},
		{name: "complete", files: 100, components: 100, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			distInfo(t, root, "alpha", "1.0.0")
			distInfo(t, root, "beta", "2.0.0")
			withBounds(t, tc.files, tc.components)
			result := catalogAcceptanceScan(t, root)
			if result.SBOM == nil {
				t.Fatal("scan returned no SBOM")
			}
			found := map[string]bool{}
			for _, component := range result.SBOM.Components {
				found[component.PURL] = true
			}
			if len(found) != tc.want || !found["pkg:pypi/alpha@1.0.0"] || (tc.want == 2 && !found["pkg:pypi/beta@2.0.0"]) {
				t.Fatalf("installed components = %+v", result.SBOM.Components)
			}
			var inventory scanrun.EngineOutcome
			var hasInventory bool
			for _, outcome := range result.EngineOutcomes {
				if outcome.Engine == "inventory" {
					inventory, hasInventory = outcome, true
				}
			}
			if !hasInventory {
				t.Fatal("missing inventory outcome")
			}
			var gap bool
			for _, warning := range result.SourceWarnings {
				if strings.Contains(warning, "lower bound") {
					gap = true
					if tc.bound != "" && !strings.Contains(warning, tc.bound) {
						t.Fatalf("warning does not name %s: %q", tc.bound, warning)
					}
				}
			}
			if tc.bound != "" {
				if !gap || result.Completeness.Confident || inventory.Coverage != scanrun.CoveragePartial || inventory.Reason != scanrun.ReasonAnalysisIncomplete {
					t.Fatalf("bounded scan: completeness=%+v inventory=%+v warnings=%q", result.Completeness, inventory, result.SourceWarnings)
				}
			} else if gap || inventory.Coverage != scanrun.CoverageComplete {
				t.Fatalf("complete catalog degraded inventory: %+v warnings=%q", inventory, result.SourceWarnings)
			}
		})
	}
}

func TestServiceInstalledCatalogUnreadableAcceptance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits cannot stage read denial on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("run as an unprivileged UID to exercise filesystem read denial")
	}
	for _, kind := range []string{"directory", "python metadata", "node manifest", "gem specification", "java archive", "unclassified file"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			distInfo(t, root, "alpha", "1.0.0")
			var blocked string
			switch kind {
			case "directory":
				blocked = filepath.Join(root, "opt", "blocked")
				if err := os.MkdirAll(blocked, 0o755); err != nil {
					t.Fatal(err)
				}
				distInfo(t, blocked, "beta", "2.0.0")
			case "python metadata":
				distInfo(t, root, "beta", "2.0.0")
				blocked = filepath.Join(root, "usr", "lib", "python3", "beta-2.0.0.dist-info", "METADATA")
			case "node manifest":
				blocked = filepath.Join(root, "app", "node_modules", "beta", "package.json")
			case "gem specification":
				blocked = filepath.Join(root, "usr", "lib", "ruby", "gems", "specifications", "beta.gemspec")
			case "java archive":
				blocked = filepath.Join(root, "opt", "beta.jar")
				writeJar(t, blocked, map[string]string{"META-INF/maven/example/beta/pom.properties": "groupId=example\nartifactId=beta\nversion=2.0.0\n"})
			case "unclassified file":
				blocked = filepath.Join(root, "opt", "unclassified")
			}
			if kind == "node manifest" || kind == "gem specification" || kind == "unclassified file" {
				if err := os.MkdirAll(filepath.Dir(blocked), 0o755); err != nil {
					t.Fatal(err)
				}
				body := `{"name":"beta","version":"2.0.0"}`
				if kind == "gem specification" {
					body = "Gem::Specification.new do |s|\n  s.name = \"beta\"\n  s.version = \"2.0.0\"\nend\n"
				}
				if err := os.WriteFile(blocked, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(blocked, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
			result := catalogAcceptanceScan(t, root)
			if result.SBOM == nil || len(result.SBOM.Components) != 1 || result.SBOM.Components[0].PURL != "pkg:pypi/alpha@1.0.0" {
				t.Fatalf("readable installed package was not retained: %+v", result.SBOM)
			}
			var partialInventory bool
			for _, outcome := range result.EngineOutcomes {
				if outcome.Engine == "inventory" && outcome.Required && outcome.Coverage == scanrun.CoveragePartial && outcome.Reason == scanrun.ReasonAnalysisIncomplete {
					partialInventory = true
				}
			}
			if !partialInventory || result.EngineCoverage.Status != scanrun.CoveragePartial || result.Completeness.Confident || !strings.Contains(strings.Join(result.SourceWarnings, "\n"), "1 root-filesystem entries could not be read") {
				t.Fatalf("unreadable %s was presented as complete: completeness=%+v aggregate=%+v inventory=%+v warnings=%q", kind, result.Completeness, result.EngineCoverage, result.EngineOutcomes, result.SourceWarnings)
			}
		})
	}
}
