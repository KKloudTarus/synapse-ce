package sca

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ownershipcapture"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestOwnershipSCAManifestsRetainAllIntroducers(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"payments/package.json", "identity/package.json", "node_modules/transitive/package.json"} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	components := []sbom.Component{{Name: "payments", Version: "1", Location: "payments/package.json"}, {Name: "identity", Version: "1", Location: filepath.Join(root, "identity", "package.json")}, {Name: "shared", Version: "2", PURL: "pkg:npm/shared@2", Location: "node_modules/transitive/package.json"}}
	ids := []string{sbom.ComponentID("payments", "1", ""), sbom.ComponentID("identity", "1", ""), sbom.ComponentID("shared", "2", "pkg:npm/shared@2")}
	doc := &sbom.SBOM{Components: components, Dependencies: []sbom.Dependency{{Ref: ids[0], DependsOn: []string{ids[2]}}, {Ref: ids[1], DependsOn: []string{ids[2]}}}}
	svc := &Service{ownershipReader: ownershipcapture.New(nil)}
	v := vulnerability.Vulnerability{Component: "shared", Version: "2", PackagePURL: "pkg:npm/shared@2"}
	evidence := svc.ownershipManifestPaths(root, newOwnershipManifestIndex(doc), v)
	if evidence.Invalid || !reflect.DeepEqual(evidence.Paths, []string{"identity/package.json", "payments/package.json"}) {
		t.Fatalf("multi-root provenance: %+v", evidence)
	}
	// Missing one introducing manifest may not silently choose the remaining team.
	doc.Components[1].Location = ""
	evidence = svc.ownershipManifestPaths(root, newOwnershipManifestIndex(doc), v)
	if !evidence.Invalid {
		t.Fatalf("partial roots accepted: %+v", evidence)
	}
	doc.Components[1].Location = "../../identity/package.json"
	evidence = svc.ownershipManifestPaths(root, newOwnershipManifestIndex(doc), v)
	if !evidence.Invalid {
		t.Fatal("traversal accepted")
	}
	// Same name/version across ecosystems needs an exact component identity.
	doc.Components = append(doc.Components, sbom.Component{Name: "shared", Version: "2", PURL: "pkg:pypi/shared@2"})
	v.PackagePURL = ""
	if got := svc.ownershipManifestPaths(root, newOwnershipManifestIndex(doc), v); !got.Invalid || len(got.Paths) != 0 {
		t.Fatalf("ambiguous component selected: %+v", got)
	}
}

type ownershipCaptureStore struct {
	t       *testing.T
	acq     *fakeAcquirer
	sources []ports.OwnershipSourceRecord
	ready   bool
	fail    bool
}

func (s *ownershipCaptureStore) SaveOwnershipSource(_ context.Context, source ports.OwnershipSourceRecord) error {
	if s.acq.cleaned != 0 {
		s.t.Fatal("source captured after workspace cleanup")
	}
	if s.fail {
		return errors.New("capture storage unavailable")
	}
	s.sources = append(s.sources, source)
	return nil
}
func (s *ownershipCaptureStore) MarkOwnershipSourceReady(_ context.Context, eng, id shared.ID) error {
	if len(s.sources) != 1 || s.sources[0].ID != id || s.sources[0].EngagementID != eng || s.acq.cleaned != 0 {
		s.t.Fatal("readiness lost scan association")
	}
	s.ready = true
	return nil
}

func TestOwnershipCaptureRunsBeforeCleanupAndStorageFailsClosed(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "storage failure"}[failure], func(t *testing.T) {
			acq := &fakeAcquirer{dir: t.TempDir()}
			svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Now().UTC()}, acq, &fakeAudit{}, &fakeDetector{})
			svc.ids = &sequenceIDs{}
			store := &ownershipCaptureStore{t: t, acq: acq, fail: failure}
			if err := svc.SetOwnershipSource(ownershipcapture.New(nil), store); err != nil {
				t.Fatal(err)
			}
			_, err := svc.Scan(shared.WithTenant(context.Background(), "default"), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
			if (err != nil) != failure {
				t.Fatalf("scan error: %v", err)
			}
			if acq.cleaned != 1 {
				t.Fatalf("cleanup count=%d", acq.cleaned)
			}
			if failure {
				if store.ready {
					t.Fatal("failed capture marked ready")
				}
				return
			}
			if !store.ready || store.sources[0].Reason != "unpinned_source" || len(store.sources[0].Snapshots) != 0 {
				t.Fatalf("unpinned workspace became authoritative: %+v", store.sources)
			}
		})
	}
}

func TestOwnershipImportedSBOMNeverUsesReportedPaths(t *testing.T) {
	svc := &Service{ownershipReader: ownershipcapture.New(nil)}
	source := &ports.OwnershipSourceRecord{ID: "imported", EngagementID: "eng", Repository: "imported-sbom", Reason: "imported_sbom_without_source"}
	result := &ScanResult{Findings: []finding.Finding{{ID: "fid", EngagementID: "eng", DedupKey: "finding", Kind: finding.KindSCA}}, SBOM: &sbom.SBOM{Components: []sbom.Component{{Name: "dep", Version: "1", Location: "services/payment/package.json"}}}, Vulnerabilities: []vulnerability.Vulnerability{{Component: "dep", Version: "1"}}}
	ctx := svc.ownershipFindingContext(context.Background(), source, "", result)
	batch, ok := ports.OwnershipSourceFrom(ctx)
	if !ok {
		t.Fatal("imported source association missing")
	}
	if evidence := batch.Findings["finding"]; len(evidence.Paths) != 0 || evidence.Invalid {
		t.Fatalf("untrusted SBOM path used: %+v", evidence)
	}
}
