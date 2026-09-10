package sca

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceupload"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type uploadedMarkerDetector struct {
	markers []string
	paths   []string
}

func (d *uploadedMarkerDetector) Detect(_ context.Context, root string) ([]ports.DetectedLanguage, error) {
	data, err := os.ReadFile(filepath.Join(root, "marker.txt"))
	if err != nil {
		return nil, err
	}
	d.markers, d.paths = append(d.markers, string(data)), append(d.paths, root)
	return []ports.DetectedLanguage{{Name: "Go", Percent: 100}}, nil
}

type uploadedScanFixture struct {
	ctx         context.Context
	tenant      shared.ID
	clock       *fakeClock
	service     *Service
	engagements *memory.EngagementRepository
	objects     *blob.Memory
	sources     *sourceupload.Store
	jobs        *memory.ScanJobStore
	runs        *memory.ScanRunStore
	queue       *memory.JobQueue
	detector    *uploadedMarkerDetector
}

func newUploadedScanFixture(t *testing.T) *uploadedScanFixture {
	t.Helper()
	tenant := shared.ID("uploaded-scan-tenant")
	fixture := &uploadedScanFixture{ctx: shared.WithTenant(context.Background(), tenant), tenant: tenant, clock: &fakeClock{t: time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC)}, engagements: memory.NewEngagementRepository(), objects: blob.NewMemory(), jobs: memory.NewScanJobStore(), runs: memory.NewScanRunStore(), detector: &uploadedMarkerDetector{}}
	fixture.sources = sourceupload.NewStoreWithRepository(fixture.objects, memory.NewEngagementSourceRepository(), 0)
	ids, audit := &sequenceIDs{}, &fakeAudit{}
	evidence, err := evidenceuc.NewService(&fakeEvidence{}, nil, audit, fixture.clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = NewService(fixture.engagements, memory.NewFindingRepository(), memory.NewScanRepository(), memory.NewScanResultStore(), fixture.jobs, fixture.runs, evidence, ids, ports.Provenance{}, fixture.clock, audit, shared.SeverityInfo, 0, sourceupload.NewAcquirer(acquire.New(), fixture.sources), fixture.detector, fakeSBOM{}, []ports.DetectionSource{fakeVuln{}}, nil, fakeLic{}, nil)
	fixture.service.SetUploadedSourceStore(fixture.sources)
	fixture.service.SetScanRunProvenance(fixture.runs, memory.NewTenantTransactionRunner())
	fixture.queue = memory.NewJobQueue(ids, fixture.clock.Now)
	fixture.service.SetQueue(fixture.queue)
	return fixture
}

func uploadedZip(t *testing.T, marker string) []byte {
	t.Helper()
	var content bytes.Buffer
	archive := zip.NewWriter(&content)
	entry, err := archive.Create("marker.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(marker)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return content.Bytes()
}

func (f *uploadedScanFixture) createAssessment(t *testing.T, id shared.ID, target string) {
	t.Helper()
	item, err := engdom.New(id, f.tenant, id.String(), "", f.clock.t)
	if err != nil {
		t.Fatal(err)
	}
	item.Scope.InScope = []engdom.Target{{Kind: engdom.TargetRepo, Value: target}}
	if err := item.Transition(engdom.StatusActive, f.clock.t); err != nil {
		t.Fatal(err)
	}
	if err := f.engagements.Create(f.ctx, item); err != nil {
		t.Fatal(err)
	}
}

func (f *uploadedScanFixture) upload(t *testing.T, id shared.ID, marker string) sourcepackage.Package {
	t.Helper()
	data := uploadedZip(t, marker)
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	f.createAssessment(t, id, sourcepackage.TargetPrefix+digest)
	item, err := f.sources.Save(f.ctx, f.tenant, id, "source.zip", "alice", f.clock.t, int64(len(data)), digest, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func (f *uploadedScanFixture) start(t *testing.T, item sourcepackage.Package) ports.ScanJob {
	t.Helper()
	job, err := f.service.StartUploadedSourceVersionScanWithOptions(f.ctx, "tester", f.tenant, item.EngagementID, item.VersionID, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func (f *uploadedScanFixture) runNext(t *testing.T, mutate func(*scaJobPayload)) {
	t.Helper()
	queued, err := f.queue.Claim(f.ctx, time.Minute, ScanJobKind)
	if err != nil || queued == nil {
		t.Fatalf("claim uploaded scan = %+v %v", queued, err)
	}
	payload := queued.Payload
	if mutate != nil {
		var parsed scaJobPayload
		if err := json.Unmarshal(payload, &parsed); err != nil {
			t.Fatal(err)
		}
		mutate(&parsed)
		payload, err = json.Marshal(parsed)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := f.service.RunScanJob(f.ctx, payload); err != nil {
		t.Fatal(err)
	}
	if err := f.queue.Complete(f.ctx, queued.ID, queued.Fence); err != nil {
		t.Fatal(err)
	}
}

func TestUploadedSourceQueuedScansFreezeInitialReuseAndNewUpload(t *testing.T) {
	f := newUploadedScanFixture(t)
	initial := f.upload(t, "initial", "source A")
	initialJob := f.start(t, initial)
	// Before the worker runs, subsequent assessments select both a new upload
	// and the original package. Neither can redirect the already admitted job.
	newUpload := f.upload(t, "retest-new-upload", "source B")
	f.createAssessment(t, "retest-reuse", initial.Target())
	reused, err := f.sources.Reuse(f.ctx, f.tenant, initial.EngagementID, "retest-reuse", initial.VersionID, "bob", f.clock.t.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if initialJob.SourcePackage == nil || initialJob.SourcePackage.Locator != "" || initialJob.SourcePackage.ObjectKey != "" {
		t.Fatalf("queued public metadata exposes storage: %+v", initialJob.SourcePackage)
	}
	initialJob.SourcePackage.Filename = "caller-mutated.zip"
	f.runNext(t, nil)
	for _, item := range []sourcepackage.Package{newUpload, reused} {
		f.start(t, item)
		f.runNext(t, nil)
	}
	if strings.Join(f.detector.markers, ",") != "source A,source B,source A" {
		t.Fatalf("wrong acquired source bytes: %v", f.detector.markers)
	}
	for _, path := range f.detector.paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("scan workspace not cleaned: %s %v", path, err)
		}
	}
	for _, item := range []sourcepackage.Package{initial, newUpload, reused} {
		job, err := f.jobs.LatestForEngagement(f.ctx, item.EngagementID)
		if err != nil || job.Status != ports.ScanSucceeded || job.Error != "" || job.SourcePackage == nil || *job.SourcePackage != *publicSourcePackage(&item) {
			t.Fatalf("terminal job source = %+v %v", job, err)
		}
		run, err := f.runs.GetScanRun(f.ctx, f.tenant, job.ID)
		if err != nil || run.Provenance != scanrun.ProvenanceNative || !run.IsSealed() || len(run.Lanes) == 0 {
			t.Fatalf("native uploaded run = %+v %v", run, err)
		}
		for _, lane := range run.Lanes {
			if lane.Target.EvaluatedRevision != item.SHA256 {
				t.Fatalf("native target revision does not identify acquired bytes: %+v", lane.Target)
			}
		}
		retained, err := f.runs.Get(f.ctx, job.ID)
		if err != nil || retained.Manifest.SourcePackage == nil || *retained.Manifest.SourcePackage != *publicSourcePackage(&item) {
			t.Fatalf("frozen run source = %+v %v", retained.Manifest.SourcePackage, err)
		}
		// Returned pointers are read copies, not mutable references into history.
		retained.Manifest.SourcePackage.CreatedBy = "forged"
		job.SourcePackage.CreatedBy = "forged"
		freshRun, _ := f.runs.Get(f.ctx, job.ID)
		freshJob, _ := f.jobs.GetJob(f.ctx, job.ID)
		if freshRun.Manifest.SourcePackage.CreatedBy != "alice" || freshJob.SourcePackage.CreatedBy != "alice" {
			t.Fatal("returned metadata pointer mutated stored provenance")
		}
	}
	if reused.VersionID == initial.VersionID || reused.ReusedFromVersionID != initial.VersionID || reused.AssociatedBy != "bob" {
		t.Fatal("child scan did not retain its distinct reuse association")
	}
}

func TestUploadedSourceAdmissionRejectsStaleVersionAndForeignOwnership(t *testing.T) {
	f := newUploadedScanFixture(t)
	initial := f.upload(t, "initial", "source A")
	other := f.upload(t, "other", "source B")
	if _, err := f.service.StartUploadedSourceVersionScanWithOptions(f.ctx, "tester", f.tenant, initial.EngagementID, other.VersionID, ScanOptions{}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale selected version = %v", err)
	}
	if _, err := f.service.StartUploadedSourceVersionScanWithOptions(shared.WithTenant(f.ctx, "other-tenant"), "tester", "other-tenant", initial.EngagementID, initial.VersionID, ScanOptions{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign source admission = %v", err)
	}
	req := ports.AcquireRequest{Kind: ports.TargetUpload, Value: initial.Target(), Locator: initial.Locator, SourcePackage: publicSourcePackage(&initial)}
	req.SourcePackage.EngagementID = other.EngagementID
	if _, err := f.service.StartScan(f.ctx, "tester", initial.EngagementID, req); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("mismatched source owner = %v", err)
	}
	if queued, err := f.queue.Claim(f.ctx, time.Minute, ScanJobKind); err != nil || queued != nil {
		t.Fatalf("invalid source selection enqueued a scan: %+v %v", queued, err)
	}
}

func TestUploadedSourceFailedQueuedAcquisitionRetainsAdmittedMetadata(t *testing.T) {
	for _, scenario := range []string{"tampered-bytes", "missing-bytes", "invalid-zip", "tampered-metadata", "mismatched-owner", "mismatched-locator"} {
		t.Run(scenario, func(t *testing.T) {
			f := newUploadedScanFixture(t)
			item := f.upload(t, "initial", "source A")
			if scenario == "invalid-zip" {
				// Valid digest/storage metadata must not make an invalid archive executable.
				data := []byte("not a ZIP archive")
				hash := sha256.Sum256(data)
				digest := hex.EncodeToString(hash[:])
				f.createAssessment(t, "invalid", sourcepackage.TargetPrefix+digest)
				var err error
				item, err = f.sources.Save(f.ctx, f.tenant, "invalid", "source.zip", "alice", f.clock.t, int64(len(data)), digest, bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
			}
			job := f.start(t, item)
			var mutate func(*scaJobPayload)
			switch scenario {
			case "tampered-bytes":
				if err := f.objects.Put(f.ctx, item.ObjectKey, bytes.Repeat([]byte("x"), int(item.Size))); err != nil {
					t.Fatal(err)
				}
			case "missing-bytes":
				if err := f.objects.DeleteObject(f.ctx, item.ObjectKey); err != nil {
					t.Fatal(err)
				}
			case "tampered-metadata":
				mutate = func(payload *scaJobPayload) { payload.Req.SourcePackage.CreatedBy = "forged" }
			case "mismatched-owner":
				mutate = func(payload *scaJobPayload) { payload.Req.SourcePackage.EngagementID = "unrelated" }
			case "mismatched-locator":
				mutate = func(payload *scaJobPayload) { payload.Req.Locator += "-changed" }
			}
			f.runNext(t, mutate)
			terminal, err := f.jobs.GetJob(f.ctx, job.ID)
			if err != nil || terminal.Status != ports.ScanFailed || terminal.Error == "" || terminal.SourcePackage == nil || *terminal.SourcePackage != *publicSourcePackage(&item) {
				t.Fatalf("failed job lost original source: %+v %v", terminal, err)
			}
			if len(f.detector.markers) != 0 {
				t.Fatal("untrusted/mismatched source reached a scanner")
			}
			if runs, err := f.runs.List(f.ctx, item.EngagementID); err != nil || len(runs) != 0 {
				t.Fatalf("failed acquisition emitted successful history: %+v %v", runs, err)
			}
		})
	}
}
