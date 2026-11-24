package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	reportinfra "github.com/KKloudTarus/synapse-ce/internal/infrastructure/report"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceupload"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	exportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/export"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	reportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/report"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func init() {
	registerHarnessSeed(harnessSeed{
		Name: "reports",
		Routes: []string{
			"GET /api/v1/engagements/{id}/code-quality",
			"GET /api/v1/engagements/{id}/export/csaf",
			"GET /api/v1/engagements/{id}/export/cyclonedx",
			"GET /api/v1/engagements/{id}/export/openvex",
			"GET /api/v1/engagements/{id}/export/sarif",
			"GET /api/v1/engagements/{id}/export/spdx",
			"GET /api/v1/engagements/{id}/recon/runs",
			"GET /api/v1/engagements/{id}/recon/runs/{rid}",
			"GET /api/v1/engagements/{id}/recon/runs/{rid}/logs",
			"GET /api/v1/engagements/{id}/report.docx",
			"GET /api/v1/engagements/{id}/report.html",
			"GET /api/v1/engagements/{id}/report.pdf",
			"GET /api/v1/engagements/{id}/sbom",
			"GET /api/v1/engagements/{id}/scan",
			"GET /api/v1/engagements/{id}/scan-runs",
			"GET /api/v1/engagements/{id}/scan-runs/compare",
			"GET /api/v1/engagements/{id}/scan-status",
			"GET /api/v1/engagements/{id}/source",
		},
		// The legacy run store reads the tenant from the request context, as the production
		// authentication middleware sets it, so the sweep must bind it for the comparison.
		TenantBound: []string{"GET /api/v1/engagements/{id}/scan-runs/compare"},
		// The comparison needs two stored runs of the engagement. This seed plants one, and comparing a
		// run with itself is a valid, empty drift that still carries the run, so a second run is not
		// needed.
		Queries: map[string]string{
			"GET /api/v1/engagements/{id}/scan-runs/compare": "?a=" + reportsScanRunID + "&b=" + reportsScanRunID,
		},
		Run: seedReports,
	})
}

// reportsMarker is planted in every tenantA record the report, export, scan and recon routes serve.
// It appears verbatim in a response body only when tenantA's data was served.
const reportsMarker = "tenantA-reports-marker"

// reportsScanRunID is the scan run this seed plants for engA, and the one the comparison route is
// asked to compare.
const reportsScanRunID = reportsMarker + "-run"

// reportsRunID is the id the generated sweep substitutes for {rid}, so the recon run planted under it
// is the one the run-detail and run-log routes are asked for.
const reportsRunID = "r1"

// seedReports wires the report, export, SBOM, scan and recon subsystems and plants tenantA data in
// each, so the routes that read them answer tenantA with its own records.
//
// The Router keeps these services in unexported fields that only NewRouter fills, so the seed sets
// them directly; the harness builds its Router by hand and never calls NewRouter. Another seed may
// have filled the same field first, so every field is created only while it is still nil, and a
// service that already exists is extended through its own setters instead of being replaced.
func seedReports(w *harnessWorld) []string {
	w.t.Helper()
	ctxA := shared.WithTenant(context.Background(), "tenantA")
	clock := fixedClock{t: time.Unix(1, 0).UTC()}

	// One finding store feeds both the export and the report services. It is keyed by engagement only,
	// so the route's tenant guard is the sole thing keeping tenantB away from this finding.
	findings := memory.NewFindingRepository()
	if err := findings.Upsert(ctxA, []finding.Finding{{
		ID: "reports-finding-A", EngagementID: "engA", Kind: finding.KindSCA, Severity: shared.SeverityHigh,
		Status: finding.StatusOpen, Title: reportsMarker + " finding",
		DedupKey: "vuln:CVE-2026-1001:" + reportsMarker + ":1.0.0", Priority: 3, Version: 1,
		Audit: shared.Audit{CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)},
	}}); err != nil {
		w.t.Fatalf("seed reports finding: %v", err)
	}

	// SARIF, OpenVEX and CSAF are built from the stored findings by the real export service.
	if w.rt.export == nil {
		w.rt.export = exportuc.NewService(findings, clock, "harness")
	}

	// HTML is rendered by the real renderer, so the finding title reaches the page. PDF and DOCX are
	// compressed containers that would hide a marker from a plain-text check, so stand-ins answer
	// them. Neither reads the engagement it is handed: every caller gets tenantA's marker, which
	// leaves the tenant guard as the only thing keeping tenantB from it.
	if w.rt.report == nil {
		report := reportuc.NewService(w.engagements, findings, nil, nil, reportsPDFRenderer{}, nil, clock, "harness")
		report.RegisterFormat(reportuc.FormatHTML, reportinfra.NewHTMLRenderer())
		report.RegisterFormat(reportuc.FormatDOCX, reportsDOCXRenderer{})
		w.rt.report = report
	}

	seedReportsScan(w, ctxA, findings, clock)
	seedReportsRecon(w, ctxA, clock)

	return []string{reportsMarker}
}

// seedReportsScan plants tenantA's scan records. The scan service takes its result, job and run
// stores only from its constructor, so those are planted when this seed builds the service. A service
// that another seed already built keeps its own (possibly absent) stores; the imported-SBOM and
// uploaded-source stores and the normalized run history have setters, so they are attached either way.
func seedReportsScan(w *harnessWorld, ctxA context.Context, findings ports.FindingRepository, clock fixedClock) {
	w.t.Helper()
	runs := memory.NewScanRunStore()
	if err := runs.Save(ctxA, ports.ScanRun{
		ID: reportsScanRunID, EngagementID: "engA", CreatedAt: time.Unix(1, 0).UTC(),
		Manifest:    ports.ScanManifest{ToolVersions: map[string]string{"synapse": "harness"}},
		FindingKeys: []string{reportsMarker},
	}); err != nil {
		w.t.Fatalf("seed reports scan run: %v", err)
	}
	// The normalized history reads by an explicit tenant argument rather than the context, so it is
	// the real tenant-scoped path and needs no wrapper.
	if w.rt.scanRunHistory == nil {
		w.rt.SetScanRunHistory(runs)
	}

	if w.rt.sca == nil {
		results := memory.NewScanResultStore()
		jobs := memory.NewScanJobStore()
		// The vault the "core" seed left in the shared state (harness_seed_evidence_vault_test.go), so the
		// evidence ledger route keeps serving its entries from this one service. It is nil when that
		// seed is absent.
		w.rt.sca = scauc.NewService(w.engagements, findings, nil, results, jobs, reportsScanRuns{ScanRunStore: runs}, harnessEvidenceVault(w), engIDs{}, ports.Provenance{}, clock, w.audit,
			shared.SeverityInfo, 0, nil, nil, nil, nil, nil, nil, nil)

		// The latest scan result is one JSON document that the scan, SPDX 2.3 and 3.0, CycloneDX and
		// code-quality routes all read, so one fixture serves them all.
		result, err := json.Marshal(scauc.ScanResult{
			Target: reportsMarker,
			SBOM: &sbom.SBOM{
				TargetRef:  reportsMarker,
				Components: []sbom.Component{{Name: reportsMarker + "-lib", Version: "1.0.0", PURL: "pkg:generic/" + reportsMarker + "-lib@1.0.0"}},
			},
			// The code-quality route reads the stored report out of the same document.
			CodeQuality: &codequality.Report{Findings: []finding.Finding{{ID: "reports-quality-A", Title: reportsMarker + " quality"}}},
		})
		if err != nil {
			w.t.Fatalf("encode reports scan result: %v", err)
		}
		if err := results.SaveResult(ctxA, "engA", result); err != nil {
			w.t.Fatalf("seed reports scan result: %v", err)
		}

		// The status poll reads the engagement's latest job.
		finished := time.Unix(2, 0).UTC()
		job := ports.ScanJob{
			ID: "reports-job-A", EngagementID: "engA", Target: reportsMarker, Kind: ports.TargetLocal,
			Status: ports.ScanSucceeded, Stage: "done", Progress: 100, StartedAt: time.Unix(1, 0).UTC(), FinishedAt: &finished,
		}
		if err := jobs.CreateRunning(ctxA, job); err != nil {
			w.t.Fatalf("seed reports scan job: %v", err)
		}
		if err := jobs.Save(ctxA, job); err != nil {
			w.t.Fatalf("finish reports scan job: %v", err)
		}
	}

	sboms := memory.NewImportedSBOMStore()
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	digest := sha256.Sum256(raw)
	if err := sboms.SaveActive(ctxA, importedsbom.Record{
		ID: "reports-sbom-A", TenantID: "tenantA", EngagementID: "engA", Filename: reportsMarker + ".cdx.json",
		Format: importedsbom.FormatCycloneDX, SpecVersion: "1.6", TargetRef: reportsMarker, ComponentCount: 1,
		SHA256: hex.EncodeToString(digest[:]), RawJSON: raw, CreatedBy: "p", CreatedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		w.t.Fatalf("seed reports imported SBOM: %v", err)
	}
	w.rt.sca.SetImportedSBOMStore(sboms)

	archive := []byte(reportsMarker + " source archive")
	archiveDigest := sha256.Sum256(archive)
	sources := sourceupload.NewStore(blob.NewMemory(), 0)
	if _, err := sources.Save(ctxA, "tenantA", "engA", reportsMarker+".zip", "p", time.Unix(1, 0).UTC(),
		int64(len(archive)), hex.EncodeToString(archiveDigest[:]), bytes.NewReader(archive)); err != nil {
		w.t.Fatalf("seed reports uploaded source: %v", err)
	}
	w.rt.sca.SetUploadedSourceStore(sources)
}

// seedReportsRecon plants one finished tenantA recon run and a log line for it. The run store is
// reachable only through the recon service's constructor, so the run is planted when this seed builds
// the service; the log line goes to whichever broker the router already holds. The run is written
// straight to the store, because starting one through the service would need a live-recon engagement
// that this fixture does not own.
func seedReportsRecon(w *harnessWorld, ctxA context.Context, clock fixedClock) {
	w.t.Helper()
	if w.rt.logs == nil {
		w.rt.logs = logstream.NewBroker(0)
	}
	// A finished run's stream is closed when the log route reads it, so the replay below ends in a
	// terminal event instead of holding the connection open.
	w.rt.logs.Publish(reportsRunID, reportsMarker+" log line")

	if w.rt.recon != nil {
		return
	}
	guard, err := execution.NewGuard(w.engagements, clock, w.audit)
	if err != nil {
		w.t.Fatalf("reports execution guard: %v", err)
	}
	vault, err := evidenceuc.NewService(memory.NewEvidenceStore(), blob.NewMemory(), w.audit, clock, engIDs{})
	if err != nil {
		w.t.Fatalf("reports evidence vault: %v", err)
	}
	runs := memory.NewReconRunRepository()
	svc, err := reconuc.NewService(guard, fakeReconRunner{}, runs, vault, w.engagements, w.rt.logs, syncDispatcher{}, clock, engIDs{},
		map[string]ports.ReconTool{"subfinder": fakeReconTool{}}, time.Minute, 1<<20, false)
	if err != nil {
		w.t.Fatalf("reports recon service: %v", err)
	}
	finished := time.Unix(2, 0).UTC()
	if err := runs.Save(ctxA, recon.Run{
		ID: reportsRunID, EngagementID: "engA", Tool: "subfinder", Target: reportsMarker + ".example.test",
		Status: recon.StatusSucceeded, Stage: "done", StartedAt: time.Unix(1, 0).UTC(), FinishedAt: &finished,
	}); err != nil {
		w.t.Fatalf("seed reports recon run: %v", err)
	}
	w.rt.recon = svc
}

// reportsScanRuns is the legacy scan-run store the scan service lists from. The real store reads the
// tenant from the request context, which the generated sweep never binds because it drives the route
// table without the authentication middleware; every list would fail before it answered anybody. This
// binds tenantA for every caller instead, so a route that lost its tenant guard serves tenantA's
// runs to tenantB and the sweep sees it.
type reportsScanRuns struct{ *memory.ScanRunStore }

func (s reportsScanRuns) List(ctx context.Context, engagementID shared.ID) ([]ports.ScanRun, error) {
	return s.ScanRunStore.List(shared.WithTenant(ctx, "tenantA"), engagementID)
}

// reportsPDFRenderer answers every caller with tenantA's marker. A real PDF compresses its text, so
// the marker would not survive as plain text for the sweep to find.
type reportsPDFRenderer struct{}

func (reportsPDFRenderer) Render(context.Context, *engdom.Engagement, []finding.Finding, ports.ReportInsight, time.Time, string) ([]byte, error) {
	return []byte("%PDF-1.4\n% " + reportsMarker + "\n"), nil
}

// reportsDOCXRenderer is the same stand-in for the Word format, which is a deflated zip.
type reportsDOCXRenderer struct{}

func (reportsDOCXRenderer) Render(_ context.Context, doc ports.ReportDocument) ([]byte, error) {
	return []byte("PK stand-in " + reportsMarker + " " + strings.TrimSpace(doc.Title)), nil
}
