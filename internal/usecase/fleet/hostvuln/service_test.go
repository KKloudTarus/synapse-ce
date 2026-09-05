package hostvuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

const tenant = shared.ID("tenant-a")

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID { s.n++; return shared.ID("id-" + strconv.Itoa(s.n)) }

type auditLog struct{ entries []ports.AuditEntry }

func (a *auditLog) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func (a *auditLog) count(action string) int {
	n := 0
	for _, e := range a.entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// fakeScanner stands in for the SCA service: it records the imported document the way the real
// ImportContextSBOM does (active record keyed by digest) and opens a running job for each scan start.
type fakeScanner struct {
	imported  *memory.ImportedSBOMStore
	jobs      *memory.ScanJobStore
	clock     ports.Clock
	imports   [][]byte
	starts    int
	importErr error
	startErr  error
}

func (f *fakeScanner) ImportContextSBOM(ctx context.Context, actor string, tenantID, engagementID shared.ID, filename string, data []byte) (*scauc.ScanResult, error) {
	if f.importErr != nil {
		return nil, f.importErr
	}
	f.imports = append(f.imports, append([]byte(nil), data...))
	sum := sha256.Sum256(data)
	if err := f.imported.SaveActive(ctx, importedsbom.Record{
		ID: shared.ID("sbom-" + strconv.Itoa(len(f.imports))), TenantID: tenantID, EngagementID: engagementID, Filename: filename,
		Format: importedsbom.FormatCycloneDX, SpecVersion: "1.5", TargetRef: "host://machine-id/abc", ComponentCount: 2,
		SHA256: hex.EncodeToString(sum[:]), RawJSON: data, CreatedBy: actor, CreatedAt: f.clock.Now(),
	}); err != nil {
		return nil, err
	}
	return &scauc.ScanResult{}, nil
}

func (f *fakeScanner) StartScanWithOptions(ctx context.Context, _ string, engagementID shared.ID, _ ports.AcquireRequest, opts scauc.ScanOptions) (ports.ScanJob, error) {
	if f.startErr != nil {
		return ports.ScanJob{}, f.startErr
	}
	if opts.Mode != scauc.ScanModeFull {
		return ports.ScanJob{}, errors.New("host scans must run the full mode")
	}
	f.starts++
	job := ports.ScanJob{ID: "job-" + strconv.Itoa(f.starts), EngagementID: engagementID.String(), Kind: "imported-sbom", Status: ports.ScanRunning, Stage: "queued", StartedAt: f.clock.Now()}
	if err := f.jobs.CreateRunning(ctx, job); err != nil {
		return ports.ScanJob{}, err
	}
	return job, nil
}

type fakeFindings struct {
	byEngagement map[shared.ID][]finding.Finding
}

func (f fakeFindings) List(_ context.Context, id shared.ID) ([]finding.Finding, error) {
	return f.byEngagement[id], nil
}

type harness struct {
	svc      *Service
	clock    *fixedClock
	eng      *memory.EngagementRepository
	assets   *memory.AssetStore
	scanner  *fakeScanner
	jobs     *memory.ScanJobStore
	findings fakeFindings
	audit    *auditLog
	host     *asset.Asset
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clock := &fixedClock{t: time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC)}
	h := &harness{
		clock:    clock,
		eng:      memory.NewEngagementRepository(),
		assets:   memory.NewAssetStore(),
		jobs:     memory.NewScanJobStore(),
		audit:    &auditLog{},
		findings: fakeFindings{byEngagement: map[shared.ID][]finding.Finding{}},
	}
	h.scanner = &fakeScanner{imported: memory.NewImportedSBOMStore(), jobs: h.jobs, clock: clock}
	var err error
	h.svc, err = NewService(h.eng, h.assets, h.findings, h.scanner, h.scanner.imported, h.jobs, &seqIDs{}, clock, h.audit)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	h.host, err = asset.New("asset-1", tenant, asset.KindHost, "machine-id/abc", "web01", map[string]string{"os": "linux"}, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.assets.UpsertAsset(context.Background(), h.host); err != nil {
		t.Fatal(err)
	}
	return h
}

// finishLatestScan moves the context's latest job to a terminal status the way the pipeline does.
func (h *harness) finishLatestScan(t *testing.T, engagementID shared.ID, status ports.ScanStatus) {
	t.Helper()
	job, err := h.jobs.LatestForEngagement(context.Background(), engagementID)
	if err != nil {
		t.Fatal(err)
	}
	job.Status, job.Stage, job.Progress = status, "done", 100
	if status == ports.ScanFailed {
		job.Error = "matcher unavailable"
	}
	done := job.StartedAt.Add(time.Minute)
	job.FinishedAt = &done
	if err := h.jobs.Save(context.Background(), job); err != nil {
		t.Fatal(err)
	}
}

func packages() []sbom.Component {
	return []sbom.Component{
		{Name: "zlib1g", Version: "1:1.2.13.dfsg-1", PURL: "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=amd64&distro=debian-12"},
		{Name: "openssl", Version: "3.0.11-1~deb12u2", PURL: "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12"},
	}
}

func inventory(pkgs []sbom.Component) dhi.HostInventory {
	return dhi.HostInventory{Facts: dhi.HostFacts{Hostname: "web01", OS: "linux", OSVersion: "12", MachineID: "abc"}, Packages: pkgs}
}

func TestRecordCreatesHiddenContextAndQueuesScan(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	out, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages()))
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if out.Skipped || out.JobID != "job-1" || out.Components != 2 || out.EngagementID.IsZero() {
		t.Fatalf("outcome = %+v", out)
	}
	eng, err := h.eng.GetByHostAssetID(ctx, tenant, h.host.ID)
	if err != nil {
		t.Fatalf("context not created: %v", err)
	}
	if eng.HostAssetID != h.host.ID || !eng.Internal() || eng.Audit.CreatedBy != "agent-1" {
		t.Fatalf("context = %+v", eng)
	}
	if got := eng.Scope.InScope; len(got) != 1 || got[0].Value != "host://machine-id/abc" {
		t.Fatalf("context scope = %+v", got)
	}
	// Hidden from operator reads.
	if _, err := h.eng.GetByIDInTenant(ctx, tenant, eng.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("host context reachable as an engagement: %v", err)
	}
	if list, _ := h.eng.List(ctx, tenant); len(list) != 0 {
		t.Fatalf("host context listed: %d", len(list))
	}
	// The imported document carries the distro-qualified PURLs the OS matcher keys on.
	if len(h.scanner.imports) != 1 {
		t.Fatalf("imports = %d", len(h.scanner.imports))
	}
	doc := string(h.scanner.imports[0])
	for _, want := range []string{`"bomFormat": "CycloneDX"`, "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64\\u0026distro=debian-12", `"name": "host://machine-id/abc"`} {
		if !strings.Contains(doc, want) {
			t.Fatalf("document missing %q:\n%s", want, doc)
		}
	}
	if h.audit.count("host_inventory.vulnerability_context_created") != 1 || h.audit.count("host_inventory.vulnerability_scan_queued") != 1 {
		t.Fatalf("audit = %+v", h.audit.entries)
	}
}

func TestRecordSkipsUnchangedPackagesAndRescansOnChange(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages())); err != nil {
		t.Fatal(err)
	}
	// While the first scan is still running, a changed package set is not recorded: the running scan
	// keeps its input and the outcome says why.
	upgraded := packages()
	upgraded[1].Version = "3.0.13-1~deb12u1"
	out, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(upgraded))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Skipped || out.Reason != hostinventory.ReasonScanActive || len(h.scanner.imports) != 1 {
		t.Fatalf("active-scan outcome = %+v imports=%d", out, len(h.scanner.imports))
	}
	h.finishLatestScan(t, "id-1", ports.ScanSucceeded)

	// Same packages in a different order: byte-identical document, no new import or scan.
	reordered := []sbom.Component{packages()[1], packages()[0]}
	out, err = h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Skipped || out.Reason != hostinventory.ReasonUnchanged || out.EngagementID != "id-1" || out.Components != 2 {
		t.Fatalf("unchanged outcome = %+v", out)
	}
	if len(h.scanner.imports) != 1 || h.scanner.starts != 1 {
		t.Fatalf("unchanged host re-imported: imports=%d starts=%d", len(h.scanner.imports), h.scanner.starts)
	}

	// Once the scan finished and the record interval has passed, the upgraded package changes the
	// digest and triggers a new import and scan on the same context.
	h.clock.t = h.clock.t.Add(MinRecordInterval)
	out, err = h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(upgraded))
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped || out.JobID != "job-2" || out.EngagementID != "id-1" {
		t.Fatalf("changed outcome = %+v", out)
	}
	if h.audit.count("host_inventory.vulnerability_context_created") != 1 {
		t.Fatalf("a second context was created")
	}
}

func TestRecordRetriesWhenLastScanFailed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages())); err != nil {
		t.Fatal(err)
	}
	h.finishLatestScan(t, "id-1", ports.ScanFailed)
	out, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages()))
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped || out.JobID != "job-2" {
		t.Fatalf("failed scan was not retried: %+v", out)
	}
}

func TestRecordNoPackagesIsANoOp(t *testing.T) {
	h := newHarness(t)
	out, err := h.svc.Record(context.Background(), "agent-1", tenant, h.host, inventory(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Skipped || out.Reason != hostinventory.ReasonNoPackages || !out.EngagementID.IsZero() {
		t.Fatalf("outcome = %+v", out)
	}
	if _, err := h.eng.GetByHostAssetID(context.Background(), tenant, h.host.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("context created for a host without packages: %v", err)
	}
}

func TestRecordValidation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	other, _ := asset.New("img-1", tenant, asset.KindImage, "sha256:1", "img", nil, time.Now())
	cases := map[string]func() error{
		"empty actor": func() error { _, err := h.svc.Record(ctx, " ", tenant, h.host, inventory(packages())); return err },
		"zero tenant": func() error { _, err := h.svc.Record(ctx, "agent-1", "", h.host, inventory(packages())); return err },
		"nil host":    func() error { _, err := h.svc.Record(ctx, "agent-1", tenant, nil, inventory(packages())); return err },
		"not a host":  func() error { _, err := h.svc.Record(ctx, "agent-1", tenant, other, inventory(packages())); return err },
	}
	for name, run := range cases {
		if err := run(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
	if len(h.scanner.imports) != 0 {
		t.Fatalf("invalid input reached the scanner")
	}
}

func TestRecordSurfacesScannerErrors(t *testing.T) {
	h := newHarness(t)
	h.scanner.startErr = errors.New("queue down")
	_, err := h.svc.Record(context.Background(), "agent-1", tenant, h.host, inventory(packages()))
	if err == nil || !strings.Contains(err.Error(), "queue host vulnerability scan: queue down") {
		t.Fatalf("err = %v", err)
	}
	if h.audit.count("host_inventory.vulnerability_scan_queued") != 0 {
		t.Fatalf("queued audit written for a failed start")
	}
}

func TestVulnerabilitiesAndHosts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	out, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages()))
	if err != nil {
		t.Fatal(err)
	}
	h.findings.byEngagement[out.EngagementID] = []finding.Finding{
		{ID: "f1", EngagementID: out.EngagementID, Kind: finding.KindSCA, Severity: shared.SeverityCritical, Title: "CVE-2024-0001 openssl", DedupKey: "vuln:CVE-2024-0001:openssl", FixedVersion: "3.0.13", KEV: true, RiskScore: 9.1},
		{ID: "f2", EngagementID: out.EngagementID, Kind: finding.KindSCA, Severity: shared.SeverityMedium, Title: "CVE-2023-0002 zlib1g", DedupKey: "vuln:CVE-2023-0002:zlib1g"},
		{ID: "f3", EngagementID: out.EngagementID, Kind: finding.KindSCA, Severity: shared.SeverityLow, Title: "GPL-3.0 zlib1g", DedupKey: "license:GPL-3.0:zlib1g"},
		{ID: "f4", EngagementID: out.EngagementID, Kind: finding.KindSAST, Severity: shared.SeverityHigh, Title: "not from packages"},
	}

	res, err := h.svc.Vulnerabilities(ctx, tenant, h.host.ID)
	if err != nil {
		t.Fatalf("Vulnerabilities: %v", err)
	}
	if res.EngagementID != out.EngagementID || res.Packages != 2 || res.RecordedAt.IsZero() {
		t.Fatalf("host view = %+v", res)
	}
	if res.LastScan == nil || res.LastScan.ID != "job-1" {
		t.Fatalf("last scan = %+v", res.LastScan)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("license and non-SCA findings leaked: %d", len(res.Findings))
	}
	want := Summary{Total: 2, Critical: 1, Medium: 1, Fixable: 1, KEV: 1}
	if res.Summary != want {
		t.Fatalf("summary = %+v, want %+v", res.Summary, want)
	}

	// A second host that never reported packages: listed, unscanned, no error.
	quiet, _ := asset.New("asset-2", tenant, asset.KindHost, "machine-id/def", "db01", nil, time.Now())
	if err := h.assets.UpsertAsset(ctx, quiet); err != nil {
		t.Fatal(err)
	}
	other, _ := asset.New("img-9", tenant, asset.KindImage, "sha256:9", "img", nil, time.Now())
	if err := h.assets.UpsertAsset(ctx, other); err != nil {
		t.Fatal(err)
	}
	rows, err := h.svc.Hosts(ctx, tenant)
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if len(rows) != 2 || rows[0].Asset.ID != h.host.ID || rows[1].Asset.ID != quiet.ID {
		t.Fatalf("hosts = %+v", rows)
	}
	if rows[0].Summary != want || rows[0].LastScan == nil || rows[0].Packages != 2 {
		t.Fatalf("scanned host row = %+v", rows[0])
	}
	if !rows[1].EngagementID.IsZero() || rows[1].LastScan != nil || rows[1].Summary.Total != 0 {
		t.Fatalf("unscanned host row = %+v", rows[1])
	}
	view, err := h.svc.Vulnerabilities(ctx, tenant, quiet.ID)
	if err != nil || !view.EngagementID.IsZero() || len(view.Findings) != 0 {
		t.Fatalf("unscanned host view = %+v, %v", view, err)
	}
}

func TestVulnerabilitiesRejectsUnknownAndNonHostAssets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Vulnerabilities(ctx, tenant, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing asset err = %v", err)
	}
	if _, err := h.svc.Vulnerabilities(ctx, "tenant-b", h.host.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant err = %v", err)
	}
	img, _ := asset.New("img-1", tenant, asset.KindImage, "sha256:1", "img", nil, time.Now())
	if err := h.assets.UpsertAsset(ctx, img); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Vulnerabilities(ctx, tenant, img.ID); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("non-host err = %v", err)
	}
}

func TestDocumentIsDeterministic(t *testing.T) {
	host, _ := asset.New("asset-1", tenant, asset.KindHost, "machine-id/abc", "web01", nil, time.Now())
	a, err := Document(host, packages())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Document(host, []sbom.Component{packages()[1], packages()[0]})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("component order changed the document")
	}
	if strings.Contains(string(a), time.Now().UTC().Format("2006")) {
		t.Fatalf("document carries the wall clock: %s", a)
	}
}

func TestNewServiceValidatesDependencies(t *testing.T) {
	h := newHarness(t)
	if _, err := NewService(nil, h.assets, h.findings, h.scanner, h.scanner.imported, h.jobs, &seqIDs{}, &fixedClock{}, h.audit); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil engagements err = %v", err)
	}
	if _, err := NewService(h.eng, h.assets, h.findings, nil, h.scanner.imported, h.jobs, &seqIDs{}, &fixedClock{}, h.audit); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil scanner err = %v", err)
	}
}

// Import succeeds, the scan start fails, the next sweep reports the same set: the recorded set was never
// measured, so it is scanned now rather than read as unchanged against an older successful scan.
func TestRecordRescansWhenTheScanStartFailedAfterImport(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages())); err != nil {
		t.Fatal(err)
	}
	h.finishLatestScan(t, "id-1", ports.ScanSucceeded)
	h.clock.t = h.clock.t.Add(time.Hour)
	upgraded := packages()
	upgraded[1].Version = "3.0.13-1~deb12u1"
	h.scanner.startErr = errors.New("queue down")
	if _, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(upgraded)); err == nil {
		t.Fatal("scan start failure not surfaced")
	}
	h.scanner.startErr = nil
	h.clock.t = h.clock.t.Add(time.Hour)
	out, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(upgraded))
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped || out.JobID != "job-2" {
		t.Fatalf("unmeasured set was not scanned: %+v", out)
	}
	if len(h.scanner.imports) != 3 {
		t.Fatalf("imports = %d (initial, failed-start, retry)", len(h.scanner.imports))
	}
}

// A changed set arriving within the minimum record interval is deferred, not imported and scanned.
func TestRecordDefersRapidChanges(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages())); err != nil {
		t.Fatal(err)
	}
	h.finishLatestScan(t, "id-1", ports.ScanSucceeded)
	changed := packages()
	changed[0].Version = "1:1.2.13.dfsg-2"
	h.clock.t = h.clock.t.Add(MinRecordInterval / 2)
	out, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(changed))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Skipped || out.Reason != hostinventory.ReasonRecordedRecently || len(h.scanner.imports) != 1 {
		t.Fatalf("rapid change was recorded: %+v imports=%d", out, len(h.scanner.imports))
	}
	h.clock.t = h.clock.t.Add(MinRecordInterval)
	out, err = h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(changed))
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped || len(h.scanner.imports) != 2 {
		t.Fatalf("change after the interval not recorded: %+v", out)
	}
}

func TestRecordRefusesOversizedInventory(t *testing.T) {
	h := newHarness(t)
	huge := make([]sbom.Component, MaxPackages+1)
	for i := range huge {
		huge[i] = sbom.Component{Name: "p" + strconv.Itoa(i), Version: "1", PURL: "pkg:deb/debian/p" + strconv.Itoa(i) + "@1?distro=debian-12"}
	}
	if _, err := h.svc.Record(context.Background(), "agent-1", tenant, h.host, inventory(huge)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized inventory accepted: %v", err)
	}
	if len(h.scanner.imports) != 0 {
		t.Fatal("oversized inventory reached the scanner")
	}
}

type fakeSummaries struct {
	calls int
	ids   []shared.ID
	out   map[shared.ID]ports.VulnerabilitySummary
}

func (f *fakeSummaries) SummarizeVulnerabilitiesByEngagements(_ context.Context, ids []shared.ID) (map[shared.ID]ports.VulnerabilitySummary, error) {
	f.calls++
	f.ids = append([]shared.ID(nil), ids...)
	return f.out, nil
}

// With a summary reader wired, Hosts counts every context in one call and never lists findings.
func TestHostsUsesTheBatchedSummaryRead(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	out, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages()))
	if err != nil {
		t.Fatal(err)
	}
	second, _ := asset.New("asset-2", tenant, asset.KindHost, "machine-id/def", "db01", nil, time.Now())
	if err := h.assets.UpsertAsset(ctx, second); err != nil {
		t.Fatal(err)
	}
	out2, err := h.svc.Record(ctx, "agent-2", tenant, second, inventory(packages()))
	if err != nil {
		t.Fatal(err)
	}
	sums := &fakeSummaries{out: map[shared.ID]ports.VulnerabilitySummary{
		out.EngagementID:  {Total: 3, High: 3},
		out2.EngagementID: {Total: 1, Critical: 1},
	}}
	h.svc.SetFindingSummaries(sums)
	listing := &countingFindings{}
	h.svc.findings = listing

	rows, err := h.svc.Hosts(ctx, tenant)
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if sums.calls != 1 || len(sums.ids) != 2 || listing.calls != 0 {
		t.Fatalf("summary calls=%d ids=%v list calls=%d", sums.calls, sums.ids, listing.calls)
	}
	if len(rows) != 2 || rows[0].Asset.ID != second.ID || rows[0].Summary.Critical != 1 || rows[1].Summary.High != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Packages != 2 || rows[0].LastScan == nil || rows[1].LastScan == nil {
		t.Fatalf("metadata or jobs missing: %+v", rows)
	}
}

type countingFindings struct{ calls int }

func (c *countingFindings) List(context.Context, shared.ID) ([]finding.Finding, error) {
	c.calls++
	return nil, nil
}

// Packages returns the recorded set, sorted, and an empty list for a host that never reported one.
func TestPackagesReturnsTheRecordedInventory(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Record(ctx, "agent-1", tenant, h.host, inventory(packages())); err != nil {
		t.Fatal(err)
	}
	got, err := h.svc.Packages(ctx, tenant, h.host.ID)
	if err != nil {
		t.Fatalf("Packages: %v", err)
	}
	if got.EngagementID != "id-1" || len(got.Packages) != 2 || got.Packages[0].Name != "openssl" || got.Packages[1].Name != "zlib1g" || got.RecordedAt.IsZero() {
		t.Fatalf("packages = %+v", got)
	}
	if got.Packages[0].PURL != packages()[1].PURL {
		t.Fatalf("purl lost: %+v", got.Packages[0])
	}
	quiet, _ := asset.New("asset-2", tenant, asset.KindHost, "machine-id/def", "db01", nil, time.Now())
	if err := h.assets.UpsertAsset(ctx, quiet); err != nil {
		t.Fatal(err)
	}
	none, err := h.svc.Packages(ctx, tenant, quiet.ID)
	if err != nil || !none.EngagementID.IsZero() || len(none.Packages) != 0 {
		t.Fatalf("unrecorded host = %+v, %v", none, err)
	}
	if _, err := h.svc.Packages(ctx, "tenant-b", h.host.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant err = %v", err)
	}
}
