// Package hostvuln correlates the OS packages a fleet host agent reports with vulnerability
// advisories and exposes the result per host (#820).
//
// A host does not get its own vulnerability pipeline. Each Kind=host asset that reports packages
// owns one hidden engagement (engagement.HostAssetID, the fleet twin of the Project analysis
// context). The package list is recorded there as the engagement's active imported SBOM and the
// existing SCA imported-SBOM scan runs against it: the same detectors, distro-qualified PURL
// matching, severity backfill, risk ranking, dedup and finding derivation a repository or image scan
// gets, and the same continuous reconciliation when advisories change. The console reads the
// findings back through the asset, never through the engagement routes, which keep hiding internal
// contexts.
//
// Recording is idempotent per package set: the CycloneDX document is a pure function of the
// packages, so an unchanged host does not re-import or re-scan on every hourly sweep.
package hostvuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// Filename is the artifact name the host package list is recorded under in the imported-SBOM store.
const Filename = "host-inventory.cdx.json"

// MaxPackages bounds one inventory. A real host carries a few thousand packages; a list far beyond
// that is not an inventory, and an agent must not be able to make the server render and scan one.
const MaxPackages = 50000

// MinRecordInterval is the shortest gap between two recorded package sets for one host. The sweep
// cadence is hourly; a host whose package set changes on every sync is being driven, not maintained,
// and the server records at most one set per interval instead of importing and scanning each time.
const MinRecordInterval = 10 * time.Minute

// targetPrefix makes the host's natural key a scope target the SCA gate can match exactly.
const targetPrefix = "host://"

// sbomEpoch pins the CycloneDX metadata timestamp so the document, and therefore its digest, depends
// only on the package set. The imported-SBOM record carries the real recording time.
var sbomEpoch = time.Unix(0, 0).UTC()

// SBOMScanner is the slice of the SCA service this use case drives.
type SBOMScanner interface {
	ImportContextSBOM(ctx context.Context, actor string, tenantID, engagementID shared.ID, filename string, data []byte) (*scauc.ScanResult, error)
	StartScanWithOptions(ctx context.Context, actor string, engagementID shared.ID, req ports.AcquireRequest, opts scauc.ScanOptions) (ports.ScanJob, error)
}

var _ SBOMScanner = (*scauc.Service)(nil)

// FindingLister reads the findings of one engagement.
type FindingLister interface {
	List(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error)
}

// Service records host packages and reads host vulnerabilities.
type Service struct {
	engagements ports.EngagementRepository
	assets      ports.AssetRepository
	findings    FindingLister
	summaries   ports.FindingSummaryReader // optional; nil ⇒ Hosts lists each context's findings to count them
	scanner     SBOMScanner
	imported    ports.ImportedSBOMStore
	jobs        ports.ScanJobStore
	ids         ports.IDGenerator
	clock       ports.Clock
	audit       ports.AuditLogger
}

// SetFindingSummaries wires the aggregate read Hosts uses to count findings per context in one query
// instead of loading every context's finding rows.
func (s *Service) SetFindingSummaries(r ports.FindingSummaryReader) { s.summaries = r }

var _ hostinventory.VulnerabilityRecorder = (*Service)(nil)

// NewService validates its dependencies and constructs the service.
func NewService(engagements ports.EngagementRepository, assets ports.AssetRepository, findings FindingLister, scanner SBOMScanner, imported ports.ImportedSBOMStore, jobs ports.ScanJobStore, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger) (*Service, error) {
	for name, dep := range map[string]any{
		"engagement repository": engagements, "asset repository": assets, "finding lister": findings, "sbom scanner": scanner,
		"imported sbom store": imported, "scan job store": jobs, "id generator": ids, "clock": clock, "audit logger": audit,
	} {
		if dep == nil {
			return nil, fmt.Errorf("%w: host vulnerabilities require a %s", shared.ErrValidation, name)
		}
	}
	return &Service{engagements: engagements, assets: assets, findings: findings, scanner: scanner, imported: imported, jobs: jobs, ids: ids, clock: clock, audit: audit}, nil
}

// TargetRef is the scope target and SBOM target the host's packages are recorded under.
func TargetRef(host *asset.Asset) string { return targetPrefix + host.Key }

// Record stores the host's packages as its SBOM and queues a vulnerability scan. It returns a
// skipped outcome when the host reported no packages or when the package set is unchanged since the
// last recorded scan and that scan did not fail.
func (s *Service) Record(ctx context.Context, actor string, tenantID shared.ID, host *asset.Asset, inv dhi.HostInventory) (hostinventory.VulnerabilityOutcome, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return hostinventory.VulnerabilityOutcome{}, fmt.Errorf("%w: host vulnerability actor is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return hostinventory.VulnerabilityOutcome{}, fmt.Errorf("%w: host vulnerability tenant id is required", shared.ErrValidation)
	}
	if host == nil || host.ID.IsZero() || host.Kind != asset.KindHost {
		return hostinventory.VulnerabilityOutcome{}, fmt.Errorf("%w: host vulnerabilities need a persisted Kind=host asset", shared.ErrValidation)
	}
	if len(inv.Packages) == 0 {
		return hostinventory.VulnerabilityOutcome{Skipped: true, Reason: hostinventory.ReasonNoPackages}, nil
	}
	if len(inv.Packages) > MaxPackages {
		return hostinventory.VulnerabilityOutcome{}, fmt.Errorf("%w: host reported %d packages, above the %d cap", shared.ErrValidation, len(inv.Packages), MaxPackages)
	}

	ref := TargetRef(host)
	data, err := Document(host, inv.Packages)
	if err != nil {
		return hostinventory.VulnerabilityOutcome{}, err
	}
	digest := hashHex(data)

	eng, created, err := s.ensureContext(ctx, actor, tenantID, host, ref)
	if err != nil {
		return hostinventory.VulnerabilityOutcome{}, err
	}
	outcome := hostinventory.VulnerabilityOutcome{EngagementID: eng.ID, Components: len(inv.Packages)}
	if !created {
		state, err := s.lastScanState(ctx, tenantID, eng.ID, digest)
		if err != nil {
			return hostinventory.VulnerabilityOutcome{}, err
		}
		switch state {
		case scanUnchanged:
			outcome.Skipped, outcome.Reason = true, hostinventory.ReasonUnchanged
			return outcome, nil
		case scanActive:
			// The worker reloads the active SBOM when it executes, so replacing it under a running
			// scan would change what that scan measures. The next sweep records the new set.
			outcome.Skipped, outcome.Reason = true, hostinventory.ReasonScanActive
			return outcome, nil
		case scanRecent:
			outcome.Skipped, outcome.Reason = true, hostinventory.ReasonRecordedRecently
			return outcome, nil
		}
	}

	if _, err := s.scanner.ImportContextSBOM(ctx, actor, tenantID, eng.ID, Filename, data); err != nil {
		return hostinventory.VulnerabilityOutcome{}, fmt.Errorf("record host packages: %w", err)
	}
	job, err := s.scanner.StartScanWithOptions(ctx, actor, eng.ID, ports.AcquireRequest{}, scauc.ScanOptions{Mode: scauc.ScanModeFull})
	if err != nil {
		return hostinventory.VulnerabilityOutcome{}, fmt.Errorf("queue host vulnerability scan: %w", err)
	}
	outcome.JobID = job.ID
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "host_inventory.vulnerability_scan_queued",
		Target: host.ID.String(),
		Metadata: map[string]string{
			"tenant_id":   tenantID.String(),
			"asset_id":    host.ID.String(),
			"engagement":  eng.ID.String(),
			"job_id":      job.ID,
			"packages":    strconv.Itoa(len(inv.Packages)),
			"sbom_sha256": digest,
		},
		At: s.clock.Now(),
	}); err != nil {
		return hostinventory.VulnerabilityOutcome{}, fmt.Errorf("audit host vulnerability scan: %w", err)
	}
	return outcome, nil
}

// Document renders the host's packages as the CycloneDX document the SCA pipeline consumes. It is
// deterministic for a given package set (sorted components, pinned timestamp) so two syncs of an
// unchanged host produce byte-identical documents.
func Document(host *asset.Asset, packages []sbom.Component) ([]byte, error) {
	ref := TargetRef(host)
	comps := append([]sbom.Component(nil), packages...)
	sort.Slice(comps, func(i, j int) bool {
		if comps[i].Name != comps[j].Name {
			return comps[i].Name < comps[j].Name
		}
		if comps[i].Version != comps[j].Version {
			return comps[i].Version < comps[j].Version
		}
		return comps[i].PURL < comps[j].PURL
	})
	data, err := scauc.MarshalCycloneDX(&sbom.SBOM{TargetRef: ref, Source: "synapse-agent", Components: comps}, ref, sbomEpoch)
	if err != nil {
		return nil, fmt.Errorf("render host package sbom: %w", err)
	}
	return data, nil
}

// ensureContext loads the host's hidden engagement or creates it. Two syncs of a new host can race
// here; the store's uniqueness on (tenant, host asset) makes the loser fail, and it then reads the
// winner's row.
func (s *Service) ensureContext(ctx context.Context, actor string, tenantID shared.ID, host *asset.Asset, ref string) (*engagement.Engagement, bool, error) {
	eng, err := s.engagements.GetByHostAssetID(ctx, tenantID, host.ID)
	if err == nil {
		return eng, false, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, false, fmt.Errorf("load host vulnerability context: %w", err)
	}
	now := s.clock.Now()
	eng, err = engagement.New(s.ids.NewID(), tenantID, host.Name+" host vulnerabilities", "", now)
	if err != nil {
		return nil, false, fmt.Errorf("build host vulnerability context: %w", err)
	}
	eng.HostAssetID = host.ID
	eng.Audit.CreatedBy, eng.Audit.UpdatedBy = actor, actor
	if err := eng.SetScope([]engagement.Target{{Kind: engagement.TargetRepo, Value: ref}}, nil, now); err != nil {
		return nil, false, fmt.Errorf("scope host vulnerability context: %w", err)
	}
	if err := s.engagements.Create(ctx, eng); err != nil {
		if existing, gerr := s.engagements.GetByHostAssetID(ctx, tenantID, host.ID); gerr == nil {
			return existing, false, nil
		}
		return nil, false, fmt.Errorf("create host vulnerability context: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "host_inventory.vulnerability_context_created",
		Target: host.ID.String(),
		Metadata: map[string]string{
			"tenant_id":  tenantID.String(),
			"asset_id":   host.ID.String(),
			"engagement": eng.ID.String(),
			"target":     ref,
		},
		At: now,
	}); err != nil {
		return nil, false, fmt.Errorf("audit host vulnerability context: %w", err)
	}
	return eng, true, nil
}

type scanState int

const (
	scanStale     scanState = iota // no record, a different package set, or a failed scan: record and scan
	scanUnchanged                  // same package set and the last scan did not fail: nothing to do
	scanActive                     // a scan is still running: do not replace its input
	scanRecent                     // a different set, but one was recorded less than MinRecordInterval ago
)

// lastScanState compares the active imported SBOM and the latest scan job with the digest of the
// package set being recorded. A failed or missing scan is retried even when the package set did not
// change, and so is a scan that started before the active record was written: the import succeeded
// but the scan start did not, so the recorded set has never been measured.
func (s *Service) lastScanState(ctx context.Context, tenantID, engagementID shared.ID, digest string) (scanState, error) {
	job, err := s.jobs.LatestForEngagement(ctx, engagementID)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		return scanStale, nil
	case err != nil:
		return scanStale, fmt.Errorf("load latest host vulnerability scan: %w", err)
	case job.Status == ports.ScanRunning:
		return scanActive, nil
	}
	// Metadata only: the digest and the recording time decide; the document body (hundreds of KB per
	// host, every hourly sweep) stays in the store.
	recs, err := s.imported.MetadataByEngagements(ctx, tenantID, []shared.ID{engagementID})
	if err != nil {
		return scanStale, fmt.Errorf("load recorded host packages: %w", err)
	}
	rec, ok := recs[engagementID]
	if !ok {
		return scanStale, nil
	}
	if rec.SHA256 != digest {
		if s.clock.Now().Sub(rec.CreatedAt) < MinRecordInterval {
			return scanRecent, nil
		}
		return scanStale, nil
	}
	if job.Status == ports.ScanFailed || job.StartedAt.Before(rec.CreatedAt) {
		return scanStale, nil
	}
	return scanUnchanged, nil
}

// Summary counts a host's vulnerability findings.
type Summary = ports.VulnerabilitySummary

// HostVulnerabilities is one host's recorded package set, its latest scan, and the findings.
type HostVulnerabilities struct {
	Asset        *asset.Asset
	EngagementID shared.ID // zero when the host has never reported packages
	Packages     int
	RecordedAt   time.Time
	LastScan     *ports.ScanJob
	Summary      Summary
	Findings     []finding.Finding
}

// HostSummary is the list-view projection of HostVulnerabilities without the findings.
type HostSummary struct {
	Asset        *asset.Asset
	EngagementID shared.ID
	Packages     int
	RecordedAt   time.Time
	LastScan     *ports.ScanJob
	Summary      Summary
}

// Vulnerabilities returns the host's current vulnerability findings, highest risk first.
func (s *Service) Vulnerabilities(ctx context.Context, tenantID, assetID shared.ID) (*HostVulnerabilities, error) {
	host, err := s.assets.GetAssetByID(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if host.Kind != asset.KindHost {
		return nil, fmt.Errorf("%w: asset %s is a %s, not a host", shared.ErrValidation, host.ID, host.Kind)
	}
	out := &HostVulnerabilities{Asset: host, Findings: []finding.Finding{}}
	eng, err := s.engagements.GetByHostAssetID(ctx, tenantID, host.ID)
	if errors.Is(err, shared.ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load host vulnerability context: %w", err)
	}
	out.EngagementID = eng.ID
	recs, err := s.imported.MetadataByEngagements(ctx, tenantID, []shared.ID{eng.ID})
	if err != nil {
		return nil, fmt.Errorf("load recorded host packages: %w", err)
	}
	if rec, ok := recs[eng.ID]; ok {
		out.Packages, out.RecordedAt = rec.ComponentCount, rec.CreatedAt
	}
	if job, err := s.jobs.LatestForEngagement(ctx, eng.ID); err == nil {
		out.LastScan = &job
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("load latest host vulnerability scan: %w", err)
	}
	list, err := s.findings.List(ctx, eng.ID)
	if err != nil {
		return nil, fmt.Errorf("list host vulnerabilities: %w", err)
	}
	for _, f := range list {
		if isVulnerability(f) {
			out.Findings = append(out.Findings, f)
		}
	}
	out.Summary = summarize(out.Findings)
	return out, nil
}

// Hosts lists every host asset with its vulnerability summary. It is five round trips for the whole
// fleet, independent of the host count: the host assets, their contexts, the active SBOM metadata,
// the per-context finding summary and the latest scan jobs. Without a summary reader it falls back to
// listing each context's findings, which is O(H) reads and fine for a small fleet only.
func (s *Service) Hosts(ctx context.Context, tenantID shared.ID) ([]HostSummary, error) {
	all, err := s.assets.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list host assets: %w", err)
	}
	hosts := make([]*asset.Asset, 0, len(all))
	for _, a := range all {
		if a.Kind == asset.KindHost {
			hosts = append(hosts, a)
		}
	}
	contexts, err := s.contextsByHost(ctx, tenantID, hosts)
	if err != nil {
		return nil, err
	}
	engagementIDs := make([]shared.ID, 0, len(contexts))
	for _, eng := range contexts {
		engagementIDs = append(engagementIDs, eng.ID)
	}
	sort.Slice(engagementIDs, func(i, j int) bool { return engagementIDs[i] < engagementIDs[j] })

	metadata := map[shared.ID]importedsbom.Metadata{}
	summaries := map[shared.ID]Summary{}
	jobs := map[shared.ID]ports.ScanJob{}
	if len(engagementIDs) > 0 {
		if metadata, err = s.imported.MetadataByEngagements(ctx, tenantID, engagementIDs); err != nil {
			return nil, fmt.Errorf("load recorded host packages: %w", err)
		}
		if summaries, err = s.summarize(ctx, engagementIDs); err != nil {
			return nil, err
		}
		if jobs, err = s.jobs.LatestForEngagements(ctx, engagementIDs); err != nil {
			return nil, fmt.Errorf("load latest host vulnerability scans: %w", err)
		}
	}

	out := make([]HostSummary, 0, len(hosts))
	for _, a := range hosts {
		row := HostSummary{Asset: a}
		if eng, ok := contexts[a.ID]; ok {
			row.EngagementID = eng.ID
			if rec, ok := metadata[eng.ID]; ok {
				row.Packages, row.RecordedAt = rec.ComponentCount, rec.CreatedAt
			}
			row.Summary = summaries[eng.ID]
			if job, ok := jobs[eng.ID]; ok {
				j := job
				row.LastScan = &j
			}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Summary.Critical != out[j].Summary.Critical {
			return out[i].Summary.Critical > out[j].Summary.Critical
		}
		if out[i].Summary.High != out[j].Summary.High {
			return out[i].Summary.High > out[j].Summary.High
		}
		if out[i].Summary.Total != out[j].Summary.Total {
			return out[i].Summary.Total > out[j].Summary.Total
		}
		return out[i].Asset.Name < out[j].Asset.Name
	})
	return out, nil
}

// contextsByHost resolves the hidden context of every host in one read when the repository can list
// them, else one lookup per host.
func (s *Service) contextsByHost(ctx context.Context, tenantID shared.ID, hosts []*asset.Asset) (map[shared.ID]*engagement.Engagement, error) {
	out := make(map[shared.ID]*engagement.Engagement, len(hosts))
	if lister, ok := s.engagements.(ports.HostEngagementLister); ok {
		all, err := lister.ListHostEngagements(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("list host vulnerability contexts: %w", err)
		}
		for _, eng := range all {
			out[eng.HostAssetID] = eng
		}
		return out, nil
	}
	for _, a := range hosts {
		eng, err := s.engagements.GetByHostAssetID(ctx, tenantID, a.ID)
		if errors.Is(err, shared.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("load host vulnerability context: %w", err)
		}
		out[a.ID] = eng
	}
	return out, nil
}

// summarize counts findings per context: one aggregate query when a summary reader is wired, else one
// finding list per context.
func (s *Service) summarize(ctx context.Context, engagementIDs []shared.ID) (map[shared.ID]Summary, error) {
	if s.summaries != nil {
		out, err := s.summaries.SummarizeVulnerabilitiesByEngagements(ctx, engagementIDs)
		if err != nil {
			return nil, fmt.Errorf("summarize host vulnerabilities: %w", err)
		}
		return out, nil
	}
	out := make(map[shared.ID]Summary, len(engagementIDs))
	for _, id := range engagementIDs {
		list, err := s.findings.List(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("list host vulnerabilities: %w", err)
		}
		vulns := make([]finding.Finding, 0, len(list))
		for _, f := range list {
			if isVulnerability(f) {
				vulns = append(vulns, f)
			}
		}
		out[id] = summarize(vulns)
	}
	return out, nil
}

// isVulnerability keeps the advisory-backed findings of the context. The imported-SBOM pipeline also
// derives license findings from the same components; those are not host vulnerabilities.
func isVulnerability(f finding.Finding) bool {
	if f.Kind != "" && f.Kind != finding.KindSCA {
		return false
	}
	return !strings.HasPrefix(f.DedupKey, "license:")
}

func summarize(list []finding.Finding) Summary {
	var sum Summary
	for _, f := range list {
		sum.Add(f.Severity, strings.TrimSpace(f.FixedVersion) != "", f.KEV)
	}
	return sum
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
