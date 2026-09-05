// Package hostinventory is the use-case layer for the VM host agent (#410/#446, epic #405). It takes
// a host inventory an agent collected (facts + installed OS packages + coverage) and persists the
// host as a Kind=host asset in the fleet asset model (#431), reusing the asset use case's idempotent
// upsert-by-natural-key + audit path.
//
// Coverage honesty is preserved: the inventory's coverage issues are recorded (count + degraded flag
// on the asset, each issue audited), so a partial host inventory is never presented as complete. The
// asset model records the host identity, its facts, and a package count; the package LIST goes to the
// optional VulnerabilityRecorder (the hostvuln use case), which records it as the host's SBOM and
// queues the SCA vulnerability pipeline against it (#820).
package hostinventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MaxHostsPerAgent bounds how many distinct host assets one agent identity may create. An agent
// reports the host it runs on; a machine-id change (reimage, cloned VM) legitimately makes a new one,
// so the cap is a small multiple rather than one. Above it, a new key is refused: an agent varying its
// facts must not mint host assets, hidden vulnerability contexts and scans without bound.
const MaxHostsPerAgent = dhi.MaxHostsPerAgent

// AssetWriter is the subset of the asset use case this service needs. The read is part of the
// authorization boundary: an authenticated agent may update the host it already reports, but must
// never silently take over a host natural key already owned by a different enrolled agent.
type AssetWriter interface {
	GetAssetByKey(ctx context.Context, tenantID shared.ID, kind asset.Kind, key string) (*asset.Asset, error)
	UpsertAsset(ctx context.Context, actor string, in assetuc.UpsertAssetInput) (*asset.Asset, error)
	ListAssets(ctx context.Context, tenantID shared.ID) ([]*asset.Asset, error)
}

// The concrete asset use case satisfies the consumer-side interface.
var _ AssetWriter = (*assetuc.Service)(nil)

// VulnerabilityRecorder turns the packages a host reported into CVE findings for that host (#820). The
// concrete implementation lives in the hostvuln use case; this consumer-side interface keeps the
// inventory path free of the SCA pipeline's types.
type VulnerabilityRecorder interface {
	Record(ctx context.Context, actor string, tenantID shared.ID, host *asset.Asset, inv dhi.HostInventory) (VulnerabilityOutcome, error)
}

// VulnerabilityOutcome reports what a sync did with the host's package list. Skipped with a Reason is
// a normal outcome (no packages, or the package set is unchanged since the last recorded scan);
// Failed marks a recorder error that was audited and did not fail the inventory sync.
type VulnerabilityOutcome struct {
	EngagementID shared.ID `json:"engagement_id,omitempty"`
	JobID        string    `json:"job_id,omitempty"`
	Components   int       `json:"components"`
	Skipped      bool      `json:"skipped"`
	Failed       bool      `json:"failed,omitempty"`
	Reason       string    `json:"reason,omitempty"`
}

// Reasons a sync records no new vulnerability scan.
const (
	ReasonNoPackages = "no packages reported"
	ReasonUnchanged  = "package set unchanged since the last recorded scan"
	ReasonScanActive = "a vulnerability scan is still running for this host; the next sync records the change"
	// ReasonRecordedRecently: a different package set arrived within the minimum record interval.
	ReasonRecordedRecently = "a package set was recorded for this host less than ten minutes ago; the next sync records the change"
	ReasonQueueError       = "vulnerability scan could not be queued; see the audit log"
)

// Service maps and persists a host inventory.
type Service struct {
	assets   AssetWriter
	audit    ports.AuditLogger
	clock    ports.Clock
	bindings ports.TelemetryAssetBindingStore // optional; nil ⇒ no telemetry asset binding is established
	vulns    VulnerabilityRecorder            // optional; nil ⇒ packages are counted but not correlated with advisories
}

// SetVulnerabilityRecorder wires the recorder that correlates the reported packages with advisories.
// When set, every sync that carries packages records them as the host's SBOM and queues a
// vulnerability scan; a recorder failure is audited and reported in the result, never returned, so a
// host inventory is persisted even when the scan pipeline is unavailable.
func (s *Service) SetVulnerabilityRecorder(r VulnerabilityRecorder) { s.vulns = r }

// SetTelemetryBinder wires the server-authoritative agent→host telemetry binding store. When set, a
// successful host-inventory sync establishes (or refreshes) the reporting agent's canonical telemetry
// asset binding — the A3 mapping that telemetry ingest requires (see the Sync doc comment). Kept an
// optional setter (nil ⇒ no binding) so telemetry-less compositions are unchanged.
func (s *Service) SetTelemetryBinder(b ports.TelemetryAssetBindingStore) { s.bindings = b }

// NewService validates its dependencies and constructs the service.
func NewService(assets AssetWriter, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if assets == nil {
		return nil, fmt.Errorf("%w: host inventory requires an asset writer", shared.ErrValidation)
	}
	if audit == nil {
		return nil, fmt.Errorf("%w: host inventory requires an audit logger", shared.ErrValidation)
	}
	if clock == nil {
		return nil, fmt.Errorf("%w: host inventory requires a clock", shared.ErrValidation)
	}
	return &Service{assets: assets, audit: audit, clock: clock}, nil
}

// SyncInput describes one observation of a host.
type SyncInput struct {
	TenantID  shared.ID
	Inventory dhi.HostInventory
}

// SyncResult reports what a sync produced.
type SyncResult struct {
	AssetID  shared.ID
	Complete bool
	Degraded bool
	Coverage int
	// VulnerabilityScan is nil when no recorder is wired.
	VulnerabilityScan *VulnerabilityOutcome
}

// Sync persists the host as a Kind=host asset. It is idempotent: two syncs of an unchanged host reuse
// the asset id (keyed by the host's stable identity) and produce no churn. reporting_agent_id is stamped
// from actor, which the HTTP adapter obtains from the authenticated fleet credential; it is never read
// from Inventory. A3 uses this server-authored attribute to establish the canonical telemetry binding.
func (s *Service) Sync(ctx context.Context, actor string, in SyncInput) (*SyncResult, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return nil, fmt.Errorf("%w: host inventory actor is required", shared.ErrValidation)
	}
	if in.TenantID.IsZero() {
		return nil, fmt.Errorf("%w: host inventory tenant id is required", shared.ErrValidation)
	}
	inv := in.Inventory.Normalize()

	key := hostKey(inv.Facts)
	if key == "" {
		return nil, fmt.Errorf("%w: host has no stable identity (machine id or hostname required)", shared.ErrValidation)
	}
	if err := s.guardAssetBinding(ctx, actor, in.TenantID, key); err != nil {
		return nil, err
	}
	degraded := inv.Degraded()

	a, err := s.assets.UpsertAsset(ctx, actor, assetuc.UpsertAssetInput{
		TenantID:   in.TenantID,
		Kind:       asset.KindHost,
		Key:        key,
		Name:       displayName(inv.Facts, key),
		Attributes: attributes(inv, degraded, actor),
	})
	if err != nil {
		if errors.Is(err, shared.ErrForbidden) {
			// The store's own cap check refused the row: two syncs from this agent raced past
			// guardHostsPerAgent and the transaction-level backstop caught the second. Audit it the
			// same way so the refusal stays attributable.
			if aerr := s.auditHostCap(ctx, actor, in.TenantID, key, MaxHostsPerAgent); aerr != nil {
				return nil, aerr
			}
		}
		return nil, fmt.Errorf("host inventory: upsert host asset: %w", err)
	}

	// Audit each coverage gap so a partial host inventory is durably attributable, not just implied.
	now := s.clock.Now()
	for _, c := range inv.Coverage {
		if err := s.audit.Record(ctx, ports.AuditEntry{
			Actor:  actor,
			Action: "host_inventory.coverage_gap",
			Target: key,
			Metadata: map[string]string{
				"tenant_id": in.TenantID.String(),
				"gap_kind":  string(c.Kind),
				"detail":    c.Detail,
			},
			At: now,
		}); err != nil {
			return nil, fmt.Errorf("host inventory: audit coverage gap: %w", err)
		}
	}

	// Establish the canonical telemetry binding this host inventory authorizes: the authenticated
	// reporting agent (actor) owns the host asset it just reconciled. Without this, telemetry ingest
	// cannot resolve the agent's asset and refuses every batch. guardAssetBinding above already proved
	// the reporting agent is not stealing another agent's host, so a cross-agent conflict here is a real
	// race and is surfaced, never swallowed.
	if s.bindings != nil {
		if err := s.bindings.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{
			TenantID: in.TenantID, AgentID: shared.ID(actor), AssetID: a.ID, UpdatedAt: now,
		}); err != nil {
			return nil, fmt.Errorf("host inventory: establish telemetry asset binding: %w", err)
		}
		// Audit the establishment/refresh of this server-authoritative binding, mirroring how blocked
		// takeovers and coverage gaps are audited — the binding is a first-class trust action, so its
		// creation must be as attributable as its rejection.
		if err := s.audit.Record(ctx, ports.AuditEntry{
			Actor:  actor,
			Action: "host_inventory.telemetry_binding_established",
			Target: a.ID.String(),
			Metadata: map[string]string{
				"tenant_id": in.TenantID.String(),
				"asset_id":  a.ID.String(),
				"agent_id":  actor,
			},
			At: now,
		}); err != nil {
			return nil, fmt.Errorf("host inventory: audit telemetry binding: %w", err)
		}
	}

	res := &SyncResult{AssetID: a.ID, Complete: inv.Complete, Degraded: degraded, Coverage: len(inv.Coverage)}
	if s.vulns != nil {
		outcome, err := s.recordVulnerabilities(ctx, actor, in.TenantID, a, inv, now)
		if err != nil {
			return nil, err
		}
		res.VulnerabilityScan = &outcome
	}
	return res, nil
}

// recordVulnerabilities hands the package list to the recorder. The inventory is already persisted,
// so a recorder failure is audited with the cause and reported as a failed outcome rather than
// undoing the sync; the agent resends the inventory on its next sweep and the scan is retried then.
// Only an audit failure is returned, because an unattributable failure is the one thing this path
// must not swallow.
func (s *Service) recordVulnerabilities(ctx context.Context, actor string, tenantID shared.ID, a *asset.Asset, inv dhi.HostInventory, now time.Time) (VulnerabilityOutcome, error) {
	outcome, err := s.vulns.Record(ctx, actor, tenantID, a, inv)
	if err == nil {
		return outcome, nil
	}
	if aerr := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "host_inventory.vulnerability_scan_failed",
		Target: a.ID.String(),
		Metadata: map[string]string{
			"tenant_id": tenantID.String(),
			"asset_id":  a.ID.String(),
			"packages":  strconv.Itoa(len(inv.Packages)),
			"error":     err.Error(),
		},
		At: now,
	}); aerr != nil {
		return VulnerabilityOutcome{}, fmt.Errorf("host inventory: audit vulnerability scan failure: %w", aerr)
	}
	return VulnerabilityOutcome{Components: len(inv.Packages), Skipped: true, Failed: true, Reason: ReasonQueueError}, nil
}

// guardAssetBinding prevents an authenticated agent from claiming the stable natural key of a host that
// is already attributed to a different enrolled agent. The audit record and security alert are emitted
// before returning the conflict, so a rejected takeover remains attributable even though no asset write
// occurs. PostgreSQL independently enforces the same invariant to close the lookup/write race.
func (s *Service) guardAssetBinding(ctx context.Context, actor string, tenantID shared.ID, key string) error {
	existing, err := s.assets.GetAssetByKey(ctx, tenantID, asset.KindHost, key)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		return s.guardHostsPerAgent(ctx, actor, tenantID, key)
	case err != nil:
		return fmt.Errorf("host inventory: lookup host asset: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("host inventory: lookup host asset returned nil without error")
	}
	oldAgent := strings.TrimSpace(existing.Attributes["reporting_agent_id"])
	if oldAgent == "" || oldAgent == actor {
		return nil
	}

	now := s.clock.Now()
	metadata := func() map[string]string {
		return map[string]string{
			"tenant_id":    tenantID.String(),
			"asset_id":     existing.ID.String(),
			"asset_key":    key,
			"old_agent_id": oldAgent,
			"new_agent_id": actor,
		}
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor,
		Action:   "host_inventory.asset_binding_takeover_blocked",
		Target:   existing.ID.String(),
		Metadata: metadata(),
		At:       now,
	}); err != nil {
		return fmt.Errorf("host inventory: audit blocked asset-binding takeover: %w", err)
	}
	alert := metadata()
	alert["alert_type"] = "telemetry_asset_binding_takeover"
	alert["severity"] = "high"
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor,
		Action:   "security.alert",
		Target:   existing.ID.String(),
		Metadata: alert,
		At:       now,
	}); err != nil {
		return fmt.Errorf("host inventory: emit asset-binding security alert: %w", err)
	}
	return fmt.Errorf("%w: host asset %s is already bound to agent %s", shared.ErrConflict, existing.ID, oldAgent)
}

// guardHostsPerAgent refuses a NEW host key once the reporting agent already owns MaxHostsPerAgent
// hosts. It runs only when the key is new, so the O(assets) scan is paid on host creation, not on
// every sync. The refusal is audited so a misbehaving or compromised agent is attributable.
func (s *Service) guardHostsPerAgent(ctx context.Context, actor string, tenantID shared.ID, key string) error {
	all, err := s.assets.ListAssets(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("host inventory: count agent hosts: %w", err)
	}
	owned := 0
	for _, a := range all {
		if a.Kind == asset.KindHost && strings.TrimSpace(a.Attributes["reporting_agent_id"]) == actor {
			owned++
		}
	}
	if owned < MaxHostsPerAgent {
		return nil
	}
	if err := s.auditHostCap(ctx, actor, tenantID, key, owned); err != nil {
		return err
	}
	return fmt.Errorf("%w: agent %s already reports %d hosts; a new host key is refused", shared.ErrForbidden, actor, owned)
}

// auditHostCap records a refused host key. owned is the count the refusing side observed: the use
// case's own count on the fast path, the cap itself when the store's transactional check refused.
func (s *Service) auditHostCap(ctx context.Context, actor string, tenantID shared.ID, key string, owned int) error {
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "host_inventory.host_cap_reached",
		Target: key,
		Metadata: map[string]string{
			"tenant_id": tenantID.String(),
			"asset_key": key,
			"hosts":     strconv.Itoa(owned),
			"cap":       strconv.Itoa(MaxHostsPerAgent),
		},
		At: s.clock.Now(),
	}); err != nil {
		return fmt.Errorf("host inventory: audit host cap: %w", err)
	}
	return nil
}

// hostKey is the host's stable natural key: the machine id when known (survives hostname changes),
// else a hostname-derived key, else empty (unidentifiable).
func hostKey(f dhi.HostFacts) string {
	if f.MachineID != "" {
		return "machine-id/" + f.MachineID
	}
	if f.Hostname != "" {
		return "hostname/" + f.Hostname
	}
	return ""
}

func displayName(f dhi.HostFacts, key string) string {
	if f.Hostname != "" {
		return f.Hostname
	}
	return key
}

func attributes(inv dhi.HostInventory, degraded bool, reportingAgent string) map[string]string {
	f := inv.Facts
	attrs := map[string]string{
		"os":                 f.OS,
		"os_version":         f.OSVersion,
		"kernel":             f.Kernel,
		"arch":               f.Arch,
		"machine_id":         f.MachineID,
		"cloud_instance":     f.CloudInstance,
		"packages":           strconv.Itoa(len(inv.Packages)),
		"complete":           strconv.FormatBool(inv.Complete),
		"degraded":           strconv.FormatBool(degraded),
		"coverage_gaps":      strconv.Itoa(len(inv.Coverage)),
		"reporting_agent_id": strings.TrimSpace(reportingAgent),
	}
	// Drop empty fact values so the asset attributes stay clean.
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	return attrs
}
