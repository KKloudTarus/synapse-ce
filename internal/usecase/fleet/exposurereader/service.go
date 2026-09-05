// Package exposurereader adapts the shipped SCA stores (asset↔component membership, vulnerability
// occurrences, and per-occurrence risk assessments) into the exposureuc.AssetVulnerabilityReader port —
// the missing join that lets the X5 Exposure producer read an asset's open vulnerable components with their
// evaluated Priority/KEV/Severity. It reuses the already-evaluated risk (vulnerabilityrisk.Assessment); it
// recomputes nothing. Every read is tenant-scoped from ctx. When constructed with NewReaderWithRuntime it
// also resolves running-vs-installed — marking a vulnerable component Running if its package matches a
// process observed executing on one of the asset's hosts (the B5 process store); constructed with NewReader
// (no runtime signals) it reports installed-only and the producer notes the reduced precision.
package exposurereader

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityoccurrence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityrisk"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/exposureuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The shipped store interfaces satisfy the narrow reader views this adapter needs — asserted here so a
// signature drift in ports breaks the build rather than the composition-root wiring.
var (
	_ MembershipReader = ports.BusinessAssetRepository(nil)
	_ OccurrenceReader = ports.VulnerabilityOccurrenceStore(nil)
	_ RiskReader       = ports.VulnerabilityRiskAssessmentStore(nil)
)

// MembershipReader is the asset-side view: which engagements an asset is assigned to and which projects
// and technical (fleet) assets make it up. ports.BusinessAssetRepository satisfies it. Occurrences carry
// no AssetID; they carry an EngagementID, so the bridge from an asset to its vulnerabilities is the set of
// engagements that belong to the asset: the ones assigned to it, plus the hidden analysis context of each
// linked project and the hidden vulnerability context of each linked host (see ContextResolver).
type MembershipReader interface {
	ListEngagementsByBusinessAsset(ctx context.Context, tenantID, assetID shared.ID) ([]*engagement.Engagement, error)
	ListBusinessAssetProjects(ctx context.Context, tenantID, assetID shared.ID) ([]asset.ComponentMembership, error)
	ListBusinessAssetTechnicalAssets(ctx context.Context, tenantID, assetID shared.ID) ([]asset.ComponentMembership, error)
}

// ContextResolver resolves a linked project or host to its machine-owned engagement, where that
// project's or host's SBOM and occurrences live. ports.EngagementRepository satisfies it.
type ContextResolver interface {
	ProjectContexts(ctx context.Context, tenantID shared.ID, projectIDs []shared.ID) (map[shared.ID]*engagement.Engagement, error)
	GetByHostAssetID(ctx context.Context, tenantID, assetID shared.ID) (*engagement.Engagement, error)
}

var _ ContextResolver = ports.EngagementRepository(nil)

// OccurrenceReader lists an engagement's vulnerability occurrences by state. ports.VulnerabilityOccurrenceStore satisfies it.
type OccurrenceReader interface {
	ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID, states []vulnerabilityoccurrence.State) ([]vulnerabilityoccurrence.Occurrence, error)
}

// RiskReader returns the current risk evaluation for one occurrence. ports.VulnerabilityRiskAssessmentStore satisfies it.
type RiskReader interface {
	Current(ctx context.Context, tenantID, occurrenceID shared.ID) (vulnerabilityrisk.Assessment, error)
}

// ProcessLister returns the running processes for a HOST/fleet asset (the running side of
// running-vs-installed). ports.EndpointProcessStore satisfies it.
type ProcessLister interface {
	ListRunningByAsset(ctx context.Context, assetID shared.ID) ([]ports.ProcessSnapshot, error)
}

// ComponentLister enumerates an engagement's current components so a vulnerable ComponentID can be resolved
// to a package name for process matching. The concrete ComponentInventoryStore satisfies it.
type ComponentLister interface {
	ListCurrentComponentsByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]sbom.ComponentRecord, error)
}

// Reader implements exposureuc.AssetVulnerabilityReader over the SCA stores. processes + components are
// OPTIONAL: when both are wired (NewReaderWithRuntime), the reader resolves the running-vs-installed
// Presence; when nil (NewReader), every component is reported installed-only.
type Reader struct {
	memberships MembershipReader
	contexts    ContextResolver
	occurrences OccurrenceReader
	risk        RiskReader
	processes   ProcessLister
	components  ComponentLister
}

var (
	_ exposureuc.AssetVulnerabilityReader = (*Reader)(nil)
	_ ProcessLister                       = ports.EndpointProcessStore(nil)
)

// NewReader constructs the adapter. All four stores are required.
func NewReader(memberships MembershipReader, contexts ContextResolver, occurrences OccurrenceReader, risk RiskReader) (*Reader, error) {
	switch {
	case memberships == nil:
		return nil, fmt.Errorf("%w: exposure reader requires a membership store", shared.ErrValidation)
	case contexts == nil:
		return nil, fmt.Errorf("%w: exposure reader requires an engagement context resolver", shared.ErrValidation)
	case occurrences == nil:
		return nil, fmt.Errorf("%w: exposure reader requires an occurrence store", shared.ErrValidation)
	case risk == nil:
		return nil, fmt.Errorf("%w: exposure reader requires a risk store", shared.ErrValidation)
	}
	return &Reader{memberships: memberships, contexts: contexts, occurrences: occurrences, risk: risk}, nil
}

// NewReaderWithRuntime is NewReader plus the runtime signals needed to resolve running-vs-installed: the
// B5 process store (running processes per host) and a component enumerator (ComponentID -> package name).
// With both wired, a vulnerable component whose package matches a running process is marked Running.
func NewReaderWithRuntime(memberships MembershipReader, contexts ContextResolver, occurrences OccurrenceReader, risk RiskReader, processes ProcessLister, components ComponentLister) (*Reader, error) {
	r, err := NewReader(memberships, contexts, occurrences, risk)
	if err != nil {
		return nil, err
	}
	if processes == nil || components == nil {
		return nil, fmt.Errorf("%w: runtime reader requires a process store and a component lister", shared.ErrValidation)
	}
	r.processes = processes
	r.components = components
	return r, nil
}

func tenantIDFrom(ctx context.Context) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return "", fmt.Errorf("%w: tenant is required in context", shared.ErrValidation)
	}
	return tenantID, nil
}

// ListAssetVulnerableComponents resolves, for one asset, the engagements that belong to it and the
// currently-open vulnerability occurrences on those engagements (with their evaluated risk). The
// engagements are the ones assigned to the asset, the hidden analysis context of every linked project and
// the hidden vulnerability context of every linked host; an occurrence on one of them is the asset's by
// construction, so no further component filter is applied. (The previous join compared project and
// technical asset ids with SBOM component ids, two namespaces that never match, and read every asset as
// clean: #819.)
//
// It ABSTAINS with shared.ErrNotFound when the asset has no exposure data to assess: no memberships and
// no assigned engagement, or, when a component lister is wired, no engagement with a component inventory
// (nothing was ever scanned). An asset that IS scanned but has no open occurrences returns (nil, nil), a
// trustworthy clean.
func (r *Reader) ListAssetVulnerableComponents(ctx context.Context, assetID shared.ID) ([]exposureuc.AssetVulnerableComponent, error) {
	tenant, err := tenantIDFrom(ctx)
	if err != nil {
		return nil, err
	}
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: asset id is required", shared.ErrValidation)
	}

	engs, technical, err := r.assetEngagements(ctx, tenant, assetID)
	if err != nil {
		return nil, err
	}
	if len(engs) == 0 {
		return nil, fmt.Errorf("%w: asset %s is not scoped into any engagement and has no scanned components", shared.ErrNotFound, assetID)
	}
	if r.components != nil {
		scanned, err := r.anyInventory(ctx, tenant, engs)
		if err != nil {
			return nil, err
		}
		if !scanned {
			return nil, fmt.Errorf("%w: asset %s has no component inventory", shared.ErrNotFound, assetID)
		}
	}

	// Dedup by (component, advisory): the same vulnerable component can appear under more than one of the
	// asset's engagements, each with its own (possibly divergent) risk evaluation. Keep the WORST — the
	// exposure factor must never be under-reported — via a deterministic risk order (not first-seen, which
	// would depend on engagement iteration order).
	byKey := make(map[componentKey]exposureuc.AssetVulnerableComponent)
	skippedUnscored := false
	for _, eng := range engs {
		if eng == nil {
			continue // defensive: the store never appends nil, but don't deref one if it ever did
		}
		occs, err := r.occurrences.ListByEngagement(ctx, tenant, eng.ID, []vulnerabilityoccurrence.State{vulnerabilityoccurrence.StateDetected})
		if err != nil {
			return nil, fmt.Errorf("list occurrences for engagement %s: %w", eng.ID, err)
		}
		for _, occ := range occs {
			ra, err := r.risk.Current(ctx, tenant, occ.ID)
			if err != nil {
				if errors.Is(err, shared.ErrNotFound) {
					skippedUnscored = true // detected but not yet risk-evaluated
					continue
				}
				return nil, fmt.Errorf("current risk for occurrence %s: %w", occ.ID, err)
			}
			cand := exposureuc.AssetVulnerableComponent{
				ComponentID: occ.ComponentID,
				AdvisoryID:  shared.ID(occ.AdvisoryID),
				Severity:    ra.Severity,
				Priority:    ra.Priority,
				KEV:         ra.KEV,
				Running:     false, // installed-only until B5 process-entity snapshots land
			}
			k := componentKey{comp: cand.ComponentID, adv: cand.AdvisoryID}
			if prev, ok := byKey[k]; !ok || riskWorse(cand, prev) {
				byKey[k] = cand
			}
		}
	}

	if len(byKey) == 0 {
		if skippedUnscored {
			// Detected vulnerabilities exist on the asset's components but none is risk-evaluated yet — we
			// cannot honestly score it, so abstain rather than report a false clean.
			return nil, fmt.Errorf("%w: asset %s has detected vulnerabilities awaiting risk evaluation", shared.ErrNotFound, assetID)
		}
		return nil, nil // scanned, no open vulnerabilities — a trustworthy clean
	}

	// Resolve running-vs-installed when the runtime signals are wired (reusing the technical memberships
	// already fetched above as the host bridge).
	if r.processes != nil && r.components != nil {
		if err := r.markRunning(ctx, tenant, technical, engs, byKey); err != nil {
			return nil, err
		}
	}

	out := make([]exposureuc.AssetVulnerableComponent, 0, len(byKey))
	for _, v := range byKey {
		out = append(out, v)
	}
	// Deterministic order (component, then advisory) so repeated reads are reproducible.
	sort.Slice(out, func(i, j int) bool {
		if out[i].ComponentID != out[j].ComponentID {
			return out[i].ComponentID < out[j].ComponentID
		}
		return out[i].AdvisoryID < out[j].AdvisoryID
	})
	return out, nil
}

// assetEngagements returns the engagements whose occurrences belong to the asset, deduplicated by id,
// plus the technical (host) memberships the running-vs-installed step reuses as its host bridge. A linked
// project or host that has no context yet (never analysed, never reported packages) contributes nothing;
// the abstain rules above decide what an empty result means.
func (r *Reader) assetEngagements(ctx context.Context, tenant, assetID shared.ID) ([]*engagement.Engagement, []asset.ComponentMembership, error) {
	assigned, err := r.memberships.ListEngagementsByBusinessAsset(ctx, tenant, assetID)
	if err != nil {
		return nil, nil, fmt.Errorf("list engagements for asset %s: %w", assetID, err)
	}
	projects, err := r.memberships.ListBusinessAssetProjects(ctx, tenant, assetID)
	if err != nil {
		return nil, nil, fmt.Errorf("list project components for asset %s: %w", assetID, err)
	}
	technical, err := r.memberships.ListBusinessAssetTechnicalAssets(ctx, tenant, assetID)
	if err != nil {
		return nil, nil, fmt.Errorf("list technical components for asset %s: %w", assetID, err)
	}

	seen := make(map[shared.ID]bool, len(assigned)+len(projects)+len(technical))
	out := make([]*engagement.Engagement, 0, len(assigned)+len(projects)+len(technical))
	add := func(e *engagement.Engagement) {
		if e == nil || e.ID.IsZero() || seen[e.ID] {
			return
		}
		seen[e.ID] = true
		out = append(out, e)
	}
	for _, e := range assigned {
		add(e)
	}
	if len(projects) > 0 {
		ids := make([]shared.ID, 0, len(projects))
		for _, m := range projects {
			ids = append(ids, m.ComponentID) // ComponentID here is the project id
		}
		contexts, err := r.contexts.ProjectContexts(ctx, tenant, ids)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve project contexts for asset %s: %w", assetID, err)
		}
		// Deterministic order: by project id, not map iteration.
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			add(contexts[id])
		}
	}
	for _, m := range technical {
		e, err := r.contexts.GetByHostAssetID(ctx, tenant, m.ComponentID) // ComponentID here is the host asset id
		if errors.Is(err, shared.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("resolve host context %s for asset %s: %w", m.ComponentID, assetID, err)
		}
		add(e)
	}
	return out, technical, nil
}

// anyInventory reports whether at least one of the engagements has a current component inventory, which
// is the evidence that something was scanned. Without it a zero-occurrence result would be an unscanned
// asset read as clean.
func (r *Reader) anyInventory(ctx context.Context, tenant shared.ID, engs []*engagement.Engagement) (bool, error) {
	for _, eng := range engs {
		recs, err := r.components.ListCurrentComponentsByEngagement(ctx, tenant, eng.ID)
		if err != nil {
			return false, fmt.Errorf("list components for engagement %s: %w", eng.ID, err)
		}
		if len(recs) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// componentKey dedups a vulnerable (component, advisory) across the asset's engagements.
type componentKey struct{ comp, adv shared.ID }

// markRunning sets Running=true on any vulnerable component whose package appears to be executing on one of
// the asset's hosts. The running side is HOST-scoped (technical-asset memberships are fleet-asset ids), so
// it gathers the running exec names across those hosts and matches them, case-insensitively, against each
// vulnerable component's package name (resolved via the engagement's component inventory). Matching is
// deliberately CONSERVATIVE — exact basename/comm == name/package, no substring — because Running scores
// strictly higher than installed, so a false match would over-report risk; low recall (installed when
// really running) is the safe failure mode, and exposureuc already notes the reduced precision.
func (r *Reader) markRunning(ctx context.Context, tenant shared.ID, hosts []asset.ComponentMembership, engs []*engagement.Engagement, byKey map[componentKey]exposureuc.AssetVulnerableComponent) error {
	running, err := r.runningExecNames(ctx, hosts)
	if err != nil {
		return err
	}
	if len(running) == 0 {
		return nil // nothing observed running on any host — every component stays installed-only
	}
	names, err := r.componentPackageNames(ctx, tenant, engs)
	if err != nil {
		return err
	}
	for k, comp := range byKey {
		for _, n := range names[comp.ComponentID] {
			if running[n] {
				comp.Running = true
				byKey[k] = comp
				break
			}
		}
	}
	return nil
}

// runningExecNames gathers the lowercased exec basenames + comms of every running process across the
// asset's host (technical) assets.
func (r *Reader) runningExecNames(ctx context.Context, hosts []asset.ComponentMembership) (map[string]bool, error) {
	names := make(map[string]bool)
	for _, h := range hosts {
		procs, err := r.processes.ListRunningByAsset(ctx, h.ComponentID) // ComponentID here is the host/fleet asset id
		if err != nil {
			return nil, fmt.Errorf("list running processes for host %s: %w", h.ComponentID, err)
		}
		for _, p := range procs {
			if p.Path != "" {
				names[strings.ToLower(path.Base(p.Path))] = true
			}
			if p.Comm != "" {
				names[strings.ToLower(p.Comm)] = true
			}
		}
	}
	return names, nil
}

// componentPackageNames maps each component id (across the asset's engagements) to its lowercased match
// candidates (name + package).
func (r *Reader) componentPackageNames(ctx context.Context, tenant shared.ID, engs []*engagement.Engagement) (map[shared.ID][]string, error) {
	out := make(map[shared.ID][]string)
	for _, eng := range engs {
		if eng == nil {
			continue
		}
		recs, err := r.components.ListCurrentComponentsByEngagement(ctx, tenant, eng.ID)
		if err != nil {
			return nil, fmt.Errorf("list components for engagement %s: %w", eng.ID, err)
		}
		for _, rec := range recs {
			var cands []string
			if rec.Name != "" {
				cands = append(cands, strings.ToLower(rec.Name))
			}
			if rec.Package != "" && !strings.EqualFold(rec.Package, rec.Name) {
				cands = append(cands, strings.ToLower(rec.Package))
			}
			if len(cands) > 0 {
				out[rec.ComponentID] = cands
			}
		}
	}
	return out, nil
}

// riskWorse reports whether exposure a represents a strictly higher risk than b, by a deterministic total
// order over the risk-relevant fields: KEV (known-exploited) beats non-KEV; then a lower Priority number
// (1 = most urgent); then a higher severity rank. Used to keep the worst of two occurrences for the same
// (component, advisory) so the exposure factor is never under-reported and the choice is order-independent.
func riskWorse(a, b exposureuc.AssetVulnerableComponent) bool {
	if a.KEV != b.KEV {
		return a.KEV
	}
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return shared.SeverityRank(a.Severity) > shared.SeverityRank(b.Severity)
}
