// Package exposurereader adapts the shipped SCA stores (asset↔component membership, vulnerability
// occurrences, and per-occurrence risk assessments) into the exposureuc.AssetVulnerabilityReader port —
// the missing join that lets the X5 Exposure producer read an asset's open vulnerable components with their
// evaluated Priority/KEV/Severity. It reuses the already-evaluated risk (vulnerabilityrisk.Assessment); it
// recomputes nothing. Every read is tenant-scoped from ctx. Running presence is not yet available (the B5
// per-asset process-entity snapshot store is deferred), so it reports installed-only — the producer notes
// the reduced running-vs-installed precision.
package exposurereader

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
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

// MembershipReader is the asset-side view: which engagements an asset belongs to and which components make
// it up. ports.BusinessAssetRepository satisfies it. (Occurrences carry no AssetID, so the component
// membership is the bridge from an asset to its vulnerabilities.)
type MembershipReader interface {
	ListEngagementsByBusinessAsset(ctx context.Context, tenantID, assetID shared.ID) ([]*engagement.Engagement, error)
	ListBusinessAssetProjects(ctx context.Context, tenantID, assetID shared.ID) ([]asset.ComponentMembership, error)
	ListBusinessAssetTechnicalAssets(ctx context.Context, tenantID, assetID shared.ID) ([]asset.ComponentMembership, error)
}

// OccurrenceReader lists an engagement's vulnerability occurrences by state. ports.VulnerabilityOccurrenceStore satisfies it.
type OccurrenceReader interface {
	ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID, states []vulnerabilityoccurrence.State) ([]vulnerabilityoccurrence.Occurrence, error)
}

// RiskReader returns the current risk evaluation for one occurrence. ports.VulnerabilityRiskAssessmentStore satisfies it.
type RiskReader interface {
	Current(ctx context.Context, tenantID, occurrenceID shared.ID) (vulnerabilityrisk.Assessment, error)
}

// Reader implements exposureuc.AssetVulnerabilityReader over the SCA stores.
type Reader struct {
	memberships MembershipReader
	occurrences OccurrenceReader
	risk        RiskReader
}

var _ exposureuc.AssetVulnerabilityReader = (*Reader)(nil)

// NewReader constructs the adapter. All three stores are required.
func NewReader(memberships MembershipReader, occurrences OccurrenceReader, risk RiskReader) (*Reader, error) {
	switch {
	case memberships == nil:
		return nil, fmt.Errorf("%w: exposure reader requires a membership store", shared.ErrValidation)
	case occurrences == nil:
		return nil, fmt.Errorf("%w: exposure reader requires an occurrence store", shared.ErrValidation)
	case risk == nil:
		return nil, fmt.Errorf("%w: exposure reader requires a risk store", shared.ErrValidation)
	}
	return &Reader{memberships: memberships, occurrences: occurrences, risk: risk}, nil
}

func tenantIDFrom(ctx context.Context) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return "", fmt.Errorf("%w: tenant is required in context", shared.ErrValidation)
	}
	return tenantID, nil
}

// ListAssetVulnerableComponents resolves, for one asset: the engagements it is scoped into, the components
// that make it up, and the currently-open vulnerability occurrences on those components (with their
// evaluated risk). It ABSTAINS with shared.ErrNotFound when the asset has no exposure data to assess (not
// in any engagement, or no component inventory) — never reporting absence as clean. An asset that IS
// scanned but has no open occurrences returns (nil, nil) = a trustworthy clean. Presence is installed-only
// (B5 running snapshots deferred).
func (r *Reader) ListAssetVulnerableComponents(ctx context.Context, assetID shared.ID) ([]exposureuc.AssetVulnerableComponent, error) {
	tenant, err := tenantIDFrom(ctx)
	if err != nil {
		return nil, err
	}
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: asset id is required", shared.ErrValidation)
	}

	engs, err := r.memberships.ListEngagementsByBusinessAsset(ctx, tenant, assetID)
	if err != nil {
		return nil, fmt.Errorf("list engagements for asset %s: %w", assetID, err) // ErrNotFound → abstain
	}
	if len(engs) == 0 {
		return nil, fmt.Errorf("%w: asset %s is not scoped into any engagement", shared.ErrNotFound, assetID)
	}

	components, err := r.componentSet(ctx, tenant, assetID)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("%w: asset %s has no component inventory", shared.ErrNotFound, assetID)
	}

	// Dedup by (component, advisory): the same vulnerable component can appear under more than one of the
	// asset's engagements, each with its own (possibly divergent) risk evaluation. Keep the WORST — the
	// exposure factor must never be under-reported — via a deterministic risk order (not first-seen, which
	// would depend on engagement iteration order).
	type key struct{ comp, adv shared.ID }
	byKey := make(map[key]exposureuc.AssetVulnerableComponent)
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
			if _, ok := components[occ.ComponentID]; !ok {
				continue
			}
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
			k := key{comp: cand.ComponentID, adv: cand.AdvisoryID}
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

// componentSet unions the asset's project and technical-asset component memberships into a lookup set.
func (r *Reader) componentSet(ctx context.Context, tenant, assetID shared.ID) (map[shared.ID]struct{}, error) {
	set := make(map[shared.ID]struct{})
	projects, err := r.memberships.ListBusinessAssetProjects(ctx, tenant, assetID)
	if err != nil {
		return nil, fmt.Errorf("list project components for asset %s: %w", assetID, err)
	}
	technical, err := r.memberships.ListBusinessAssetTechnicalAssets(ctx, tenant, assetID)
	if err != nil {
		return nil, fmt.Errorf("list technical components for asset %s: %w", assetID, err)
	}
	for _, m := range projects {
		set[m.ComponentID] = struct{}{}
	}
	for _, m := range technical {
		set[m.ComponentID] = struct{}{}
	}
	return set, nil
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
