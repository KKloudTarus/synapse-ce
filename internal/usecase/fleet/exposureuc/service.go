// Package exposureuc is the Phase-C/X5 (#634) producer of the coverage-honest RiskContext.Exposure factor:
// it reads an asset's currently-open vulnerable components (with their already-evaluated vulnerabilityrisk
// Priority/KEV and running/installed presence), fuses them via the pure-domain exposure.Fuse, and returns
// an abstain-capable Assessment for the tri-score risk assembler to place into RiskContext.Exposure. It is
// the twin of baselineuc (the Behavior producer): it produces a FACTOR, never a verdict, never sets Risk
// or a disposition, never touches the Confidence axis, and ABSTAINS (lowers Coverage, not Risk) when an
// asset has no inventory/exposure data. It REUSES the shipped continuous-exposure evaluation — it does not
// recompute KEV/EPSS/CVSS.
package exposureuc

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/exposure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AssetVulnerableComponent is one open (component × advisory) exposure on an asset, carrying the
// already-evaluated risk (Priority 1-highest..5-background + KEV, from vulnerabilityrisk) and whether the
// component was observed RUNNING. Running is false (installed-only) until per-asset process-entity
// snapshots are persisted (the deferred B5 tail); the fusion still ranks it correctly, and the producer
// notes the reduced running-vs-installed precision as a coverage reason.
type AssetVulnerableComponent struct {
	ComponentID shared.ID
	AdvisoryID  shared.ID
	Severity    shared.Severity
	Priority    int
	KEV         bool
	Running     bool
}

// AssetVulnerabilityReader is the consumer-side view this producer needs: the currently-open vulnerable
// components for one asset. A nil slice with a nil error means "inventory scanned, no open vulnerabilities"
// (scored as a real 0 exposure); shared.ErrNotFound means "no inventory/exposure data for this asset" —
// the producer ABSTAINS rather than reading absence as clean. An adapter implements this over the shipped
// occurrence/risk stores joined to the asset via component membership.
//
// CONTRACT: the implementing adapter MUST scope the query by the tenant derived from ctx
// (shared.TenantFrom) — the asset id alone is not a tenant boundary, and returning another tenant's
// components here would leak them into that tenant's risk score.
type AssetVulnerabilityReader interface {
	ListAssetVulnerableComponents(ctx context.Context, assetID shared.ID) ([]AssetVulnerableComponent, error)
}

// Assessment is the coverage-honest Exposure factor for one asset. Exposure is 0 whenever Scoreable is
// false; the assembler places Exposure into RiskContext.Exposure ONLY when Scoreable, and otherwise
// reflects the gap in Coverage (never in Risk).
type Assessment struct {
	Exposure  riskassessment.Score
	Scoreable bool
	Reasons   []string
}

// Service produces the Exposure factor for an asset.
type Service struct {
	reader AssetVulnerabilityReader
}

// NewService constructs the exposure producer.
func NewService(reader AssetVulnerabilityReader) (*Service, error) {
	if reader == nil {
		return nil, fmt.Errorf("%w: exposure service requires a vulnerability reader", shared.ErrValidation)
	}
	return &Service{reader: reader}, nil
}

// Assess computes the RiskContext.Exposure factor for one asset. It abstains (Scoreable=false, Exposure=0)
// when the asset has no inventory/exposure data; scores a real 0 when inventory is present but clean; and
// otherwise fuses the open exposures. When no vulnerable component was observed running (runtime telemetry
// absent), it still scores the installed exposures but records that running-vs-installed precision is
// limited — an honest coverage note, never a Risk discount.
func (s *Service) Assess(ctx context.Context, assetID shared.ID) (Assessment, error) {
	if assetID.IsZero() {
		return Assessment{}, fmt.Errorf("%w: asset id is required", shared.ErrValidation)
	}
	comps, err := s.reader.ListAssetVulnerableComponents(ctx, assetID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return Assessment{Scoreable: false, Reasons: []string{"no inventory/exposure data for asset — abstaining"}}, nil
		}
		return Assessment{}, err
	}
	if len(comps) == 0 {
		// Inventory present, nothing open: a genuine, trustworthy zero exposure.
		return Assessment{Exposure: 0, Scoreable: true}, nil
	}
	exposures := make([]exposure.ComponentExposure, 0, len(comps))
	anyRunning := false
	for _, c := range comps {
		presence := exposure.PresenceInstalled
		if c.Running {
			presence = exposure.PresenceRunning
			anyRunning = true
		}
		exposures = append(exposures, exposure.ComponentExposure{
			ComponentID: c.ComponentID,
			AdvisoryID:  c.AdvisoryID,
			Severity:    c.Severity,
			Priority:    c.Priority,
			KEV:         c.KEV,
			Presence:    presence,
		})
	}
	score, err := exposure.Fuse(exposures)
	if err != nil {
		return Assessment{}, err
	}
	a := Assessment{Exposure: score, Scoreable: true}
	if !anyRunning {
		a.Reasons = append(a.Reasons, "running-vs-installed precision limited: no runtime process telemetry for asset (exposures scored as installed)")
	}
	return a, nil
}
