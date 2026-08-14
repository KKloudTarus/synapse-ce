// Package riskstoryuc is the read-model assembler for the unified per-asset risk story (issue #427). It
// correlates records ALREADY produced by the other pillars — the asset inventory (#431), the findings of
// every engine, the reachability verdicts (judgments), the attack-path graph (#419), the runtime
// detections (#423), and the continuous vulnerability occurrences/assessments (#514) — into one story per
// asset. It creates no data and persists no new table; every element it emits references the backing
// record it came from, and the pure domain (internal/domain/riskstory) enforces that honesty invariant
// and the deterministic ordering. There is NO LLM in this path.
package riskstoryuc

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskstory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// The reader interfaces are the NARROW read surface this assembler needs — consumer-defined so the
// service is testable with small fakes and depends only on "somewhere to read X", not on the concrete
// stores. The composition root wires the tenant-scoped repositories (which satisfy the broader ports)
// into these. Every read is tenant-scoped by the implementation via the existing chokepoint.
type (
	// AssetReader lists the tenant's assets and their typed edges.
	AssetReader interface {
		ListAssets(ctx context.Context, tenantID shared.ID) ([]*asset.Asset, error)
		ListEdges(ctx context.Context, tenantID shared.ID) ([]*asset.Edge, error)
	}
	// FindingReader lists an engagement's findings (internal processing surface; the story is not the
	// report path, so ListByEngagement is correct here).
	FindingReader interface {
		ListByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error)
	}
	// BindingReader lists the tenant's producer-owned asset↔finding attributions (#419). Attribution is
	// explicit; the assembler never derives an asset from finding prose.
	BindingReader interface {
		ListBindings(ctx context.Context, tenantID shared.ID) ([]attackpath.Binding, error)
	}
	// JudgmentReader lists an engagement's judgments; the assembler reads only confirmed reachability
	// verdicts from them.
	JudgmentReader interface {
		ListByEngagement(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
	}
	// DetectionReader lists an engagement's runtime detection ledger rows (#423).
	DetectionReader interface {
		ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error)
	}
)

// Service assembles risk stories. StaleAfter is the freshness target an element is measured against
// (consistent with the fleet-coverage rules, #413); a non-positive target means "no freshness
// requirement". now is injected so assembly is testable and deterministic.
type Service struct {
	assets     AssetReader
	findings   FindingReader
	bindings   BindingReader
	judgments  JudgmentReader
	detections DetectionReader
	staleAfter time.Duration
	now        func() time.Time
}

// NewService validates dependencies and returns the assembler. A nil clock defaults to time.Now.
func NewService(assets AssetReader, findings FindingReader, bindings BindingReader, judgments JudgmentReader, detections DetectionReader, staleAfter time.Duration, now func() time.Time) (*Service, error) {
	if assets == nil || findings == nil || bindings == nil || judgments == nil || detections == nil {
		return nil, fmt.Errorf("%w: risk story read dependencies are required", shared.ErrValidation)
	}
	if now == nil {
		now = time.Now
	}
	return &Service{assets: assets, findings: findings, bindings: bindings, judgments: judgments, detections: detections, staleAfter: staleAfter, now: now}, nil
}

// StoriesForEngagement assembles one story per asset that has at least one correlated signal in the
// engagement (a bound finding, a runtime detection, an exposure, or an attack-path edge). Stories are
// returned ordered by asset id for a diffable result. The tenant is derived from ctx and never crossed.
func (s *Service) StoriesForEngagement(ctx context.Context, engagementID shared.ID) ([]riskstory.Story, error) {
	tenantID, err := tenantIDFrom(ctx)
	if err != nil {
		return nil, err
	}
	if engagementID.IsZero() {
		return nil, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}

	c, err := s.load(ctx, tenantID, engagementID)
	if err != nil {
		return nil, err
	}

	stories := make([]riskstory.Story, 0, len(c.assets))
	for _, a := range c.assets {
		if a == nil {
			continue
		}
		story, ok, err := s.assembleAsset(tenantID, a, c)
		if err != nil {
			return nil, err
		}
		if ok {
			stories = append(stories, story)
		}
	}
	// Order by asset id so repeated runs over the same records produce the same slice.
	sortStoriesByAsset(stories)
	return stories, nil
}

// StoryForAsset assembles the single story for one asset, or shared.ErrNotFound when the asset has no
// correlated signal in the engagement.
func (s *Service) StoryForAsset(ctx context.Context, engagementID, assetID shared.ID) (riskstory.Story, error) {
	tenantID, err := tenantIDFrom(ctx)
	if err != nil {
		return riskstory.Story{}, err
	}
	if engagementID.IsZero() || assetID.IsZero() {
		return riskstory.Story{}, fmt.Errorf("%w: engagement id and asset id are required", shared.ErrValidation)
	}
	c, err := s.load(ctx, tenantID, engagementID)
	if err != nil {
		return riskstory.Story{}, err
	}
	a, ok := c.assetByID[assetID]
	if !ok {
		return riskstory.Story{}, fmt.Errorf("%w: asset %s", shared.ErrNotFound, assetID)
	}
	story, has, err := s.assembleAsset(tenantID, a, c)
	if err != nil {
		return riskstory.Story{}, err
	}
	if !has {
		return riskstory.Story{}, fmt.Errorf("%w: no risk story for asset %s", shared.ErrNotFound, assetID)
	}
	return story, nil
}

// correlated is the per-engagement working set, loaded once and indexed by asset identity.
type correlated struct {
	assets      []*asset.Asset
	assetByID   map[shared.ID]*asset.Asset
	findingByID map[shared.ID]finding.Finding
	reachBySubj map[shared.ID]reachVerdict // confirmed reachability verdict per finding
	bindByAsset map[shared.ID][]attackpath.Binding
	detsByAsset map[shared.ID][]detection.Record
	exposeTo    map[shared.ID][]*asset.Edge // exposure edges pointing at the asset
	reachEdges  map[shared.ID][]*asset.Edge // reachability edges touching the asset
}

type reachVerdict struct {
	claim      judgment.ReachabilityClaim // the full claim, so Supersedes compares the real proof tier
	judgmentID shared.ID
}

func (s *Service) load(ctx context.Context, tenantID, engagementID shared.ID) (*correlated, error) {
	assets, err := s.assets.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	edges, err := s.assets.ListEdges(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list edges: %w", err)
	}
	findings, err := s.findings.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	bindings, err := s.bindings.ListBindings(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	judgments, err := s.judgments.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list judgments: %w", err)
	}
	dets, err := s.detections.ListDetections(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list detections: %w", err)
	}

	c := &correlated{
		assets:      assets,
		assetByID:   make(map[shared.ID]*asset.Asset, len(assets)),
		findingByID: make(map[shared.ID]finding.Finding, len(findings)),
		reachBySubj: map[shared.ID]reachVerdict{},
		bindByAsset: map[shared.ID][]attackpath.Binding{},
		detsByAsset: map[shared.ID][]detection.Record{},
		exposeTo:    map[shared.ID][]*asset.Edge{},
		reachEdges:  map[shared.ID][]*asset.Edge{},
	}
	for _, a := range assets {
		if a != nil {
			c.assetByID[a.ID] = a
		}
	}
	for _, f := range findings {
		c.findingByID[f.ID] = f
	}
	// Only this engagement's bindings, and only for findings we actually loaded (tenant + engagement
	// scoped both ways).
	for _, b := range bindings {
		if b.EngagementID != engagementID {
			continue
		}
		if _, ok := c.findingByID[b.FindingID]; !ok {
			continue
		}
		c.bindByAsset[b.AssetID] = append(c.bindByAsset[b.AssetID], b)
	}
	for _, d := range dets {
		if d.AssetID.IsZero() {
			continue
		}
		c.detsByAsset[d.AssetID] = append(c.detsByAsset[d.AssetID], d)
	}
	for _, e := range edges {
		if e == nil {
			continue
		}
		switch e.Kind {
		case asset.EdgeExposes:
			c.exposeTo[e.To] = append(c.exposeTo[e.To], e)
		case asset.EdgeReaches:
			// A reachability edge is a path element on both endpoints. A self-edge (From==To) touches one
			// asset once, not twice.
			c.reachEdges[e.From] = append(c.reachEdges[e.From], e)
			if e.To != e.From {
				c.reachEdges[e.To] = append(c.reachEdges[e.To], e)
			}
		}
	}
	// Reachability verdicts: only CONFIRMED reachability judgments. A STRICTLY stronger proof tier wins
	// (Supersedes on the full typed claim, per ADR-0024 — a deterministic Tier-2 call-graph result
	// overrides a weaker LLM tier); equal-or-lower tiers leave the stored verdict standing, so the first
	// confirmed verdict at the strongest tier wins over the store's deterministic ordering.
	for _, j := range judgments {
		if j.Capability != judgment.CapReachability || j.State != judgment.StateConfirmed {
			continue
		}
		rc, ok := j.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		cur, seen := c.reachBySubj[j.SubjectID]
		if !seen || rc.Supersedes(cur.claim) {
			c.reachBySubj[j.SubjectID] = reachVerdict{claim: rc, judgmentID: j.ID}
		}
	}
	return c, nil
}

// assembleAsset builds the Inputs for one asset and hands them to the pure domain assembler. It returns
// ok=false when the asset has no correlated signal at all (so it is not surfaced as an empty story).
// tenantID is the authenticated principal's tenant; an asset whose own tenant disagrees is skipped as a
// defensive guard against a mis-scoped store (the reads are already tenant-scoped).
func (s *Service) assembleAsset(tenantID shared.ID, a *asset.Asset, c *correlated) (riskstory.Story, bool, error) {
	if a.TenantID != tenantID {
		return riskstory.Story{}, false, nil
	}
	now := s.now().UTC()

	// Asset-level runtime signal: the finding's asset has been seen under active attack when it carries a
	// FRESH runtime detection. This corroborates every finding on the asset (the asset is under attack),
	// without over-claiming that a specific CVE was exploited — the detections also appear as their own
	// traceable elements.
	seenUnderAttack := s.assetUnderActiveAttack(a, c, now)

	exposure := s.exposureElements(a, c)
	findings := s.findingElements(a, c, now, seenUnderAttack)
	paths := s.pathElements(a, c)
	detections := s.detectionElements(a, c, now)

	if len(exposure) == 0 && len(findings) == 0 && len(paths) == 0 && len(detections) == 0 {
		return riskstory.Story{}, false, nil
	}

	story, err := riskstory.Assemble(riskstory.Inputs{
		AssetID:  a.ID,
		TenantID: tenantID,
		Identity: riskstory.AssetFacts{
			Kind:       string(a.Kind),
			Key:        a.Key,
			Name:       a.Name,
			Provenance: riskstory.Provenance{Kind: riskstory.ProvAsset, ID: a.ID},
		},
		Exposure:    exposure,
		Findings:    findings,
		Paths:       paths,
		Detections:  detections,
		GeneratedAt: now,
	})
	if err != nil {
		return riskstory.Story{}, false, fmt.Errorf("assemble story for asset %s: %w", a.ID, err)
	}
	return story, true, nil
}

func (s *Service) exposureElements(a *asset.Asset, c *correlated) []riskstory.ExposureElement {
	var out []riskstory.ExposureElement
	for _, e := range c.exposeTo[a.ID] {
		el := riskstory.ExposureElement{
			Description: fmt.Sprintf("exposed by %s", e.From),
			Confidence:  string(e.Confidence),
			Provenance:  riskstory.Provenance{Kind: riskstory.ProvAssetEdge, ID: e.Provenance},
		}
		if e.Confidence == asset.EdgeInferred {
			el.Qualifiers = append(el.Qualifiers, riskstory.QualInferredEdge)
		}
		out = append(out, el)
	}
	return out
}

func (s *Service) findingElements(a *asset.Asset, c *correlated, now time.Time, seenUnderAttack bool) []riskstory.FindingElement {
	var out []riskstory.FindingElement
	for _, b := range c.bindByAsset[a.ID] {
		f, ok := c.findingByID[b.FindingID]
		if !ok {
			continue
		}
		el := riskstory.FindingElement{
			FindingID:  f.ID,
			Title:      f.Title,
			Severity:   string(f.Severity),
			Priority:   f.Priority,
			RiskScore:  f.RiskScore,
			KEV:        f.KEV,
			Provenance: riskstory.Provenance{Kind: riskstory.ProvFinding, ID: f.ID},
			// A finding attributed via an attack-path binding IS on an attack path. An inferred binding
			// is carried as an inferred-edge qualifier rather than silently upgraded to certainty.
			OnAttackPath: true,
			// Asset-level runtime corroboration: the finding's asset carries a fresh detection.
			SeenUnderAttack: seenUnderAttack,
		}
		if b.Confidence == asset.EdgeInferred {
			el.Qualifiers = append(el.Qualifiers, riskstory.QualInferredEdge)
		}
		if b.Provenance != "" {
			el.Evidence = append(el.Evidence, riskstory.Provenance{Kind: riskstory.ProvAttackPath, ID: b.Provenance})
		}

		// Reachability verdict (a strictly stronger proof tier supersedes; here we only read a confirmed
		// verdict). Unknown is carried as a qualifier, never flattened to reachable/not-reachable.
		if v, has := c.reachBySubj[f.ID]; has {
			el.Reachability = string(v.claim.Reachable)
			el.Reachable = v.claim.Reachable == judgment.Reachable
			if v.claim.Reachable == judgment.ReachUnknown {
				el.Qualifiers = append(el.Qualifiers, riskstory.QualReachabilityUnknown)
			}
			if v.judgmentID != "" {
				el.Evidence = append(el.Evidence, riskstory.Provenance{Kind: riskstory.ProvReachability, ID: v.judgmentID})
			}
		} else if f.Reachability != "" {
			// Fall back to the finding's own recorded reachability label when no judgment is present.
			el.Reachability = f.Reachability
			el.Reachable = f.Reachability == string(judgment.Reachable)
			if f.Reachability == string(judgment.ReachUnknown) {
				el.Qualifiers = append(el.Qualifiers, riskstory.QualReachabilityUnknown)
			}
		}

		// The continuous vulnerability occurrence + immutable assessment (#514) are backing records for
		// the finding's vulnerability state; reference them so the story is navigable to that evidence.
		if !f.OccurrenceID.IsZero() {
			el.Evidence = append(el.Evidence, riskstory.Provenance{Kind: riskstory.ProvOccurrence, ID: f.OccurrenceID})
		}
		if !f.RiskAssessmentID.IsZero() {
			el.Evidence = append(el.Evidence, riskstory.Provenance{Kind: riskstory.ProvAssessment, ID: f.RiskAssessmentID})
		}

		el.LastObserved = findingObservedAt(f)
		if !riskstory.Fresh(el.LastObserved, now, s.staleAfter) {
			el.Stale = true
			el.Qualifiers = append(el.Qualifiers, riskstory.QualStale)
		}
		out = append(out, el)
	}
	return out
}

func (s *Service) pathElements(a *asset.Asset, c *correlated) []riskstory.PathElement {
	var out []riskstory.PathElement
	for _, e := range c.reachEdges[a.ID] {
		el := riskstory.PathElement{
			Summary:    fmt.Sprintf("%s reaches %s", e.From, e.To),
			Confidence: string(e.Confidence),
			Provenance: riskstory.Provenance{Kind: riskstory.ProvAttackPath, ID: e.Provenance},
		}
		if e.Confidence == asset.EdgeInferred {
			el.Qualifiers = append(el.Qualifiers, riskstory.QualInferredEdge)
		}
		out = append(out, el)
	}
	return out
}

func (s *Service) detectionElements(a *asset.Asset, c *correlated, now time.Time) []riskstory.DetectionElement {
	var out []riskstory.DetectionElement
	for _, d := range c.detsByAsset[a.ID] {
		el := riskstory.DetectionElement{
			RuleID:     d.Detection.RuleID,
			Severity:   string(d.Detection.Severity),
			Observed:   d.Detection.Observed,
			Provenance: riskstory.Provenance{Kind: riskstory.ProvDetection, ID: d.ID},
		}
		if !riskstory.Fresh(d.Detection.Observed, now, s.staleAfter) {
			el.Stale = true
			el.Qualifiers = append(el.Qualifiers, riskstory.QualStale)
		}
		out = append(out, el)
	}
	return out
}

// assetUnderActiveAttack reports whether the asset carries at least one FRESH runtime detection — the
// honest, asset-level "seen under attack" signal. A stale detection is a past event, not current
// attack, so it does not corroborate.
func (s *Service) assetUnderActiveAttack(a *asset.Asset, c *correlated, now time.Time) bool {
	for _, d := range c.detsByAsset[a.ID] {
		if riskstory.Fresh(d.Detection.Observed, now, s.staleAfter) {
			return true
		}
	}
	return false
}

// findingObservedAt is when the finding's risk state was last evaluated, falling back to its last audit
// update so a stale finding is measurable even before the first re-evaluation.
func findingObservedAt(f finding.Finding) time.Time {
	if f.EvaluatedAt != nil && !f.EvaluatedAt.IsZero() {
		return *f.EvaluatedAt
	}
	if !f.Audit.UpdatedAt.IsZero() {
		return f.Audit.UpdatedAt
	}
	return f.Audit.CreatedAt
}

func sortStoriesByAsset(stories []riskstory.Story) {
	sort.Slice(stories, func(i, j int) bool { return stories[i].AssetID < stories[j].AssetID })
}

func tenantIDFrom(ctx context.Context) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return "", fmt.Errorf("%w: tenant is required in context", shared.ErrValidation)
	}
	return tenantID, nil
}
