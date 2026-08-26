package businessassetuc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	repo      ports.BusinessAssetRepository
	findings  ports.FindingRepository
	imported  ports.ImportedFindingStore
	judgments ports.JudgmentStore
	retests   ports.RetestRepository
	audit     ports.AuditLogger
	clock     ports.Clock
	ids       ports.IDGenerator
}

func NewService(repo ports.BusinessAssetRepository, findings ports.FindingRepository, imported ports.ImportedFindingStore, judgments ports.JudgmentStore, retests ports.RetestRepository, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if repo == nil || findings == nil || imported == nil || judgments == nil || retests == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: business asset service dependencies are required", shared.ErrValidation)
	}
	return &Service{repo: repo, findings: findings, imported: imported, judgments: judgments, retests: retests, audit: audit, clock: clock, ids: ids}, nil
}

type CreateInput struct {
	TenantID               shared.ID
	Key, Name, Description string
	Type                   asset.BusinessAssetType
	Criticality            asset.Criticality
	Owner                  string
	Metadata               map[string]string
	Actor                  string
}

func (s *Service) Create(ctx context.Context, in CreateInput) (*asset.BusinessAsset, error) {
	in.TenantID = shared.TenantOrDefault(in.TenantID)
	if _, err := s.repo.GetBusinessAssetByKey(ctx, in.TenantID, strings.TrimSpace(in.Key)); err == nil {
		return nil, fmt.Errorf("%w: business asset key already exists", shared.ErrConflict)
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, err
	}
	a, err := asset.NewBusinessAsset(s.ids.NewID(), in.TenantID, in.Key, in.Name, in.Description, in.Type, in.Criticality, in.Owner, in.Metadata, in.Actor, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateBusinessAsset(ctx, a); err != nil {
		return nil, fmt.Errorf("create business asset: %w", err)
	}
	if err := s.record(ctx, in.Actor, "business_asset.created", a.ID); err != nil {
		return nil, err
	}
	return a, nil
}

type UpdateInput struct {
	Name, Description string
	Type              asset.BusinessAssetType
	Criticality       asset.Criticality
	Owner             string
	Metadata          map[string]string
	Lifecycle         asset.BusinessAssetLifecycle
	Version           int
	Actor             string
}

func (s *Service) resolveAsset(ctx context.Context, tenantID, idOrKey shared.ID) (*asset.BusinessAsset, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	a, err := s.repo.GetBusinessAssetByID(ctx, tenantID, idOrKey)
	if err == nil {
		return a, nil
	}
	if errors.Is(err, shared.ErrNotFound) {
		return s.repo.GetBusinessAssetByKey(ctx, tenantID, idOrKey.String())
	}
	return nil, err
}

func (s *Service) Update(ctx context.Context, tenantID, id shared.ID, in UpdateInput) (*asset.BusinessAsset, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	a, err := s.resolveAsset(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	cp := *a
	cp.Metadata = clone(a.Metadata)
	if err := cp.Update(in.Name, in.Description, in.Type, in.Criticality, in.Owner, in.Metadata, in.Version, in.Actor, s.clock.Now()); err != nil {
		return nil, err
	}
	if in.Lifecycle != "" && in.Lifecycle != cp.Lifecycle {
		if err := cp.Transition(in.Lifecycle, cp.Version, in.Actor, s.clock.Now()); err != nil {
			return nil, err
		}
	}
	if err := s.repo.UpdateBusinessAsset(ctx, &cp, in.Version); err != nil {
		return nil, err
	}
	if err := s.record(ctx, in.Actor, "business_asset.updated", cp.ID); err != nil {
		return nil, err
	}
	return &cp, nil
}

func (s *Service) Get(ctx context.Context, tenantID, id shared.ID) (*asset.BusinessAsset, error) {
	return s.resolveAsset(ctx, tenantID, id)
}

type Filter struct {
	Query       string
	Type        asset.BusinessAssetType
	Criticality asset.Criticality
	Lifecycle   asset.BusinessAssetLifecycle
	Owner       string
}

func (s *Service) List(ctx context.Context, tenantID shared.ID, filter Filter) ([]*asset.BusinessAsset, error) {
	all, err := s.repo.ListBusinessAssets(ctx, shared.TenantOrDefault(tenantID))
	if err != nil {
		return nil, err
	}
	query, owner := strings.ToLower(strings.TrimSpace(filter.Query)), strings.ToLower(strings.TrimSpace(filter.Owner))
	out := make([]*asset.BusinessAsset, 0, len(all))
	for _, a := range all {
		if query != "" && !strings.Contains(strings.ToLower(a.Key+" "+a.Name), query) {
			continue
		}
		if filter.Type != "" && a.Type != filter.Type || filter.Criticality != "" && a.Criticality != filter.Criticality || filter.Lifecycle != "" && a.Lifecycle != filter.Lifecycle {
			continue
		}
		if owner != "" && !strings.Contains(strings.ToLower(a.Owner), owner) {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (s *Service) ReplaceProjects(ctx context.Context, tenantID, id shared.ID, links []asset.ComponentMembership, actor string) error {
	return s.replace(ctx, tenantID, id, links, actor, true)
}
func (s *Service) ReplaceTechnicalAssets(ctx context.Context, tenantID, id shared.ID, links []asset.ComponentMembership, actor string) error {
	return s.replace(ctx, tenantID, id, links, actor, false)
}
func (s *Service) replace(ctx context.Context, tenantID, id shared.ID, links []asset.ComponentMembership, actor string, projects bool) error {
	tenantID = shared.TenantOrDefault(tenantID)
	a, err := s.resolveAsset(ctx, tenantID, id)
	if err != nil {
		return err
	}
	id = a.ID
	if !a.AcceptsAssignments() {
		return fmt.Errorf("%w: retired business asset is read-only", shared.ErrValidation)
	}
	for i := range links {
		links[i].TenantID, links[i].AssetID = tenantID, id
		if err := links[i].Validate(); err != nil {
			return err
		}
	}
	if projects {
		err = s.repo.ReplaceBusinessAssetProjects(ctx, tenantID, id, links)
	} else {
		err = s.repo.ReplaceBusinessAssetTechnicalAssets(ctx, tenantID, id, links)
	}
	if err != nil {
		return err
	}
	return s.record(ctx, actor, "business_asset.membership_replaced", id)
}

func (s *Service) Projects(ctx context.Context, tenantID, id shared.ID) ([]asset.ComponentMembership, error) {
	a, err := s.resolveAsset(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return s.repo.ListBusinessAssetProjects(ctx, a.TenantID, a.ID)
}
func (s *Service) TechnicalAssets(ctx context.Context, tenantID, id shared.ID) ([]asset.ComponentMembership, error) {
	a, err := s.resolveAsset(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return s.repo.ListBusinessAssetTechnicalAssets(ctx, a.TenantID, a.ID)
}

func (s *Service) AssignEngagement(ctx context.Context, tenantID, engagementID, assetID shared.ID, actor string) error {
	tenantID = shared.TenantOrDefault(tenantID)
	if !assetID.IsZero() {
		a, err := s.resolveAsset(ctx, tenantID, assetID)
		if err != nil {
			return err
		}
		assetID = a.ID
		if !a.AcceptsAssignments() {
			return fmt.Errorf("%w: retired business asset is read-only", shared.ErrValidation)
		}
	}
	if err := s.repo.AssignEngagementBusinessAsset(ctx, tenantID, engagementID, assetID); err != nil {
		return err
	}
	return s.record(ctx, actor, "engagement.business_asset_assigned", engagementID)
}

func (s *Service) Engagements(ctx context.Context, tenantID, id shared.ID) ([]*engagement.Engagement, error) {
	a, err := s.resolveAsset(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	tenantID = a.TenantID
	ctx = shared.WithTenant(ctx, tenantID)
	return s.repo.ListEngagementsByBusinessAsset(ctx, tenantID, a.ID)
}

type AggregatedFinding struct {
	Finding          finding.Finding                  `json:"finding"`
	ImportedFinding  *importedfinding.ImportedFinding `json:"imported_finding,omitempty"`
	External         bool                             `json:"external"`
	CanSelfPromote   *bool                            `json:"can_self_promote,omitempty"`
	SuppressedByTool bool                             `json:"suppressed_by_tool"`
	Provenance       *importedfinding.Provenance      `json:"provenance,omitempty"`
	Reachability     ReachabilityProjection           `json:"reachability"`
	EngagementID     shared.ID                        `json:"engagement_id"`
	EngagementName   string                           `json:"engagement_name"`
}

type ReachabilityEvidence struct {
	JudgmentID shared.ID                  `json:"judgment_id"`
	State      judgment.ReachabilityState `json:"state"`
	Tier       judgment.ReachabilityTier  `json:"tier"`
	Confidence int                        `json:"confidence"`
	Path       []string                   `json:"path,omitempty"`
	Status     judgment.State             `json:"status"`
	ObservedAt time.Time                  `json:"observed_at"`
}

type ReachabilityProjection struct {
	State      judgment.ReachabilityState `json:"state"`
	Tier       judgment.ReachabilityTier  `json:"tier"`
	Confidence int                        `json:"confidence"`
	Path       []string                   `json:"path,omitempty"`
	Status     judgment.State             `json:"status,omitempty"`
	Source     string                     `json:"source"`
	History    []ReachabilityEvidence     `json:"history"`
}

func (s *Service) Findings(ctx context.Context, tenantID, id shared.ID) ([]AggregatedFinding, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	ctx = shared.WithTenant(ctx, tenantID)
	engagements, err := s.Engagements(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	out := []AggregatedFinding{}
	for _, e := range engagements {
		rows, err := s.findings.ListByEngagement(ctx, e.ID)
		if err != nil {
			return nil, err
		}
		for _, f := range finding.Publishable(rows) {
			reachability, err := s.findingReachability(ctx, e.ID, f)
			if err != nil {
				return nil, err
			}
			f.Reachability = string(reachability.State)
			out = append(out, AggregatedFinding{Finding: f, Reachability: reachability, EngagementID: e.ID, EngagementName: e.Name})
		}
		imports, err := s.imported.ListByEngagement(ctx, tenantID, e.ID)
		if err != nil {
			return nil, err
		}
		for _, imported := range imports {
			importedCopy := imported
			provenance := imported.Provenance
			canSelfPromote := imported.CanSelfPromote()
			out = append(out, AggregatedFinding{
				Finding: finding.Finding{
					ID: imported.ID, EngagementID: imported.EngagementID, Title: imported.Title,
					Description: imported.Message, Severity: imported.Severity, Status: finding.StatusOpen,
					Class: finding.ClassThirdParty, Reachability: string(judgment.ReachUnknown), DedupKey: imported.Fingerprint,
				},
				ImportedFinding:  &importedCopy,
				External:         imported.External(),
				CanSelfPromote:   &canSelfPromote,
				SuppressedByTool: imported.Suppressed,
				Provenance:       &provenance,
				Reachability:     ReachabilityProjection{State: judgment.ReachUnknown, Tier: judgment.Tier0, Source: "external", History: []ReachabilityEvidence{}},
				EngagementID:     e.ID,
				EngagementName:   e.Name,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Finding, out[j].Finding
		if shared.SeverityRank(a.Severity) != shared.SeverityRank(b.Severity) {
			return shared.SeverityRank(a.Severity) > shared.SeverityRank(b.Severity)
		}
		return a.ID < b.ID
	})
	return out, nil
}

func (s *Service) findingReachability(ctx context.Context, engagementID shared.ID, f finding.Finding) (ReachabilityProjection, error) {
	projection := ReachabilityProjection{State: judgment.ReachUnknown, Tier: judgment.Tier0, Source: "none", History: []ReachabilityEvidence{}}
	switch judgment.ReachabilityState(f.Reachability) {
	case judgment.Reachable, judgment.NotReachable:
		projection.State = judgment.ReachabilityState(f.Reachability)
		projection.Source = "finding_metadata"
	}
	rows, err := s.judgments.ListBySubject(ctx, engagementID, f.ID)
	if err != nil {
		return ReachabilityProjection{}, err
	}
	var selected *ReachabilityEvidence
	var selectedClaim judgment.ReachabilityClaim
	for _, row := range rows {
		if row.Capability != judgment.CapReachability || row.SubjectKind != judgment.SubjectFinding {
			continue
		}
		claim, ok := row.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		evidence := ReachabilityEvidence{
			JudgmentID: row.ID, State: claim.Reachable, Tier: claim.Tier, Confidence: claim.Confidence,
			Path: append([]string(nil), claim.Path...), Status: row.State, ObservedAt: row.Audit.CreatedAt,
		}
		projection.History = append(projection.History, evidence)
		if selected == nil || claim.Supersedes(selectedClaim) {
			selectedCopy := evidence
			selected = &selectedCopy
			selectedClaim = claim
		}
	}
	if selected != nil {
		projection.State = selected.State
		projection.Tier = selected.Tier
		projection.Confidence = selected.Confidence
		projection.Path = append([]string(nil), selected.Path...)
		projection.Status = selected.Status
		projection.Source = "judgment"
	}
	return projection, nil
}

type CoverageVerdict string

const (
	CoverageCovered      CoverageVerdict = "covered"
	CoverageStale        CoverageVerdict = "stale"
	CoverageNotAssessed  CoverageVerdict = "not_assessed"
	CoverageUnknown      CoverageVerdict = "unknown"
	CoverageExcluded     CoverageVerdict = "excluded"
	CoverageFailed       CoverageVerdict = "failed"
	CoveragePartial      CoverageVerdict = "partial"
	CoverageUnauthorized CoverageVerdict = "unauthorized"
)

func (v CoverageVerdict) Passing() bool { return v == CoverageCovered }

// MapFleetCoverageVerdict translates the #413 capability verdict into the business-assessment
// vocabulary. agent_missing has no business analogue because Engagement coverage does not depend on
// an enrolled agent, so it fails closed to unknown.
func MapFleetCoverageVerdict(verdict fleetcoverage.Verdict) CoverageVerdict {
	switch verdict {
	case fleetcoverage.VerdictUnauthorized:
		return CoverageUnauthorized
	case fleetcoverage.VerdictRefused:
		return CoverageFailed
	case fleetcoverage.VerdictNever:
		return CoverageNotAssessed
	case fleetcoverage.VerdictStale:
		return CoverageStale
	case fleetcoverage.VerdictPartial:
		return CoveragePartial
	case fleetcoverage.VerdictCovered:
		return CoverageCovered
	default:
		return CoverageUnknown
	}
}

type CoverageSignals struct {
	Known      bool
	Authorized bool
	Excluded   bool
	Failed     bool
	Assessed   bool
	Fresh      bool
	Complete   bool
}

func ResolveCoverage(signals CoverageSignals) CoverageVerdict {
	switch {
	case !signals.Known:
		return CoverageUnknown
	case !signals.Authorized:
		return CoverageUnauthorized
	case signals.Excluded:
		return CoverageExcluded
	case signals.Failed:
		return CoverageFailed
	case !signals.Assessed:
		return CoverageNotAssessed
	case !signals.Fresh:
		return CoverageStale
	case !signals.Complete:
		return CoveragePartial
	default:
		return CoverageCovered
	}
}

type CoverageRow struct {
	Kind                string          `json:"kind"`
	ComponentID         string          `json:"component_id"`
	Name                string          `json:"name"`
	Verdict             CoverageVerdict `json:"verdict"`
	EngagementID        string          `json:"engagement_id,omitempty"`
	LastAssessed        *time.Time      `json:"last_assessed,omitempty"`
	FreshnessTargetDays int             `json:"freshness_target_days"`
}
type Coverage struct {
	Rows                []CoverageRow           `json:"rows"`
	Counts              map[CoverageVerdict]int `json:"counts"`
	FreshnessTargetDays int                     `json:"freshness_target_days"`
}

func (s *Service) Coverage(ctx context.Context, tenantID, id shared.ID) (Coverage, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	ctx = shared.WithTenant(ctx, tenantID)
	projects, err := s.Projects(ctx, tenantID, id)
	if err != nil {
		return Coverage{}, err
	}
	technical, err := s.TechnicalAssets(ctx, tenantID, id)
	if err != nil {
		return Coverage{}, err
	}
	engagements, err := s.Engagements(ctx, tenantID, id)
	if err != nil {
		return Coverage{}, err
	}
	const freshness = 90
	rows := make([]CoverageRow, 0, len(projects)+len(technical))
	latest := map[string]*engagement.Engagement{}
	excluded := map[string]bool{}
	for _, e := range engagements {
		for _, t := range e.Scope.InScope {
			if prior := latest[t.Value]; prior == nil || prior.Audit.UpdatedAt.Before(e.Audit.UpdatedAt) {
				latest[t.Value] = e
			}
		}
		for _, t := range e.Scope.OutOfScope {
			excluded[t.Value] = true
		}
	}
	seen := map[string]bool{}
	add := func(kind string, links []asset.ComponentMembership) {
		for _, link := range links {
			row := CoverageRow{Kind: kind, ComponentID: link.ComponentID.String(), Name: link.ComponentID.String(), FreshnessTargetDays: freshness}
			signals := CoverageSignals{Known: true, Authorized: true, Complete: true}
			seen[row.ComponentID] = true
			if e := latest[row.ComponentID]; e != nil {
				row.EngagementID = e.ID.String()
				signals.Authorized = e.IsAuthorizedAt(s.clock.Now())
				signals.Failed = e.Status == engagement.StatusArchived
				signals.Assessed = e.Status == engagement.StatusCompleted
				if signals.Assessed || signals.Failed {
					at := e.Audit.UpdatedAt
					row.LastAssessed = &at
					signals.Fresh = s.clock.Now().Sub(at) <= freshness*24*time.Hour
				}
			}
			row.Verdict = ResolveCoverage(signals)
			rows = append(rows, row)
		}
	}
	add("project", projects)
	add("technical_asset", technical)
	for value, e := range latest {
		if seen[value] {
			continue
		}
		row := CoverageRow{Kind: "scope", ComponentID: value, Name: value, EngagementID: e.ID.String(), FreshnessTargetDays: freshness}
		signals := CoverageSignals{Known: true, Authorized: e.IsAuthorizedAt(s.clock.Now()), Failed: e.Status == engagement.StatusArchived, Assessed: e.Status == engagement.StatusCompleted, Complete: true}
		if signals.Assessed || signals.Failed {
			at := e.Audit.UpdatedAt
			row.LastAssessed = &at
			signals.Fresh = s.clock.Now().Sub(at) <= freshness*24*time.Hour
		}
		row.Verdict = ResolveCoverage(signals)
		rows = append(rows, row)
	}
	for value := range excluded {
		if !seen[value] {
			rows = append(rows, CoverageRow{Kind: "scope", ComponentID: value, Name: value, Verdict: ResolveCoverage(CoverageSignals{Known: true, Authorized: true, Excluded: true}), FreshnessTargetDays: freshness})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		return rows[i].ComponentID < rows[j].ComponentID
	})
	counts := map[CoverageVerdict]int{}
	for _, r := range rows {
		counts[r.Verdict]++
	}
	return Coverage{Rows: rows, Counts: counts, FreshnessTargetDays: freshness}, nil
}

type Posture struct {
	Rating         string                  `json:"rating"`
	Explanation    string                  `json:"explanation"`
	FindingCounts  map[string]int          `json:"finding_counts"`
	CoverageCounts map[CoverageVerdict]int `json:"coverage_counts"`
}

func (s *Service) Posture(ctx context.Context, tenantID, id shared.ID) (Posture, error) {
	findings, err := s.Findings(ctx, tenantID, id)
	if err != nil {
		return Posture{}, err
	}
	coverage, err := s.Coverage(ctx, tenantID, id)
	if err != nil {
		return Posture{}, err
	}
	fc := map[string]int{}
	rating := "good"
	explanation := "No publishable findings and all known components are covered."
	for _, f := range findings {
		fc[string(f.Finding.Severity)]++
		if f.Finding.Severity == shared.SeverityCritical {
			rating = "critical"
		} else if rating != "critical" && f.Finding.Severity == shared.SeverityHigh {
			rating = "high_risk"
		} else if rating == "good" {
			rating = "attention"
		}
	}
	incompleteCoverage := len(coverage.Rows) == 0
	for verdict, count := range coverage.Counts {
		if count > 0 && !verdict.Passing() {
			incompleteCoverage = true
		}
	}
	if incompleteCoverage {
		if rating == "good" {
			rating = "unknown"
		}
		explanation = "Coverage is incomplete, stale, failed, or unauthorized; zero findings is not a clean result."
	} else if len(findings) > 0 {
		explanation = "Posture is derived from current findings and current coverage; external findings retain provenance and do not satisfy coverage."
	}
	return Posture{Rating: rating, Explanation: explanation, FindingCounts: fc, CoverageCounts: coverage.Counts}, nil
}

type HistoryItem struct {
	EngagementID   string     `json:"engagement_id"`
	Name           string     `json:"name"`
	Status         string     `json:"status"`
	AuthorizedFrom *time.Time `json:"authorized_from,omitempty"`
	AuthorizedTo   *time.Time `json:"authorized_to,omitempty"`
	ScopeCount     int        `json:"scope_count"`
	FindingCount   int        `json:"finding_count"`
	RetestCount    int        `json:"retest_count"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (s *Service) History(ctx context.Context, tenantID, id shared.ID) ([]HistoryItem, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	ctx = shared.WithTenant(ctx, tenantID)
	engagements, err := s.Engagements(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	out := make([]HistoryItem, 0, len(engagements))
	for _, e := range engagements {
		rows, err := s.findings.ListByEngagement(ctx, e.ID)
		if err != nil {
			return nil, err
		}
		retestCount := 0
		for _, row := range rows {
			retests, err := s.retests.ListByEngagementFinding(ctx, e.ID, row.ID)
			if err != nil {
				return nil, err
			}
			retestCount += len(retests)
		}
		imports, err := s.imported.ListByEngagement(ctx, tenantID, e.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, HistoryItem{EngagementID: e.ID.String(), Name: e.Name, Status: string(e.Status), AuthorizedFrom: e.AuthorizedFrom, AuthorizedTo: e.AuthorizedTo, ScopeCount: len(e.Scope.InScope) + len(e.Scope.OutOfScope), FindingCount: len(rows) + len(imports), RetestCount: retestCount, UpdatedAt: e.Audit.UpdatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (s *Service) record(ctx context.Context, actor, action string, target shared.ID) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	return s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target.String(), At: s.clock.Now()})
}
func clone(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
