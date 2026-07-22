// Package projectuc implements project application logic.
package projectuc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	hotspotsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/hotspots"
	issuesuc "github.com/KKloudTarus/synapse-ce/internal/usecase/issues"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	qualitygatesuc "github.com/KKloudTarus/synapse-ce/internal/usecase/qualitygates"
	qualityprofilesuc "github.com/KKloudTarus/synapse-ce/internal/usecase/qualityprofiles"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

type Service struct {
	repo             ports.ProjectRepository
	engagements      ports.EngagementRepository
	clock            ports.Clock
	ids              ports.IDGenerator
	audit            ports.AuditLogger
	scanner          *scauc.Service
	archives         ports.ProjectArchiveStore
	analyses         ports.ProjectAnalysisStore
	hotspots         ports.ProjectHotspotStore
	issues           ports.ProjectIssueStore
	ruleCatalog      ports.RuleCatalog
	findings         ports.FindingRepository
	gates            *qualitygatesuc.Service
	gateMutator      ports.QualityGateMutator
	profiles         *qualityprofilesuc.Service
	allowLocalSource bool
	cursorSecret     []byte
}

func NewService(repo ports.ProjectRepository, engagements ports.EngagementRepository, clock ports.Clock, ids ports.IDGenerator, audit ports.AuditLogger, allowLocalSource bool) *Service {
	return &Service{repo: repo, engagements: engagements, clock: clock, ids: ids, audit: audit, allowLocalSource: allowLocalSource}
}

func (s *Service) SetScanner(scanner *scauc.Service)                      { s.scanner = scanner }
func (s *Service) SetArchiveStore(store ports.ProjectArchiveStore)        { s.archives = store }
func (s *Service) SetAnalysisStore(store ports.ProjectAnalysisStore)      { s.analyses = store }
func (s *Service) SetHotspotStore(store ports.ProjectHotspotStore)        { s.hotspots = store }
func (s *Service) SetIssueStore(store ports.ProjectIssueStore)            { s.issues = store }
func (s *Service) SetRuleCatalog(catalog ports.RuleCatalog)               { s.ruleCatalog = catalog }
func (s *Service) SetQualityProfiles(profiles *qualityprofilesuc.Service) { s.profiles = profiles }
func (s *Service) SetFindingRepository(repo ports.FindingRepository)      { s.findings = repo }
func (s *Service) SetQualityGates(gates *qualitygatesuc.Service)          { s.gates = gates }
func (s *Service) SetQualityGateMutator(mutator ports.QualityGateMutator) { s.gateMutator = mutator }

// ValidateCursorSecret returns an error when key is nil or shorter than 32 bytes.
func ValidateCursorSecret(key []byte) error {
	if len(key) < 32 {
		return fmt.Errorf("measure cursor secret must be at least 32 bytes, got %d", len(key))
	}
	return nil
}

// SetCursorSecret injects the HMAC signing key for pagination cursors.
// Returns an error when the key is absent or shorter than 32 bytes.
// The byte slice is copied so later caller mutation cannot alter the service key.
func (s *Service) SetCursorSecret(secret []byte) error {
	if err := ValidateCursorSecret(secret); err != nil {
		return err
	}
	copied := make([]byte, len(secret))
	copy(copied, secret)
	s.cursorSecret = copied
	return nil
}

type ruleResolver struct {
	catalog ports.RuleCatalog
	ctx     context.Context
}

func (r *ruleResolver) Get(key rule.Key) (rule.Rule, error) {
	return r.catalog.Get(r.ctx, key)
}

func (s *Service) CreateFromArchive(ctx context.Context, in CreateInput, filename string, src io.Reader) (*project.Project, error) {
	if err := requireActor(in.CreatedBy); err != nil {
		return nil, err
	}
	if s.archives == nil {
		return nil, fmt.Errorf("%w: project archive uploads are not configured", shared.ErrValidation)
	}
	id := s.ids.NewID()
	path, err := s.archives.Save(ctx, id, filename, src)
	if err != nil {
		return nil, err
	}
	in.SourceBinding = project.SourceBinding{Kind: project.SourceArchive, Value: path}
	p, err := s.create(ctx, in, id)
	if err != nil {
		_ = s.archives.Delete(ctx, id)
	}
	return p, err
}

type CreateInput struct {
	TenantID             shared.ID
	CreatedBy            string
	Name                 string
	Key                  string
	SourceBinding        project.SourceBinding
	DefaultProfileByLang map[string]string
	GateID               string
}

func (s *Service) Create(ctx context.Context, in CreateInput) (*project.Project, error) {
	return s.create(ctx, in, s.ids.NewID())
}

func (s *Service) create(ctx context.Context, in CreateInput, id shared.ID) (*project.Project, error) {
	if err := requireActor(in.CreatedBy); err != nil {
		return nil, err
	}
	if s.engagements == nil {
		return nil, fmt.Errorf("%w: project analysis context repository is required", shared.ErrValidation)
	}
	if in.SourceBinding.Kind == project.SourceLocal && !s.allowLocalSource {
		return nil, fmt.Errorf("%w: local project sources are only available in development", shared.ErrValidation)
	}
	if in.SourceBinding.Kind == project.SourceLocal || in.SourceBinding.Kind == project.SourceArchive {
		if abs, err := filepath.Abs(in.SourceBinding.Value); err == nil {
			in.SourceBinding.Value = abs
		}
	}
	now := s.clock.Now()
	p, err := project.New(id, in.TenantID, in.Name, in.Key, in.SourceBinding, in.DefaultProfileByLang, in.GateID, now)
	if err != nil {
		return nil, err
	}
	p.Audit.CreatedBy, p.Audit.UpdatedBy = in.CreatedBy, in.CreatedBy
	if _, builtIn := qualitygate.Resolve(p.GateID); p.GateID != "" && !builtIn {
		if s.gateMutator == nil {
			return nil, fmt.Errorf("%w: quality gate mutations are not configured", shared.ErrValidation)
		}
		err = s.gateMutator.CreateProjectWithGate(ctx, p)
	} else {
		err = s.repo.Create(ctx, p)
	}
	if err != nil {
		return nil, fmt.Errorf("persist project: %w", err)
	}
	analysis, err := engagement.New(s.ids.NewID(), p.TenantID, p.Name+" analysis", "", now)
	if err == nil {
		analysis.ProjectID = p.ID
		analysis.Audit.CreatedBy, analysis.Audit.UpdatedBy = in.CreatedBy, in.CreatedBy
		err = analysis.SetScope([]engagement.Target{{Kind: engagement.TargetRepo, Value: p.SourceBinding.Value}}, nil, now)
	}
	if err == nil {
		err = s.engagements.Create(ctx, analysis)
	}
	if err != nil {
		_ = s.repo.DeleteByKey(ctx, p.TenantID, p.Key)
		return nil, fmt.Errorf("persist project analysis context: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: in.CreatedBy, Action: "project.create", Target: p.ID.String(), Metadata: map[string]string{"project": p.Key}, At: now}); err != nil {
		return nil, fmt.Errorf("audit project.create: %w", err)
	}
	return p, nil
}

func (s *Service) List(ctx context.Context, tenantID shared.ID) ([]*project.Project, error) {
	list, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	return list, nil
}

// ProjectSummary combines a Project with its latest decision record and active job.
type ProjectSummary struct {
	Project        *project.Project
	LatestAnalysis *projectanalysis.Analysis
	LatestJob      *ports.ScanJob
}

// ListSummaries serves the unpaginated Project portfolio without browser-side N+1 requests.
// add cursor pagination plus server-side filters when returning a tenant's full searchable portfolio becomes materially expensive.
func (s *Service) ListSummaries(ctx context.Context, tenantID shared.ID) ([]ProjectSummary, error) {
	projects, err := s.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	projectIDs := make([]shared.ID, len(projects))
	for i, p := range projects {
		projectIDs[i] = p.ID
	}
	latest := map[shared.ID]projectanalysis.Analysis{}
	if s.analyses != nil {
		latest, err = s.analyses.LatestForProjects(ctx, tenantID, projectIDs)
		if err != nil {
			return nil, fmt.Errorf("list latest project analyses: %w", err)
		}
	}
	contexts := map[shared.ID]*engagement.Engagement{}
	if s.scanner != nil && s.engagements != nil {
		contexts, err = s.engagements.ProjectContexts(ctx, tenantID, projectIDs)
		if err != nil {
			return nil, fmt.Errorf("list project analysis contexts: %w", err)
		}
	}
	engagementIDs := make([]shared.ID, 0, len(contexts))
	for _, context := range contexts {
		engagementIDs = append(engagementIDs, context.ID)
	}
	jobs := map[shared.ID]ports.ScanJob{}
	if s.scanner != nil {
		jobs, err = s.scanner.LatestJobs(ctx, engagementIDs)
		if err != nil {
			return nil, fmt.Errorf("list latest project analysis jobs: %w", err)
		}
	}
	out := make([]ProjectSummary, len(projects))
	for i, p := range projects {
		out[i].Project = p
		if analysis, ok := latest[p.ID]; ok {
			out[i].LatestAnalysis = &analysis
		}
		if context := contexts[p.ID]; context != nil {
			if job, ok := jobs[context.ID]; ok {
				out[i].LatestJob = &job
			}
		}
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, tenantID shared.ID, key string) (*project.Project, error) {
	p, err := s.repo.GetByKey(ctx, tenantID, strings.TrimSpace(key))
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}
	return p, nil
}

func (s *Service) analysisContext(ctx context.Context, tenantID shared.ID, key string) (*project.Project, *engagement.Engagement, error) {
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return nil, nil, err
	}
	e, err := s.engagements.GetByProjectID(ctx, tenantID, p.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get project analysis context: %w", err)
	}
	return p, e, nil
}

func (s *Service) AssignGate(ctx context.Context, actor string, tenantID shared.ID, key, gateID string) (*project.Project, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	if _, err := s.resolveManagedGate(ctx, tenantID, gateID); err != nil {
		return nil, err
	}
	if s.gateMutator == nil {
		return nil, fmt.Errorf("%w: quality gate mutations are not configured", shared.ErrValidation)
	}
	gateID = strings.TrimSpace(gateID)
	if err := s.gateMutator.AssignProjectGate(ctx, tenantID, p.Key, gateID, ports.AuditEntry{Actor: actor, Action: "project.gate.assign", Target: p.ID.String(), Metadata: map[string]string{"project": p.Key, "gate": gateID}, At: s.clock.Now()}); err != nil {
		return nil, fmt.Errorf("assign project quality gate: %w", err)
	}
	p.GateID = gateID
	return p, nil
}

func (s *Service) StartAnalysis(ctx context.Context, actor string, tenantID shared.ID, key string, coverage *measure.CoverageReport) (ports.ScanJob, error) {
	if err := requireActor(actor); err != nil {
		return ports.ScanJob{}, err
	}
	if s.scanner == nil {
		return ports.ScanJob{}, fmt.Errorf("%w: project analysis is not configured", shared.ErrValidation)
	}
	p, e, err := s.analysisContext(ctx, tenantID, key)
	if err != nil {
		return ports.ScanJob{}, err
	}
	gate, err := s.resolveManagedGate(ctx, tenantID, p.GateID)
	if err != nil {
		return ports.ScanJob{}, err
	}
	return s.scanner.StartScanWithOptions(ctx, actor, e.ID, ports.AcquireRequest{
		Kind: p.SourceBinding.Kind, Value: p.SourceBinding.Value, Ref: p.SourceBinding.Ref,
	}, scauc.ScanOptions{Mode: scauc.ScanModeFull, CodeQuality: true, ProjectAnalysis: true, LineCoverage: coverage, Gate: gate})
}

func (s *Service) AnalysisStatus(ctx context.Context, tenantID shared.ID, key string) (ports.ScanJob, error) {
	if s.scanner == nil {
		return ports.ScanJob{}, shared.ErrNotFound
	}
	_, e, err := s.analysisContext(ctx, tenantID, key)
	if err != nil {
		return ports.ScanJob{}, err
	}
	return s.scanner.LatestJob(ctx, e.ID)
}

type LatestAnalysis struct {
	Analysis projectanalysis.Analysis
	Result   []byte
}

func (s *Service) LatestAnalysis(ctx context.Context, tenantID shared.ID, key string) (LatestAnalysis, error) {
	if s.analyses == nil {
		return LatestAnalysis{}, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return LatestAnalysis{}, err
	}
	analysis, result, err := s.analyses.LatestWithResult(ctx, tenantID, p.ID)
	if err != nil {
		return LatestAnalysis{}, err
	}
	return LatestAnalysis{Analysis: analysis, Result: result}, nil
}

// ListAnalyses returns one immutable Project history page, newest first.
func (s *Service) ListAnalyses(ctx context.Context, tenantID shared.ID, key string, limit int, beforeCreatedAt time.Time, beforeID shared.ID) ([]projectanalysis.Analysis, bool, error) {
	if s.analyses == nil {
		return nil, false, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return nil, false, err
	}
	return s.analyses.List(ctx, tenantID, p.ID, limit, beforeCreatedAt, beforeID)
}

// GetAnalysis returns one snapshot without disclosing another Project's history.
func (s *Service) GetAnalysis(ctx context.Context, tenantID shared.ID, key, id string) (projectanalysis.Analysis, error) {
	if s.analyses == nil {
		return projectanalysis.Analysis{}, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return projectanalysis.Analysis{}, err
	}
	return s.analyses.Get(ctx, tenantID, p.ID, shared.ID(id))
}

// RecordProjectAnalysis is called by SCA only after a successful pipeline and
// before its ScanJob becomes succeeded. Non-Project scans intentionally no-op.
func (s *Service) RecordProjectAnalysis(ctx context.Context, engagementID shared.ID, jobID string, completedAt time.Time, result *scauc.ScanResult) error {
	if result == nil {
		return fmt.Errorf("project analysis result is required")
	}
	e, err := s.engagements.GetByID(ctx, engagementID)
	if err != nil {
		return fmt.Errorf("get project analysis context: %w", err)
	}
	if e.ProjectID.IsZero() {
		return nil
	}
	if s.analyses == nil {
		return fmt.Errorf("project analysis store is not configured")
	}
	p, err := s.repo.GetByID(ctx, e.TenantID, e.ProjectID)
	if err != nil {
		return fmt.Errorf("get project for analysis: %w", err)
	}
	previous, _, err := s.analyses.List(ctx, p.TenantID, p.ID, 1, time.Time{}, "")
	if err != nil {
		return fmt.Errorf("list project analyses: %w", err)
	}
	var baseline *projectanalysis.Analysis
	if len(previous) > 0 {
		baseline = &previous[0]
	}
	all := append([]finding.Finding{}, result.Findings...)
	if result.CodeQuality != nil {
		all = append(all, result.CodeQuality.Findings...)
	}
	if s.findings != nil {
		persisted, err := s.findings.ListByEngagement(ctx, engagementID)
		if err != nil {
			return fmt.Errorf("list persisted findings: %w", err)
		}
		statuses := make(map[string]finding.Status, len(persisted))
		for _, item := range persisted {
			if key := finding.Identity(item); key != "" {
				statuses[key] = item.Status
			}
		}
		for i := range all {
			if status, ok := statuses[finding.Identity(all[i])]; ok {
				all[i].Status = status
			}
		}
	}
	all = finding.Publishable(all)
	// Honor the project's assigned quality profiles: deactivate rules and apply severity overrides
	// before classification, so both issues and hotspots reflect the profile (P9, #183). Languages with
	// no assignment (or assigned to the built-in default) contribute nothing.
	if s.profiles != nil {
		overlay, err := s.profiles.OverlayForProject(ctx, p.TenantID, p.DefaultProfileByLang)
		if err != nil {
			return fmt.Errorf("resolve project quality profiles: %w", err)
		}
		all = overlay.Apply(all)
	}
	if s.ruleCatalog == nil {
		return fmt.Errorf("classify project hotspots: rule catalog is not configured")
	}
	issues, candidates, err := hotspotsuc.Classify(ctx, all, s.ruleCatalog)
	if err != nil {
		return fmt.Errorf("classify project hotspots: %w", err)
	}
	loc := 0
	if result.CodeQuality != nil {
		loc = result.CodeQuality.Inventory.Totals().CodeLines
	}

	// Compute Hotspot Summaries
	var existingHotspots []hotspot.Hotspot
	if s.hotspots != nil {
		var beforeID shared.ID
		var beforeLastSeenAt time.Time
		for {
			page, err := s.hotspots.ListHotspots(ctx, p.TenantID, p.ID, hotspot.ListFilter{Limit: 1000, BeforeID: beforeID, BeforeLastSeenAt: beforeLastSeenAt})
			if err != nil {
				break
			}
			existingHotspots = append(existingHotspots, page.Items...)
			if page.Next == nil {
				break
			}
			beforeID = page.Next.BeforeID
			beforeLastSeenAt = page.Next.BeforeLastSeenAt
		}
	}
	existingMap := make(map[string]hotspot.Hotspot, len(existingHotspots))
	for _, h := range existingHotspots {
		existingMap[h.Key] = h
	}

	hsTotal := len(candidates)
	hsReviewed := 0
	newHsTotal := 0
	newHsReviewed := 0

	for _, c := range candidates {
		ex, found := existingMap[c.Key]
		isNew := !found
		if found && baseline != nil && ex.FirstSeenAt.After(baseline.CreatedAt) {
			isNew = true
		} else if !found {
			// if baseline is nil, everything is new code
			isNew = true
		} else if found && baseline == nil {
			isNew = true
		}

		if isNew {
			newHsTotal++
		}

		if found {
			// Reappearance of a fixed hotspot => becomes to_review (unreviewed)
			if ex.Status == hotspot.StatusFixed && completedAt.After(ex.LastSeenAt) {
				if !isNew {
					newHsTotal++ // Reopened hotspot is tracked as new code
				}
				continue
			}
			if ex.Status.Reviewed() {
				hsReviewed++
				if isNew {
					newHsReviewed++
				}
			}
		}
	}

	overallHsSummary, _ := hotspot.NewSummary(hsTotal, hsReviewed)
	newHsSummary, _ := hotspot.NewSummary(newHsTotal, newHsReviewed)

	gate := result.Gate
	gateSource := ""
	if p.GateID != "" {
		gateSource = "managed"
	}
	if len(gate.Conditions) == 0 {
		var err error
		gate, err = s.resolveManagedGate(ctx, p.TenantID, p.GateID)
		if err != nil {
			return err
		}
	}
	if p.GateID == "" && len(gate.Conditions) > 0 {
		gateSource = "repository"
	}
	issueCandidates, err := issuesuc.Project(ctx, issues, s.ruleCatalog)
	if err != nil {
		return fmt.Errorf("project issues: %w", err)
	}
	// A prior triage decision (accepted/false-positive/won't-fix) carries forward:
	// the resolved issue stays exempt from this analysis's quality gate.
	exempt := result.GateExemptKeys(issues)
	if s.issues != nil {
		resolved, rErr := s.issues.ResolvedIssueKeys(ctx, p.TenantID, p.ID)
		if rErr != nil {
			return fmt.Errorf("carry forward resolved issues: %w", rErr)
		}
		for k := range resolved {
			exempt[k] = true
		}
	}

	var issueInputs []measure.IssueInput
	for _, f := range issues {
		if !f.Kind.IsRuleBased() {
			continue
		}
		path, _, _ := qualitygate.FileLineOf(f.DedupKey)
		issueInputs = append(issueInputs, measure.IssueInput{
			Path:     path,
			RuleKey:  rule.Key(f.RuleKey),
			Severity: f.Severity,
		})
	}
	for _, candidate := range candidates {
		path := candidate.Location
		if path == "" {
			path, _, _ = qualitygate.FileLineOf(candidate.FindingIdentity)
		}
		issueInputs = append(issueInputs, measure.IssueInput{
			Path:     path,
			RuleKey:  rule.Key(candidate.RuleKey),
			Severity: candidate.Severity,
		})
	}

	resolver := &ruleResolver{catalog: s.ruleCatalog, ctx: ctx}

	var inventory measure.Inventory
	var compPtr *measure.ComplexityReport
	var dupPtr *measure.DuplicationReport
	if result.CodeQuality != nil {
		inventory = result.CodeQuality.Inventory
		compPtr = result.CodeQuality.Complexity
		dupPtr = result.CodeQuality.Duplication
	}

	snapshot, err := measure.BuildSnapshot(measure.BuildSnapshotInput{
		Inventory:   inventory,
		Complexity:  compPtr,
		Coverage:    result.LineCoverage,
		Duplication: dupPtr,
		Issues:      issueInputs,
		RuleCatalog: resolver,
	})
	if err != nil {
		return fmt.Errorf("build measure snapshot: %w", err)
	}
	var analysisDuplication measure.DuplicationReport
	if dupPtr != nil {
		analysisDuplication = *dupPtr
	}

	analysis, err := projectanalysis.Build(projectanalysis.Input{
		ID: jobID, TenantID: p.TenantID, ProjectID: p.ID, ProjectKey: p.Key, CreatedAt: completedAt,
		SourceRef: result.SourceRef, SourceCommit: result.SourceCommit, Findings: issues, Gate: gate, GateSource: gateSource, GateExempt: exempt, LinesOfCode: loc,
		Coverage: result.LineCoverage, Duplication: analysisDuplication, Previous: baseline,
		Hotspots: overallHsSummary, NewHotspots: newHsSummary, Snapshot: snapshot,
	})
	if err != nil {
		return fmt.Errorf("build project analysis: %w", err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal project analysis result: %w", err)
	}
	if projectionStore, ok := s.analyses.(ports.ProjectIssueProjectionStore); ok {
		if err := projectionStore.SaveWithResultAndProjections(ctx, analysis, data, candidates, issueCandidates); err != nil {
			return fmt.Errorf("save project analysis and projections: %w", err)
		}
	} else if projectionStore, ok := s.analyses.(ports.ProjectAnalysisProjectionStore); ok {
		// A store that can persist hotspots but not issues must not silently drop the
		// issue projection while marking the analysis complete: fail closed instead.
		if len(issueCandidates) > 0 {
			return fmt.Errorf("save project analysis and projections: store cannot persist issue projections")
		}
		if err := projectionStore.SaveWithResultAndHotspots(ctx, analysis, data, candidates); err != nil {
			return fmt.Errorf("save project analysis and hotspots: %w", err)
		}
	} else if len(candidates) > 0 {
		return fmt.Errorf("save project analysis and hotspots: projection store is not configured")
	} else if err := s.analyses.SaveWithResult(ctx, analysis, data); err != nil {
		return fmt.Errorf("save project analysis: %w", err)
	}
	return nil
}

// ListHotspots returns projections belonging to the requested tenant and Project for the current analysis lens.
func (s *Service) ListHotspots(ctx context.Context, tenantID shared.ID, key string, filter hotspot.ListFilter) (hotspot.Page, error) {
	if s.hotspots == nil || s.analyses == nil {
		return hotspot.Page{}, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return hotspot.Page{}, err
	}
	latestMap, err := s.analyses.LatestForProjects(ctx, tenantID, []shared.ID{p.ID})
	if err != nil {
		return hotspot.Page{}, err
	}
	latest, ok := latestMap[p.ID]
	if !ok {
		// Empty page with A-grade summary
		summary, _ := hotspot.NewSummary(0, 0)
		return hotspot.Page{Summary: summary, Facets: hotspot.Facets{Statuses: map[string]int{}, RuleKeys: map[string]int{}, Severities: map[string]int{}}}, nil
	}

	page, summary, err := s.hotspots.ListAnalysisHotspots(ctx, tenantID, p.ID, shared.ID(latest.ID), filter.Lens, filter)
	if err != nil {
		return hotspot.Page{}, err
	}
	page.Summary = summary
	return page, nil
}

// GetHotspot returns one projection only after the Project has been resolved in the caller's tenant.
func (s *Service) GetHotspot(ctx context.Context, tenantID shared.ID, key string, hotspotID shared.ID) (hotspot.Hotspot, error) {
	if s.hotspots == nil {
		return hotspot.Hotspot{}, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return hotspot.Hotspot{}, err
	}
	return s.hotspots.GetHotspot(ctx, tenantID, p.ID, hotspotID)
}

// TransitionHotspot applies a human review decision to a hotspot.
func (s *Service) TransitionHotspot(ctx context.Context, actor string, tenantID shared.ID, key string, hotspotID shared.ID, to hotspot.Status, rationale string, expectedVersion int) (hotspot.Hotspot, hotspot.ReviewEvent, error) {
	if err := requireActor(actor); err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, err
	}
	if s.hotspots == nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, err
	}

	cmd := hotspot.TransitionCommand{
		TenantID:        p.TenantID,
		ProjectID:       p.ID,
		HotspotID:       hotspotID,
		EventID:         s.ids.NewID(),
		To:              to,
		Actor:           actor,
		Rationale:       rationale,
		ExpectedVersion: expectedVersion,
	}
	updated, event, err := s.hotspots.TransitionHotspot(ctx, cmd)
	if err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, fmt.Errorf("transition hotspot: %w", err)
	}

	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "project.hotspot.review",
		Target: p.ID.String(),
		Metadata: map[string]string{
			"project":    p.Key,
			"hotspot_id": hotspotID.String(),
			"to":         string(to),
		},
		At: s.clock.Now(),
	}); err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, fmt.Errorf("audit hotspot review: %w", err)
	}

	return updated, event, nil
}

// HotspotHistory returns the immutable review event history of a hotspot.
func (s *Service) HotspotHistory(ctx context.Context, tenantID shared.ID, key string, hotspotID shared.ID) ([]hotspot.ReviewEvent, error) {
	if s.hotspots == nil {
		return nil, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	return s.hotspots.HotspotHistory(ctx, p.TenantID, p.ID, hotspotID)
}

// ListIssues returns the tenant- and Project-scoped code-quality issues for the
// faceted explorer. Cross-tenant/unknown projects resolve to not-found via Get.
func (s *Service) ListIssues(ctx context.Context, tenantID shared.ID, key string, filter issue.ListFilter) (issue.Page, error) {
	if s.issues == nil {
		return issue.Page{}, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return issue.Page{}, err
	}
	return s.issues.ListIssues(ctx, p.TenantID, p.ID, filter)
}

// GetIssue returns one issue only after the Project is resolved in the caller's tenant.
func (s *Service) GetIssue(ctx context.Context, tenantID shared.ID, key string, issueID shared.ID) (issue.Issue, error) {
	if s.issues == nil {
		return issue.Issue{}, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return issue.Issue{}, err
	}
	return s.issues.GetIssue(ctx, p.TenantID, p.ID, issueID)
}

// TransitionIssue applies an attributable, gate-affecting triage decision to an issue.
func (s *Service) TransitionIssue(ctx context.Context, actor string, tenantID shared.ID, key string, issueID shared.ID, to issue.Status, rationale string, expectedVersion int) (issue.Issue, issue.ReviewEvent, error) {
	if err := requireActor(actor); err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, err
	}
	if s.issues == nil {
		return issue.Issue{}, issue.ReviewEvent{}, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, err
	}
	cmd := issue.TransitionCommand{
		TenantID:        p.TenantID,
		ProjectID:       p.ID,
		IssueID:         issueID,
		EventID:         s.ids.NewID(),
		To:              to,
		Actor:           actor,
		Rationale:       rationale,
		ExpectedVersion: expectedVersion,
	}
	updated, event, err := s.issues.TransitionIssue(ctx, cmd)
	if err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, fmt.Errorf("transition issue: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "project.issue.transition",
		Target: p.ID.String(),
		Metadata: map[string]string{
			"project":  p.Key,
			"issue_id": issueID.String(),
			"to":       string(to),
		},
		At: s.clock.Now(),
	}); err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, fmt.Errorf("audit issue transition: %w", err)
	}
	return updated, event, nil
}

// IssueHistory returns the immutable, append-only lifecycle history of an issue.
func (s *Service) IssueHistory(ctx context.Context, tenantID shared.ID, key string, issueID shared.ID) ([]issue.ReviewEvent, error) {
	if s.issues == nil {
		return nil, shared.ErrNotFound
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	return s.issues.IssueHistory(ctx, p.TenantID, p.ID, issueID)
}

func (s *Service) resolveManagedGate(ctx context.Context, tenantID shared.ID, key string) (qualitygate.Gate, error) {
	if strings.TrimSpace(key) == "" {
		return qualitygate.Gate{}, nil
	}
	if s.gates == nil {
		return qualitygate.Gate{}, fmt.Errorf("%w: quality gate service is not configured", shared.ErrValidation)
	}
	gate, err := s.gates.Get(ctx, tenantID, key)
	if err != nil {
		return qualitygate.Gate{}, err
	}
	return gate, nil
}

func (s *Service) Delete(ctx context.Context, actor string, tenantID shared.ID, key string) error {
	if err := requireActor(actor); err != nil {
		return err
	}
	p, err := s.repo.GetByKey(ctx, tenantID, strings.TrimSpace(key))
	if err != nil {
		return err
	}
	if s.engagements != nil {
		if e, err := s.engagements.GetByProjectID(ctx, tenantID, p.ID); err == nil {
			if err := s.engagements.Delete(ctx, e.ID); err != nil {
				return fmt.Errorf("delete project analysis context: %w", err)
			}
		} else if !errors.Is(err, shared.ErrNotFound) {
			return fmt.Errorf("get project analysis context: %w", err)
		}
	}
	if err := s.repo.DeleteByKey(ctx, tenantID, p.Key); err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "project.delete", Target: p.ID.String(), Metadata: map[string]string{"project": p.Key}, At: s.clock.Now()}); err != nil {
		return fmt.Errorf("audit project.delete: %w", err)
	}
	return nil
}

func requireActor(actor string) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	return nil
}
