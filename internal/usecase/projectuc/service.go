// Package projectuc implements project application logic.
package projectuc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

type analysisContextRepository interface {
	GetByProjectID(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error)
}

type Service struct {
	repo             ports.ProjectRepository
	engagements      ports.EngagementRepository
	analysisContexts analysisContextRepository
	clock            ports.Clock
	ids              ports.IDGenerator
	audit            ports.AuditLogger
	scanner          *scauc.Service
	archives         ports.ProjectArchiveStore
	allowLocalSource bool
}

func NewService(repo ports.ProjectRepository, engagements ports.EngagementRepository, clock ports.Clock, ids ports.IDGenerator, audit ports.AuditLogger, allowLocalSource bool) *Service {
	contexts, _ := engagements.(analysisContextRepository)
	return &Service{repo: repo, engagements: engagements, analysisContexts: contexts, clock: clock, ids: ids, audit: audit, allowLocalSource: allowLocalSource}
}

func (s *Service) SetScanner(scanner *scauc.Service)               { s.scanner = scanner }
func (s *Service) SetArchiveStore(store ports.ProjectArchiveStore) { s.archives = store }

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
	if s.engagements == nil || s.analysisContexts == nil {
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
	if err := s.repo.Create(ctx, p); err != nil {
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
	e, err := s.analysisContexts.GetByProjectID(ctx, tenantID, p.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get project analysis context: %w", err)
	}
	return p, e, nil
}

func (s *Service) StartAnalysis(ctx context.Context, actor string, tenantID shared.ID, key string) (ports.ScanJob, error) {
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
	if latest, latestErr := s.scanner.LatestJob(ctx, e.ID); latestErr == nil && latest.Status == ports.ScanRunning {
		return ports.ScanJob{}, fmt.Errorf("%w: project analysis is already running", shared.ErrConflict)
	} else if latestErr != nil && !errors.Is(latestErr, shared.ErrNotFound) {
		return ports.ScanJob{}, latestErr
	}
	return s.scanner.StartScanWithOptions(ctx, actor, e.ID, ports.AcquireRequest{
		Kind: p.SourceBinding.Kind, Value: p.SourceBinding.Value, Ref: p.SourceBinding.Ref,
	}, scauc.ScanOptions{Mode: scauc.ScanModeFull, CodeQuality: true})
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

func (s *Service) LatestAnalysis(ctx context.Context, tenantID shared.ID, key string) ([]byte, error) {
	if s.scanner == nil {
		return nil, shared.ErrNotFound
	}
	_, e, err := s.analysisContext(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	return s.scanner.LatestResult(ctx, e.ID)
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
		if e, err := s.analysisContexts.GetByProjectID(ctx, tenantID, p.ID); err == nil {
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
