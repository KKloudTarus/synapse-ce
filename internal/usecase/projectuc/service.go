// Package projectuc implements project application logic.
package projectuc

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	repo  ports.ProjectRepository
	clock ports.Clock
	ids   ports.IDGenerator
	audit ports.AuditLogger
}

func NewService(repo ports.ProjectRepository, clock ports.Clock, ids ports.IDGenerator, audit ports.AuditLogger) *Service {
	return &Service{repo: repo, clock: clock, ids: ids, audit: audit}
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
	if err := requireActor(in.CreatedBy); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	p, err := project.New(s.ids.NewID(), in.TenantID, in.Name, in.Key, in.SourceBinding, in.DefaultProfileByLang, in.GateID, now)
	if err != nil {
		return nil, err
	}
	p.Audit.CreatedBy, p.Audit.UpdatedBy = in.CreatedBy, in.CreatedBy
	if err := s.repo.Create(ctx, p); err != nil {
		return nil, fmt.Errorf("persist project: %w", err)
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

func (s *Service) Delete(ctx context.Context, actor string, tenantID shared.ID, key string) error {
	if err := requireActor(actor); err != nil {
		return err
	}
	p, err := s.repo.GetByKey(ctx, tenantID, strings.TrimSpace(key))
	if err != nil {
		return err
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
