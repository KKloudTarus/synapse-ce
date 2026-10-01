package projectuc

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// StartBitbucketWebhookAnalysis uses only the persisted source and requires a
// durable queue so receipt and scan enqueue can commit together.
func (s *Service) StartBitbucketWebhookAnalysis(ctx context.Context, actor string, tenantID, projectID shared.ID, in ports.BitbucketScanTarget) (ports.ScanJob, error) {
	if err := requireActor(actor); err != nil {
		return ports.ScanJob{}, err
	}
	if s.scanner == nil {
		return ports.ScanJob{}, fmt.Errorf("%w: project analysis is not configured", shared.ErrValidation)
	}
	p, err := s.repo.GetByID(ctx, tenantID, projectID)
	if err != nil {
		return ports.ScanJob{}, fmt.Errorf("get webhook project: %w", err)
	}
	if p == nil || p.SourceBinding.Kind != project.SourceGit {
		return ports.ScanJob{}, fmt.Errorf("%w: webhook project must use a git source", shared.ErrValidation)
	}
	e, err := s.engagements.GetByProjectID(ctx, tenantID, p.ID)
	if err != nil {
		return ports.ScanJob{}, fmt.Errorf("get project analysis context: %w", err)
	}
	gate, err := s.resolveManagedGate(ctx, tenantID, p.GateID)
	if err != nil {
		return ports.ScanJob{}, err
	}
	ref := strings.TrimSpace(in.Ref)
	request := ports.AcquireRequest{
		Kind: p.SourceBinding.Kind, Value: p.SourceBinding.Value,
		Ref: ref, Commit: strings.TrimSpace(in.SHA),
		DisableGitCredentials: in.Fork,
	}
	if in.PullRequest {
		request.BaseRef = in.BaseRef
		if request.BaseRef == "" {
			request.BaseRef = p.SourceBinding.DefaultBranch
		}
		if request.BaseRef == "" {
			request.BaseRef = p.SourceBinding.Ref
		}
	} else {
		request.BaseRef = p.SourceBinding.BaseRef
	}
	return s.scanner.StartQueuedScanWithOptions(ctx, actor, e.ID, request, scauc.ScanOptions{
		Mode: scauc.ScanModeFull, CodeQuality: true, ProjectAnalysis: true,
		NoBuildExecution: in.Fork, Gate: gate,
	})
}
