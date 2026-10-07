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

// ResolveBitbucketWebhookTarget expands the provider's PR commit prefix using
// only the stored repository. Network I/O runs before receipt/enqueue locking.
func (s *Service) ResolveBitbucketWebhookTarget(ctx context.Context, tenantID, projectID shared.ID, in ports.BitbucketScanTarget) (ports.BitbucketScanTarget, error) {
	if !in.PullRequest || len(in.SHA) != 12 || s.bitbucketCommits == nil {
		return in, fmt.Errorf("%w: Bitbucket commit resolution is not configured", shared.ErrValidation)
	}
	p, err := s.repo.GetByID(ctx, tenantID, projectID)
	if err != nil {
		return in, fmt.Errorf("get webhook project: %w", err)
	}
	if p == nil || p.SourceBinding.Kind != project.SourceGit {
		return in, fmt.Errorf("%w: webhook project must use a git source", shared.ErrValidation)
	}
	sha, err := s.bitbucketCommits.ResolveBitbucketCommit(shared.WithTenant(ctx, tenantID), p.SourceBinding.Value, in.SHA, in.Fork)
	if err != nil {
		return in, fmt.Errorf("resolve Bitbucket webhook commit: %w", err)
	}
	if len(sha) != 40 || !strings.HasPrefix(strings.ToLower(sha), strings.ToLower(in.SHA)) {
		return in, fmt.Errorf("%w: Bitbucket resolved commit mismatch", shared.ErrValidation)
	}
	for _, c := range sha {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return in, fmt.Errorf("%w: Bitbucket resolved commit is invalid", shared.ErrValidation)
		}
	}
	in.SHA, in.ResolvedRepository = strings.ToLower(sha), p.SourceBinding.Value
	return in, nil
}

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
	if in.ResolvedRepository != "" && in.ResolvedRepository != p.SourceBinding.Value {
		return ports.ScanJob{}, fmt.Errorf("%w: Bitbucket source changed during commit resolution", shared.ErrConflict)
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
