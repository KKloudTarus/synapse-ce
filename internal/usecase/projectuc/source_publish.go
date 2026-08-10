package projectuc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const sourcePublishCompensationTimeout = 5 * time.Second

// PublishSourceInput contains only contributor-controlled facts that are safe to accept.
// Tenant and project identity are resolved by the authenticated server path, never from the archive.
type PublishSourceInput struct {
	TenantID    shared.ID
	ProjectKey  string
	AnalysisID  string
	Actor       string
	ToolVersion string
	Archive     io.Reader
}

// PublishSource contributes source bytes to an already-created server-owned analysis.
// It never creates an analysis and never lets the caller choose an artifact namespace.
func (s *Service) PublishSource(ctx context.Context, in PublishSourceInput) (projectanalysis.SourceManifest, error) {
	if err := requireActor(in.Actor); err != nil {
		return projectanalysis.SourceManifest{}, err
	}
	if strings.TrimSpace(in.ProjectKey) == "" || strings.TrimSpace(in.AnalysisID) == "" || strings.TrimSpace(in.ToolVersion) == "" || in.Archive == nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("%w: source publish input is incomplete", shared.ErrValidation)
	}
	if s.analyses == nil || s.sourceArtifacts == nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("%w: source publication is not configured", shared.ErrValidation)
	}
	publisher, ok := s.sourceArtifacts.(ports.ProjectSourceArtifactPublisher)
	if !ok {
		return projectanalysis.SourceManifest{}, fmt.Errorf("%w: source publication is not configured", shared.ErrValidation)
	}
	mutator, ok := s.analyses.(ports.ProjectAnalysisSourceAtomicMutator)
	if !ok {
		return projectanalysis.SourceManifest{}, fmt.Errorf("%w: transactional source publication is not configured", shared.ErrValidation)
	}

	project, err := s.repo.GetByKey(ctx, in.TenantID, in.ProjectKey)
	if err != nil {
		return projectanalysis.SourceManifest{}, err
	}
	analysisID := shared.ID(in.AnalysisID)
	analysis, err := s.analyses.Get(ctx, in.TenantID, project.ID, analysisID)
	if err != nil {
		return projectanalysis.SourceManifest{}, err
	}
	if analysis.TenantID != in.TenantID.String() || analysis.ProjectID != project.ID.String() || analysis.ProjectKey != project.Key {
		return projectanalysis.SourceManifest{}, shared.ErrNotFound
	}
	if !analysis.SourceRevision.Kind.Valid() {
		return projectanalysis.SourceManifest{}, fmt.Errorf("%w: analysis target cannot retain source", shared.ErrValidation)
	}
	if analysis.Capabilities.Source.Available || analysis.SourceManifest.Digest != "" || len(analysis.SourceManifest.Files) != 0 || analysis.SourceManifest.Writer != nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("%w: source snapshot already retained", shared.ErrConflict)
	}

	allowed := make([]string, 0, len(analysis.Snapshot.Nodes))
	for _, node := range analysis.Snapshot.Nodes {
		if node.Kind == measure.NodeFile && sourcepolicy.RetainPath(node.Path) {
			allowed = append(allowed, node.Path)
		}
	}
	// Image scans, a single JAR/archive, and other package-only targets have no scanner-owned
	// source-file inventory. Refuse them here, before the artifact adapter can claim a namespace.
	if len(allowed) == 0 {
		return projectanalysis.SourceManifest{}, fmt.Errorf("%w: analysis target has no retainable source files", shared.ErrValidation)
	}
	now := s.clock.Now().UTC()
	writer := projectanalysis.SourceWriter{Actor: in.Actor, ToolVersion: strings.TrimSpace(in.ToolVersion), PublishedAt: now}
	capture, err := publisher.PublishArchive(ctx, in.TenantID, project.ID, analysis.ID, writer, allowed, in.Archive)
	if err != nil {
		return projectanalysis.SourceManifest{}, err
	}
	audit := ports.AuditEntry{
		Actor:  in.Actor,
		Action: ports.ProjectSourcePublishAuditAction,
		Target: analysis.ID,
		Metadata: map[string]string{
			"project":         project.Key,
			"artifact_digest": capture.Manifest.Digest,
			"tool_version":    writer.ToolVersion,
		},
		At: now,
	}
	if err := mutator.AttachSourceWithAudit(ctx, in.TenantID, project.ID, analysisID, capture, audit); err != nil {
		if errors.Is(err, ports.ErrProjectSourceCommitUncertain) {
			// COMMIT may already be durable. Never destroy bytes that a committed analysis+audit can
			// reference; if the transaction actually rolled back, retention can reap the orphan later.
			return projectanalysis.SourceManifest{}, err
		}
		// The mutator may fail because the request context itself expired. Compensation must still
		// get a short bounded opportunity to remove the artifact that this call just published.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sourcePublishCompensationTimeout)
		cleanupErr := publisher.DiscardPublished(cleanupCtx, in.TenantID, project.ID, analysis.ID)
		cancel()
		if cleanupErr != nil {
			return projectanalysis.SourceManifest{}, errors.Join(err, fmt.Errorf("rollback published artifact: %w", cleanupErr))
		}
		return projectanalysis.SourceManifest{}, err
	}
	return capture.Manifest, nil
}
