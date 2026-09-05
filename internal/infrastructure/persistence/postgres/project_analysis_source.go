package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ProjectAnalysisSourceAtomicMutator = (*ProjectAnalysisStore)(nil)

func (r *ProjectAnalysisStore) AttachSourceWithAudit(ctx context.Context, tenantID, projectID, analysisID shared.ID, capture projectanalysis.SourceCapture, audit ports.AuditEntry) error {
	if tenantID.IsZero() || projectID.IsZero() || analysisID.IsZero() {
		return fmt.Errorf("%w: source attachment scope is required", shared.ErrValidation)
	}
	if err := validatePublishedCapture(capture); err != nil {
		return err
	}
	if err := validateSourcePublishAudit(audit, analysisID, capture); err != nil {
		return err
	}

	// requireTenant owns the transaction so the analysis read, the payload update and the audit
	// append all run under one bound tenant; the audit_log policy needs that binding too.
	err := requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		var payload []byte
		if err := tx.QueryRow(ctx, `SELECT payload FROM project_analyses WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, tenantID.String(), projectID.String(), analysisID.String()).Scan(&payload); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("lock project analysis for source attachment: %w", err)
		}
		var analysis projectanalysis.Analysis
		if err := json.Unmarshal(payload, &analysis); err != nil {
			return fmt.Errorf("decode project analysis for source attachment: %w", err)
		}
		if analysis.Capabilities.Source.Available || analysis.SourceManifest.Digest != "" || len(analysis.SourceManifest.Files) != 0 || analysis.SourceManifest.Writer != nil {
			return shared.ErrConflict
		}
		if err := validateCaptureAgainstAnalysis(analysis, capture.Manifest); err != nil {
			return err
		}

		analysis.SourceManifest = capture.Manifest
		analysis.Capabilities.Source = projectanalysis.Capability{Available: true}
		analysis.Capabilities.Highlighting = projectanalysis.Capability{Available: true}
		updated, err := json.Marshal(analysis)
		if err != nil {
			return fmt.Errorf("marshal project analysis source attachment: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE project_analyses SET payload=$4 WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, tenantID.String(), projectID.String(), analysisID.String(), updated); err != nil {
			return fmt.Errorf("attach project analysis source: %w", err)
		}
		return appendAudit(ctx, tx, audit)
	})
	if err != nil {
		// Once COMMIT has been sent, a transport failure can make its durable outcome unknowable.
		// The caller must not compensate by deleting the artifact: the DB row and audit may already
		// be committed. An orphan is safe to retain and later reap; missing committed bytes are not.
		if errors.Is(err, ErrTenantCommit) {
			return fmt.Errorf("%w: commit project analysis source attachment: %v", ports.ErrProjectSourceCommitUncertain, err)
		}
		return err
	}
	return nil
}

func validatePublishedCapture(capture projectanalysis.SourceCapture) error {
	if !capture.Capabilities.Source.Available {
		return fmt.Errorf("%w: published source capability must be available", shared.ErrValidation)
	}
	if capture.Manifest.Writer == nil {
		return fmt.Errorf("%w: source writer provenance is required", shared.ErrValidation)
	}
	if err := capture.Manifest.Writer.Validate(); err != nil {
		return fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	if capture.Manifest.Digest == "" || capture.Manifest.Digest != capture.Manifest.ArtifactDigest() {
		return fmt.Errorf("%w: source manifest digest is invalid", shared.ErrValidation)
	}
	available := 0
	for _, file := range capture.Manifest.Files {
		if err := file.Validate(); err != nil {
			return fmt.Errorf("%w: %v", shared.ErrValidation, err)
		}
		if file.Available {
			available++
		}
	}
	if available == 0 {
		return fmt.Errorf("%w: published source manifest contains no retained source bytes", shared.ErrValidation)
	}
	return nil
}

func validateSourcePublishAudit(audit ports.AuditEntry, analysisID shared.ID, capture projectanalysis.SourceCapture) error {
	writer := capture.Manifest.Writer
	if writer == nil || audit.Actor != writer.Actor || !audit.At.Equal(writer.PublishedAt) {
		return fmt.Errorf("%w: source audit provenance does not match manifest writer", shared.ErrValidation)
	}
	if audit.Action != ports.ProjectSourcePublishAuditAction || audit.Target != analysisID.String() {
		return fmt.Errorf("%w: source audit action or target is invalid", shared.ErrValidation)
	}
	if audit.Metadata["artifact_digest"] != capture.Manifest.Digest || audit.Metadata["tool_version"] != writer.ToolVersion {
		return fmt.Errorf("%w: source audit metadata does not match manifest", shared.ErrValidation)
	}
	return nil
}

func validateCaptureAgainstAnalysis(analysis projectanalysis.Analysis, manifest projectanalysis.SourceManifest) error {
	allowed := make(map[string]struct{})
	for _, node := range analysis.Snapshot.Nodes {
		if node.Kind == measure.NodeFile && sourcepolicy.RetainPath(node.Path) {
			allowed[node.Path] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		if _, ok := allowed[file.Path]; !ok {
			return fmt.Errorf("%w: published source path is not part of the analysis snapshot", shared.ErrValidation)
		}
		if _, duplicate := seen[file.Path]; duplicate {
			return fmt.Errorf("%w: duplicate published source path", shared.ErrValidation)
		}
		seen[file.Path] = struct{}{}
	}
	return nil
}
