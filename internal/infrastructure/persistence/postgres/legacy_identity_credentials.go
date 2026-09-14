package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const legacyCredentialCols = `tenant_id,id,user_id,membership_id,person_id,classification,digest,status,classification_reason,version,source_updated_at,classified_at,updated_at`

// LegacyCredentialRepository owns the D5 derived bearer projection. The legacy users row remains
// authoritative until read cutover; this repository always re-reads it under the tenant transaction
// before changing the projection or the global exact-hash locator.
type LegacyCredentialRepository struct{ pool *pgxpool.Pool }

func NewLegacyCredentialRepository(pool *pgxpool.Pool) (*LegacyCredentialRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: legacy credential repository requires pool", shared.ErrValidation)
	}
	return &LegacyCredentialRepository{pool: pool}, nil
}

var _ ports.LegacyCredentialProjectionStore = (*LegacyCredentialRepository)(nil)

func (repository *LegacyCredentialRepository) ClassifyAndProjectLegacyCredential(ctx context.Context, tenantID, userID shared.ID, at time.Time) (projection ports.LegacyCredentialProjection, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	at = at.UTC()
	if tenantID.IsZero() || userID.IsZero() || userID.String() == "operator" || at.IsZero() {
		return projection, fmt.Errorf("%w: legacy credential classification input is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		source, sourceErr := lockLegacyCredentialSource(ctx, tx, tenantID, userID)
		if sourceErr != nil {
			return sourceErr
		}
		membershipID, personID, membershipErr := requireLegacyCredentialMembership(ctx, tx, tenantID, userID)
		if membershipErr != nil {
			return membershipErr
		}

		classification, reason, classifyErr := classifyLegacyCredentialEvidence(ctx, tx, tenantID, userID)
		if classifyErr != nil {
			return classifyErr
		}
		projection, classifyErr = upsertLegacyCredentialProjection(ctx, tx, source, membershipID, personID, classification, reason, at)
		return classifyErr
	})
	return projection, err
}

func (repository *LegacyCredentialRepository) SyncIssuedLegacyCredential(ctx context.Context, request ports.LegacyCredentialSyncRequest) (projection ports.LegacyCredentialProjection, projected bool, err error) {
	request.TenantID = shared.TenantOrDefault(request.TenantID)
	request.At = request.At.UTC()
	if err := validateLegacyCredentialSync(request); err != nil {
		return projection, false, err
	}
	err = WithTenant(ctx, repository.pool, request.TenantID.String(), func(tx pgx.Tx) error {
		source, sourceErr := lockLegacyCredentialSource(ctx, tx, request.TenantID, request.UserID)
		if sourceErr != nil {
			return sourceErr
		}
		if source.Digest != request.Digest || source.Disabled != request.Disabled {
			return fmt.Errorf("%w: authoritative legacy credential changed before projection", shared.ErrConflict)
		}
		existing, existingErr := getLegacyCredentialForUpdate(ctx, tx, request.TenantID, request.UserID)
		if errors.Is(existingErr, pgx.ErrNoRows) {
			// Rotation may race the offline classifier. The source write remains authoritative and
			// the later classifier observes its durable user.api_key_hash plus rotation audit.
			return nil
		}
		if existingErr != nil {
			return existingErr
		}
		projection, existingErr = writeLegacyCredentialProjection(ctx, tx, existing, source, ports.LegacyCredentialIssued, "writer_issued", request.At)
		if existingErr == nil {
			projected = true
		}
		return existingErr
	})
	return projection, projected, err
}

func (repository *LegacyCredentialRepository) SyncLegacyCredentialDisabled(ctx context.Context, request ports.LegacyCredentialSyncRequest) (projection ports.LegacyCredentialProjection, projected bool, err error) {
	request.TenantID = shared.TenantOrDefault(request.TenantID)
	request.At = request.At.UTC()
	if err := validateLegacyCredentialSync(request); err != nil {
		return projection, false, err
	}
	err = WithTenant(ctx, repository.pool, request.TenantID.String(), func(tx pgx.Tx) error {
		source, sourceErr := lockLegacyCredentialSource(ctx, tx, request.TenantID, request.UserID)
		if sourceErr != nil {
			return sourceErr
		}
		if source.Digest != request.Digest || source.Disabled != request.Disabled {
			return fmt.Errorf("%w: authoritative legacy credential changed before disable projection", shared.ErrConflict)
		}
		existing, existingErr := getLegacyCredentialForUpdate(ctx, tx, request.TenantID, request.UserID)
		if errors.Is(existingErr, pgx.ErrNoRows) {
			return nil
		}
		if existingErr != nil {
			return existingErr
		}
		projection, existingErr = writeLegacyCredentialProjection(ctx, tx, existing, source, existing.Classification, existing.ClassificationReason, request.At)
		if existingErr == nil {
			projected = true
		}
		return existingErr
	})
	return projection, projected, err
}

func (repository *LegacyCredentialRepository) ResolveLegacyCredentialClassification(ctx context.Context, request ports.LegacyCredentialResolutionRequest) (projection ports.LegacyCredentialProjection, err error) {
	request.TenantID = shared.TenantOrDefault(request.TenantID)
	request.Reason = strings.TrimSpace(request.Reason)
	request.Actor = strings.TrimSpace(request.Actor)
	request.At = request.At.UTC()
	if request.TenantID.IsZero() || request.ResolutionID.IsZero() || request.UserID.IsZero() || request.UserID.String() == "operator" ||
		(request.Resolution != ports.LegacyCredentialIssued && request.Resolution != ports.LegacyCredentialPlaceholder) || request.ExpectedVersion <= 0 ||
		request.Reason == "" || len(request.Reason) > 1024 || request.Actor == "" || len(request.Actor) > 256 || request.At.IsZero() {
		return projection, fmt.Errorf("%w: legacy credential resolution is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, request.TenantID.String(), func(tx pgx.Tx) error {
		source, sourceErr := lockLegacyCredentialSource(ctx, tx, request.TenantID, request.UserID)
		if sourceErr != nil {
			return sourceErr
		}
		existing, existingErr := getLegacyCredentialForUpdate(ctx, tx, request.TenantID, request.UserID)
		if existingErr != nil {
			if errors.Is(existingErr, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return existingErr
		}
		if existing.Classification != ports.LegacyCredentialAmbiguous || existing.Version != request.ExpectedVersion {
			return fmt.Errorf("%w: legacy credential classification is no longer the expected ambiguous version", shared.ErrConflict)
		}
		if _, insertErr := tx.Exec(ctx, `INSERT INTO legacy_credential_resolutions
			(tenant_id,id,user_id,resolution,expected_version,reason,actor,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			request.TenantID.String(), request.ResolutionID.String(), request.UserID.String(), string(request.Resolution), request.ExpectedVersion,
			request.Reason, request.Actor, request.At); insertErr != nil {
			return fmt.Errorf("record legacy credential resolution: %w", insertErr)
		}
		projection, existingErr = writeLegacyCredentialProjection(ctx, tx, existing, source, request.Resolution, "administrator_resolution", request.At)
		return existingErr
	})
	return projection, err
}

func (repository *LegacyCredentialRepository) GetLegacyCredentialProjection(ctx context.Context, tenantID, userID shared.ID) (projection ports.LegacyCredentialProjection, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || userID.IsZero() {
		return projection, fmt.Errorf("%w: legacy credential lookup is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var scanErr error
		projection, scanErr = scanLegacyCredentialProjection(tx.QueryRow(ctx, `SELECT `+legacyCredentialCols+` FROM legacy_human_credentials WHERE tenant_id=$1 AND user_id=$2`, tenantID.String(), userID.String()))
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return projection, shared.ErrNotFound
	}
	if err != nil {
		return projection, fmt.Errorf("get legacy credential projection: %w", err)
	}
	return projection, nil
}

func (repository *LegacyCredentialRepository) ReconcileLegacyCredentials(ctx context.Context, tenantID shared.ID) (reconciliation ports.LegacyCredentialReconciliation, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() {
		return reconciliation, fmt.Errorf("%w: legacy credential reconciliation tenant is required", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `WITH source AS (
			SELECT id,api_key_hash,disabled,updated_at FROM users WHERE ownership_tenant_id=$1 AND id<>'operator'
		), joined AS (
			SELECT s.*, c.id AS credential_id,c.classification,c.digest,c.status,c.source_updated_at
			FROM source s LEFT JOIN legacy_human_credentials c ON c.tenant_id=$1 AND c.user_id=s.id
		)
		SELECT
			count(*)::int,
			count(credential_id)::int,
			count(*) FILTER (WHERE classification='issued')::int,
			count(*) FILTER (WHERE classification='placeholder')::int,
			count(*) FILTER (WHERE classification='ambiguous')::int,
			count(*) FILTER (WHERE credential_id IS NULL)::int,
			count(*) FILTER (WHERE credential_id IS NOT NULL AND (
				source_updated_at<>updated_at OR
				(classification='issued' AND (digest<>api_key_hash OR status<>CASE WHEN disabled THEN 'disabled' ELSE 'active' END)) OR
				(classification IN ('placeholder','ambiguous') AND (digest IS NOT NULL OR status<>'unavailable'))
			))::int,
			(SELECT count(*)::int FROM legacy_human_credentials c
			 LEFT JOIN credential_index i ON i.digest=c.digest AND i.organization_id=c.tenant_id AND i.credential_kind='legacy_api_key' AND i.credential_id=c.id
			 WHERE c.tenant_id=$1 AND ((c.classification='issued' AND i.digest IS NULL) OR (c.classification<>'issued' AND EXISTS (
				SELECT 1 FROM credential_index x WHERE x.organization_id=c.tenant_id AND x.credential_kind='legacy_api_key' AND x.credential_id=c.id
			 ))))
		FROM joined`, tenantID.String()).Scan(
			&reconciliation.SourceCount, &reconciliation.ProjectedCount, &reconciliation.IssuedCount, &reconciliation.PlaceholderCount,
			&reconciliation.AmbiguousCount, &reconciliation.MissingCount, &reconciliation.DriftCount, &reconciliation.IndexDriftCount)
	})
	if err != nil {
		return reconciliation, fmt.Errorf("reconcile legacy credentials: %w", err)
	}
	return reconciliation, nil
}

type lockedLegacyCredentialSource struct {
	TenantID  shared.ID
	UserID    shared.ID
	Digest    string
	Disabled  bool
	UpdatedAt time.Time
}

func lockLegacyCredentialSource(ctx context.Context, tx pgx.Tx, tenantID, userID shared.ID) (source lockedLegacyCredentialSource, err error) {
	source.TenantID, source.UserID = tenantID, userID
	err = tx.QueryRow(ctx, `SELECT api_key_hash,disabled,updated_at FROM users WHERE ownership_tenant_id=$1 AND id=$2 AND id<>'operator' FOR SHARE`, tenantID.String(), userID.String()).
		Scan(&source.Digest, &source.Disabled, &source.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return source, shared.ErrNotFound
	}
	if err != nil {
		return source, fmt.Errorf("lock authoritative legacy credential: %w", err)
	}
	if !validCredentialDigest(source.Digest) {
		return source, fmt.Errorf("%w: authoritative legacy credential digest is corrupt", shared.ErrValidation)
	}
	return source, nil
}

func requireLegacyCredentialMembership(ctx context.Context, tx pgx.Tx, tenantID, userID shared.ID) (membershipID, personID shared.ID, err error) {
	err = tx.QueryRow(ctx, `SELECT id,person_id FROM memberships WHERE tenant_id=$1 AND id=$2 AND person_id=$2 AND status IN ('active','suspended')`, tenantID.String(), userID.String()).Scan(&membershipID, &personID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", fmt.Errorf("%w: legacy membership projection is required before credential classification", shared.ErrConflict)
	}
	if err != nil {
		return "", "", fmt.Errorf("read legacy credential membership: %w", err)
	}
	return membershipID, personID, nil
}

func classifyLegacyCredentialEvidence(ctx context.Context, tx pgx.Tx, tenantID, userID shared.ID) (ports.LegacyCredentialClassification, string, error) {
	var resolution string
	resolutionErr := tx.QueryRow(ctx, `SELECT resolution FROM legacy_credential_resolutions WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, tenantID.String(), userID.String()).Scan(&resolution)
	if resolutionErr == nil {
		switch ports.LegacyCredentialClassification(resolution) {
		case ports.LegacyCredentialIssued:
			return ports.LegacyCredentialIssued, "administrator_resolution", nil
		case ports.LegacyCredentialPlaceholder:
			return ports.LegacyCredentialPlaceholder, "administrator_resolution", nil
		default:
			return "", "", fmt.Errorf("decode legacy credential resolution: %w", shared.ErrValidation)
		}
	}
	if !errors.Is(resolutionErr, pgx.ErrNoRows) {
		return "", "", fmt.Errorf("read legacy credential resolution: %w", resolutionErr)
	}

	var issued, oidcLinked bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_log WHERE tenant_id=$1 AND target=$2 AND action IN ('user.created','user.api_key_rotated'))`, tenantID.String(), userID.String()).Scan(&issued); err != nil {
		return "", "", fmt.Errorf("read legacy credential issuance evidence: %w", err)
	}
	if issued {
		return ports.LegacyCredentialIssued, "durable_issuance_audit", nil
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oidc_external_identities WHERE tenant_id=$1 AND user_id=$2)`, tenantID.String(), userID.String()).Scan(&oidcLinked); err != nil {
		return "", "", fmt.Errorf("read legacy OIDC placeholder evidence: %w", err)
	}
	if oidcLinked {
		return ports.LegacyCredentialPlaceholder, "oidc_without_issuance_evidence", nil
	}
	return ports.LegacyCredentialAmbiguous, "missing_durable_issuance_evidence", nil
}

func upsertLegacyCredentialProjection(ctx context.Context, tx pgx.Tx, source lockedLegacyCredentialSource, membershipID, personID shared.ID, classification ports.LegacyCredentialClassification, reason string, at time.Time) (ports.LegacyCredentialProjection, error) {
	existing, err := getLegacyCredentialForUpdate(ctx, tx, source.TenantID, source.UserID)
	if err == nil {
		if existing.Classification == ports.LegacyCredentialIssued && classification != ports.LegacyCredentialIssued && existing.Digest != source.Digest {
			return ports.LegacyCredentialProjection{}, fmt.Errorf("%w: issued credential source changed outside the one-writer projection path", shared.ErrConflict)
		}
		return writeLegacyCredentialProjection(ctx, tx, existing, source, classification, reason, at)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ports.LegacyCredentialProjection{}, err
	}

	projection := ports.LegacyCredentialProjection{
		TenantID: source.TenantID, ID: source.UserID, UserID: source.UserID, MembershipID: membershipID, PersonID: personID,
		Classification: classification, ClassificationReason: reason, Version: 1, SourceUpdatedAt: source.UpdatedAt.UTC(), ClassifiedAt: at, UpdatedAt: at,
	}
	applyLegacyCredentialMaterial(&projection, source)
	if err := replaceLegacyCredentialLocator(ctx, tx, projection); err != nil {
		return ports.LegacyCredentialProjection{}, err
	}
	var digest any
	if projection.Digest != "" {
		digest = projection.Digest
	}
	_, err = tx.Exec(ctx, `INSERT INTO legacy_human_credentials
		(tenant_id,id,user_id,membership_id,person_id,classification,digest,status,classification_reason,version,source_updated_at,classified_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$11)`,
		projection.TenantID.String(), projection.ID.String(), projection.UserID.String(), projection.MembershipID.String(), projection.PersonID.String(),
		string(projection.Classification), digest, string(projection.Status), projection.ClassificationReason, projection.SourceUpdatedAt, at)
	if err != nil {
		return ports.LegacyCredentialProjection{}, mapLegacyCredentialWriteError("insert legacy credential projection", err)
	}
	return projection, nil
}

func writeLegacyCredentialProjection(ctx context.Context, tx pgx.Tx, existing ports.LegacyCredentialProjection, source lockedLegacyCredentialSource, classification ports.LegacyCredentialClassification, reason string, at time.Time) (ports.LegacyCredentialProjection, error) {
	if existing.TenantID != source.TenantID || existing.UserID != source.UserID {
		return ports.LegacyCredentialProjection{}, fmt.Errorf("%w: legacy credential projection ownership mismatch", shared.ErrConflict)
	}
	updated := existing
	updated.Classification = classification
	updated.ClassificationReason = reason
	updated.SourceUpdatedAt = source.UpdatedAt.UTC()
	updated.UpdatedAt = at
	if classification != existing.Classification {
		updated.ClassifiedAt = at
	}
	updated.Version++
	applyLegacyCredentialMaterial(&updated, source)
	if err := replaceLegacyCredentialLocator(ctx, tx, updated); err != nil {
		return ports.LegacyCredentialProjection{}, err
	}
	var digest any
	if updated.Digest != "" {
		digest = updated.Digest
	}
	row := tx.QueryRow(ctx, `UPDATE legacy_human_credentials SET classification=$4,digest=$5,status=$6,classification_reason=$7,version=version+1,
		source_updated_at=$8,classified_at=$9,updated_at=$10 WHERE tenant_id=$1 AND id=$2 AND version=$3 RETURNING `+legacyCredentialCols,
		updated.TenantID.String(), updated.ID.String(), existing.Version, string(updated.Classification), digest, string(updated.Status), updated.ClassificationReason,
		updated.SourceUpdatedAt, updated.ClassifiedAt, updated.UpdatedAt)
	projection, err := scanLegacyCredentialProjection(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.LegacyCredentialProjection{}, fmt.Errorf("%w: legacy credential projection version changed", shared.ErrConflict)
	}
	if err != nil {
		return ports.LegacyCredentialProjection{}, mapLegacyCredentialWriteError("update legacy credential projection", err)
	}
	return projection, nil
}

func applyLegacyCredentialMaterial(projection *ports.LegacyCredentialProjection, source lockedLegacyCredentialSource) {
	if projection.Classification != ports.LegacyCredentialIssued {
		projection.Digest = ""
		projection.Status = ports.LegacyCredentialUnavailable
		return
	}
	projection.Digest = source.Digest
	projection.Status = ports.LegacyCredentialActive
	if source.Disabled {
		projection.Status = ports.LegacyCredentialDisabled
	}
}

func replaceLegacyCredentialLocator(ctx context.Context, tx pgx.Tx, projection ports.LegacyCredentialProjection) error {
	if _, err := tx.Exec(ctx, `DELETE FROM credential_index WHERE organization_id=$1 AND credential_kind='legacy_api_key' AND credential_id=$2`, projection.TenantID.String(), projection.ID.String()); err != nil {
		return fmt.Errorf("delete previous legacy credential locator: %w", err)
	}
	if projection.Classification != ports.LegacyCredentialIssued {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credential_index(digest,organization_id,credential_kind,credential_id) VALUES($1,$2,'legacy_api_key',$3)`, projection.Digest, projection.TenantID.String(), projection.ID.String()); err != nil {
		return mapLegacyCredentialWriteError("insert legacy credential locator", err)
	}
	return nil
}

func getLegacyCredentialForUpdate(ctx context.Context, tx pgx.Tx, tenantID, userID shared.ID) (ports.LegacyCredentialProjection, error) {
	return scanLegacyCredentialProjection(tx.QueryRow(ctx, `SELECT `+legacyCredentialCols+` FROM legacy_human_credentials WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, tenantID.String(), userID.String()))
}

func scanLegacyCredentialProjection(row rowScanner) (projection ports.LegacyCredentialProjection, err error) {
	var classification, status string
	var digest *string
	err = row.Scan(&projection.TenantID, &projection.ID, &projection.UserID, &projection.MembershipID, &projection.PersonID,
		&classification, &digest, &status, &projection.ClassificationReason, &projection.Version, &projection.SourceUpdatedAt, &projection.ClassifiedAt, &projection.UpdatedAt)
	if err != nil {
		return projection, err
	}
	projection.Classification = ports.LegacyCredentialClassification(classification)
	projection.Status = ports.LegacyCredentialStatus(status)
	if digest != nil {
		projection.Digest = *digest
	}
	return projection, nil
}

func validateLegacyCredentialSync(request ports.LegacyCredentialSyncRequest) error {
	if request.TenantID.IsZero() || request.UserID.IsZero() || request.UserID.String() == "operator" || !validCredentialDigest(request.Digest) || request.At.IsZero() {
		return fmt.Errorf("%w: legacy credential sync request is invalid", shared.ErrValidation)
	}
	return nil
}

func validCredentialDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func mapLegacyCredentialWriteError(operation string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("%s: %w", operation, shared.ErrConflict)
		case "23503":
			return fmt.Errorf("%s: %w", operation, shared.ErrForbidden)
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}
