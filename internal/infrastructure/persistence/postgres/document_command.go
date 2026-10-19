package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.DocumentCommandStore = (*DocumentStore)(nil)

const documentCommandCols = `actor_user_id,actor_membership_id,actor_person_id,connection_revision,credential_revision,read_group,artifact,progress,progress_version,created_at,updated_at`

func documentArtifactJSON(artifact ports.DocumentArtifact) ([]byte, string, error) {
	if artifact.GeneratedAt.IsZero() || strings.TrimSpace(artifact.Title) == "" || strings.TrimSpace(artifact.SourceRevision) == "" || len(artifact.PDF) == 0 || len(artifact.PDF) > 10<<20 {
		return nil, "", shared.ErrValidation
	}
	encoded, err := json.Marshal(artifact)
	if err != nil || len(encoded) > 32<<20 {
		return nil, "", shared.ErrValidation
	}
	imageBytes := 0
	for _, image := range artifact.Images {
		if strings.TrimSpace(image.Name) == "" || strings.TrimSpace(image.MediaType) == "" || len(image.Data) == 0 {
			return nil, "", shared.ErrValidation
		}
		imageBytes += len(image.Data)
	}
	if imageBytes > 10<<20 {
		return nil, "", shared.ErrValidation
	}
	sum := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(sum[:]), nil
}

func validateDocumentCommand(command ports.DocumentCommand) ([]byte, error) {
	if err := command.Intent.Validate(); err != nil || command.Intent.State != writeintent.Pending || command.Intent.Version != 1 || command.Intent.Attempts != 0 || command.Intent.LeaseUntil != nil || command.Actor.UserID.IsZero() || command.ConnectionRevision < 1 || command.CredentialRevision < 0 || strings.TrimSpace(command.ReadGroup) == "" || len(command.ReadGroup) > 255 {
		return nil, shared.ErrValidation
	}
	if command.Intent.Action == docpublish.Purge {
		return json.Marshal(ports.DocumentArtifact{})
	}
	artifact, _, err := documentArtifactJSON(command.Artifact)
	return artifact, err
}

func commandProgressJSON(progress ports.DocumentProgress) ([]byte, error) {
	if progress.Version < 1 || progress.UpdatedAt.IsZero() || progress.Uploaded < 0 || len(progress.UploadedReceipts) > 256 {
		return nil, shared.ErrValidation
	}
	for _, receipt := range progress.UploadedReceipts {
		if strings.TrimSpace(receipt.Key) == "" || len(receipt.Key) > 512 || len(receipt.Digest) != 64 {
			return nil, shared.ErrValidation
		}
	}
	data, err := json.Marshal(progress)
	if err != nil || len(data) > 1<<20 {
		return nil, shared.ErrValidation
	}
	return data, nil
}

func scanDocumentCommand(ctx context.Context, tx pgx.Tx, tenant, intentID shared.ID) (ports.DocumentCommand, error) {
	var command ports.DocumentCommand
	var artifact, progress []byte
	var progressVersion int
	err := tx.QueryRow(ctx, `SELECT `+documentCommandCols+` FROM document_commands WHERE tenant_id=$1 AND intent_id=$2`, tenant.String(), intentID.String()).Scan(
		&command.Actor.UserID, &command.Actor.MembershipID, &command.Actor.PersonID, &command.ConnectionRevision, &command.CredentialRevision, &command.ReadGroup, &artifact, &progress, &progressVersion, &command.Intent.CreatedAt, &command.Intent.UpdatedAt)
	if err != nil {
		return ports.DocumentCommand{}, err
	}
	if err = json.Unmarshal(artifact, &command.Artifact); err != nil {
		return ports.DocumentCommand{}, err
	}
	if err = json.Unmarshal(progress, &command.Progress); err != nil {
		return ports.DocumentCommand{}, err
	}
	command.Progress.Version = progressVersion
	intent, err := scanDocumentIntent(tx.QueryRow(ctx, `SELECT `+documentIntentCols+` FROM document_intents WHERE tenant_id=$1 AND id=$2`, tenant.String(), intentID.String()))
	if err != nil {
		return ports.DocumentCommand{}, err
	}
	command.Intent = intent
	return command, nil
}

func sameStoredDocumentCommand(existing, requested ports.DocumentCommand) bool {
	_, existingDigest, existingErr := documentArtifactJSON(existing.Artifact)
	_, requestedDigest, requestedErr := documentArtifactJSON(requested.Artifact)
	if existing.Intent.Action == docpublish.Purge && requested.Intent.Action == docpublish.Purge {
		existingErr, requestedErr, existingDigest, requestedDigest = nil, nil, "", ""
	}
	return existingErr == nil && requestedErr == nil && existing.Intent.SameCommand(requested.Intent) && existing.Actor == requested.Actor && existing.ConnectionRevision == requested.ConnectionRevision && existing.CredentialRevision == requested.CredentialRevision && existing.ReadGroup == requested.ReadGroup && existingDigest == requestedDigest
}

func documentTargetLock(ctx context.Context, tx pgx.Tx, tenant shared.ID, target docpublish.Target) error {
	key := strings.Join([]string{tenant.String(), target.IntegrationID.String(), string(target.SourceKind), target.SourceRef, string(target.Scope), target.ScopeID.String(), target.Container}, "\x1f")
	return tx.QueryRow(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key).Scan(new(any))
}

func documentActiveFence(ctx context.Context, tx pgx.Tx, tenant shared.ID, target docpublish.Target) error {
	engagement, project := documentScopeArgs(target)
	var found string
	err := tx.QueryRow(ctx, `SELECT i.id FROM document_intents i
        LEFT JOIN document_commands c ON c.tenant_id=i.tenant_id AND c.intent_id=i.id
        WHERE i.tenant_id=$1 AND i.integration_id=$2 AND i.source_kind=$3 AND i.source_ref=$4 AND i.container=$5
          AND i.engagement_id IS NOT DISTINCT FROM $6 AND i.project_id IS NOT DISTINCT FROM $7
          AND (i.state IN ('pending','in_flight','uncertain') OR (i.state='failed' AND COALESCE(c.progress->'Remote'->>'ID','')<>''))
        FOR UPDATE OF i LIMIT 1`, tenant.String(), target.IntegrationID.String(), string(target.SourceKind), target.SourceRef, target.Container, engagement, project).Scan(&found)
	if err == nil {
		return shared.ErrConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

func (s *DocumentStore) withDocumentTx(ctx context.Context, tenant shared.ID, fn func(pgx.Tx) error) error {
	if tx, bound, err := contextTenantTx(ctx, tenant); bound {
		if err != nil {
			return err
		}
		return fn(tx)
	}
	return requireTenant(ctx, s.pool, tenant, fn)
}

func (s *DocumentStore) CreateDocumentCommand(ctx context.Context, tenant shared.ID, command ports.DocumentCommand) (ports.DocumentCommand, bool, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentCommand{}, false, err
	}
	artifact, err := validateDocumentCommand(command)
	if tenant.IsZero() || command.Intent.TenantID != tenant || err != nil {
		return ports.DocumentCommand{}, false, shared.ErrValidation
	}
	var out ports.DocumentCommand
	created := false
	err = s.withDocumentTx(ctx, tenant, func(tx pgx.Tx) error {
		var intentID shared.ID
		e := tx.QueryRow(ctx, `SELECT id FROM document_intents WHERE tenant_id=$1 AND integration_id=$2 AND request_key=$3`, tenant.String(), command.Intent.IntegrationID.String(), command.Intent.RequestKey).Scan(&intentID)
		if e == nil {
			stored, readErr := scanDocumentCommand(ctx, tx, tenant, intentID)
			if readErr != nil || !sameStoredDocumentCommand(stored, command) {
				return shared.ErrConflict
			}
			out = stored
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e = documentTargetLock(ctx, tx, tenant, command.Intent.Target); e != nil {
			return e
		}
		if e = documentActiveFence(ctx, tx, tenant, command.Intent.Target); e != nil {
			return e
		}
		var link docpublish.Link
		link, e = selectDocumentLinkByTarget(ctx, tx, tenant, command.Intent.Target, "FOR KEY SHARE")
		progress := ports.DocumentProgress{Version: 1, IntentVersion: command.Intent.Version, Step: "shell", UpdatedAt: command.Intent.CreatedAt}
		switch command.Intent.Action {
		case docpublish.Create:
			if e == nil {
				return shared.ErrConflict
			}
			if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
		case docpublish.Update, docpublish.Purge:
			if errors.Is(e, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			if e != nil {
				return e
			}
			if link.ID != command.Intent.LinkID || link.RetiredAt != nil {
				return shared.ErrConflict
			}
			progress.Remote = docpublish.RemotePage{ID: link.RemotePageID, Version: link.RemoteVersion, URL: link.RemoteURL}
			if command.Intent.Action == docpublish.Update {
				progress.Step = "restrictions"
			} else {
				progress.Step = "purge"
			}
		}
		progressJSON, e := commandProgressJSON(progress)
		if e != nil {
			return e
		}
		engagement, project := documentScopeArgs(command.Intent.Target)
		var linkID any
		if !command.Intent.LinkID.IsZero() {
			linkID = command.Intent.LinkID.String()
		}
		_, e = tx.Exec(ctx, `INSERT INTO document_intents(id,tenant_id,integration_id,source_kind,source_ref,engagement_id,project_id,container,link_id,action,request_key,payload_digest,content_hash,correlation_marker,state,version,attempts,remote_id,remote_url,remote_version,error_code,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'pending',1,0,'','',0,'',$15,$16)`, command.Intent.ID.String(), tenant.String(), command.Intent.IntegrationID.String(), string(command.Intent.SourceKind), command.Intent.SourceRef, engagement, project, command.Intent.Container, linkID, string(command.Intent.Action), command.Intent.RequestKey, command.Intent.PayloadDigest, command.Intent.ContentHash, command.Intent.Marker, command.Intent.CreatedAt.UTC(), command.Intent.UpdatedAt.UTC())
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO document_commands(tenant_id,intent_id,actor_user_id,actor_membership_id,actor_person_id,connection_revision,credential_revision,read_group,artifact,progress,progress_version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12)`, tenant.String(), command.Intent.ID.String(), command.Actor.UserID.String(), command.Actor.MembershipID.String(), command.Actor.PersonID.String(), command.ConnectionRevision, command.CredentialRevision, command.ReadGroup, artifact, progressJSON, command.Intent.CreatedAt.UTC(), command.Intent.UpdatedAt.UTC())
		if e != nil {
			return e
		}
		out, e = scanDocumentCommand(ctx, tx, tenant, command.Intent.ID)
		created = e == nil
		return e
	})
	if err != nil {
		return ports.DocumentCommand{}, false, documentWriteError(err)
	}
	return out, created, nil
}

func (s *DocumentStore) GetDocumentCommand(ctx context.Context, tenant, intentID shared.ID) (ports.DocumentCommand, error) {
	if tenant.IsZero() || intentID.IsZero() {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	var out ports.DocumentCommand
	err := s.withDocumentTx(ctx, tenant, func(tx pgx.Tx) error { var e error; out, e = scanDocumentCommand(ctx, tx, tenant, intentID); return e })
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.DocumentCommand{}, shared.ErrNotFound
	}
	return out, documentWriteError(err)
}

func (s *DocumentStore) FindDocumentCommand(ctx context.Context, tenant, integrationID shared.ID, requestKey string) (ports.DocumentCommand, error) {
	if tenant.IsZero() || integrationID.IsZero() || strings.TrimSpace(requestKey) == "" {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	var out ports.DocumentCommand
	err := s.withDocumentTx(ctx, tenant, func(tx pgx.Tx) error {
		var id shared.ID
		if e := tx.QueryRow(ctx, `SELECT id FROM document_intents WHERE tenant_id=$1 AND integration_id=$2 AND request_key=$3`, tenant.String(), integrationID.String(), requestKey).Scan(&id); e != nil {
			return e
		}
		var e error
		out, e = scanDocumentCommand(ctx, tx, tenant, id)
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.DocumentCommand{}, shared.ErrNotFound
	}
	return out, documentWriteError(err)
}

func (s *DocumentStore) SaveDocumentProgress(ctx context.Context, tenant, intentID shared.ID, expected int, progress ports.DocumentProgress) (ports.DocumentCommand, error) {
	if tenant.IsZero() || intentID.IsZero() || expected < 1 {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	var out ports.DocumentCommand
	err := s.withDocumentTx(ctx, tenant, func(tx pgx.Tx) error {
		intent, e := scanDocumentIntent(tx.QueryRow(ctx, `SELECT `+documentIntentCols+` FROM document_intents WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant.String(), intentID.String()))
		if e != nil {
			return e
		}
		if intent.State != writeintent.InFlight || progress.IntentVersion != intent.Version || intent.LeaseUntil == nil || progress.LeaseUntil == nil || !progress.LeaseUntil.Equal(*intent.LeaseUntil) {
			return shared.ErrConflict
		}
		data, e := commandProgressJSON(progress)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE document_commands SET progress=$3,progress_version=progress_version+1,updated_at=$4 WHERE tenant_id=$1 AND intent_id=$2 AND progress_version=$5`, tenant.String(), intentID.String(), data, progress.UpdatedAt.UTC(), expected)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrConflict
		}
		out, e = scanDocumentCommand(ctx, tx, tenant, intentID)
		return e
	})
	return out, documentWriteError(err)
}

func (s *DocumentStore) ResumeDocumentCommand(ctx context.Context, tenant, intentID shared.ID, expectedIntent, expectedProgress int, progress ports.DocumentProgress, at time.Time) (ports.DocumentCommand, error) {
	if tenant.IsZero() || intentID.IsZero() || expectedIntent < 1 || expectedProgress < 1 || at.IsZero() {
		return ports.DocumentCommand{}, shared.ErrValidation
	}
	var out ports.DocumentCommand
	err := s.withDocumentTx(ctx, tenant, func(tx pgx.Tx) error {
		intent, e := scanDocumentIntent(tx.QueryRow(ctx, `SELECT `+documentIntentCols+` FROM document_intents WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant.String(), intentID.String()))
		if e != nil {
			return e
		}
		if intent.Version != expectedIntent || intent.State != writeintent.Uncertain {
			return shared.ErrConflict
		}
		next, e := intent.Apply(docpublish.IntentTransition{Event: docpublish.ReconcileResumable, Resumable: true}, at)
		if e != nil {
			return e
		}
		progress.IntentVersion = next.Version
		progress.LeaseUntil = nil
		progress.UpdatedAt = at.UTC()
		data, e := commandProgressJSON(progress)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE document_commands SET progress=$3,progress_version=progress_version+1,updated_at=$4 WHERE tenant_id=$1 AND intent_id=$2 AND progress_version=$5`, tenant.String(), intentID.String(), data, at.UTC(), expectedProgress)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrConflict
		}
		_, e = tx.Exec(ctx, `UPDATE document_intents SET state=$3,version=$4,attempts=$5,lease_until=NULL,remote_id='',remote_url='',remote_version=0,error_code='',updated_at=$6 WHERE tenant_id=$1 AND id=$2 AND version=$7`, tenant.String(), intentID.String(), string(next.State), next.Version, next.Attempts, next.UpdatedAt, expectedIntent)
		if e != nil {
			return e
		}
		out, e = scanDocumentCommand(ctx, tx, tenant, intentID)
		return e
	})
	return out, documentWriteError(err)
}

func (s *DocumentStore) ListDocumentCommands(ctx context.Context, tenant shared.ID, limit int, at time.Time) ([]ports.DocumentCommand, error) {
	if tenant.IsZero() || limit < 1 || limit > docpublish.MaxListLimit || at.IsZero() {
		return nil, shared.ErrValidation
	}
	out := make([]ports.DocumentCommand, 0, limit)
	err := s.withDocumentTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `WITH selected AS (
            SELECT c.intent_id FROM document_commands c JOIN document_intents i ON i.tenant_id=c.tenant_id AND i.id=c.intent_id
            WHERE c.tenant_id=$1 AND (i.state='pending' OR i.state='uncertain' OR (i.state='failed' AND i.attempts<5) OR (i.state='in_flight' AND i.lease_until<=$3))
            ORDER BY c.checked_at NULLS FIRST,c.check_version,c.intent_id FOR UPDATE OF c SKIP LOCKED LIMIT $2
        ) UPDATE document_commands c SET checked_at=$3,check_version=c.check_version+1
          FROM selected s WHERE c.tenant_id=$1 AND c.intent_id=s.intent_id RETURNING c.intent_id`, tenant.String(), limit, at.UTC())
		if e != nil {
			return e
		}
		ids := make([]shared.ID, 0, limit)
		for rows.Next() {
			var id shared.ID
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return e
		}
		rows.Close()
		for _, id := range ids {
			item, e := scanDocumentCommand(ctx, tx, tenant, id)
			if e != nil {
				return e
			}
			out = append(out, item)
		}
		return nil
	})
	return out, documentWriteError(err)
}
