package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DocumentStore is the durable documentation-publishing adapter; it does not use
// integration_operations, integration_bindings, the CI scheduler or a notification delivery.
type DocumentStore struct{ pool *pgxpool.Pool }

func NewDocumentStore(pool *pgxpool.Pool) (*DocumentStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: document store requires a PostgreSQL pool", shared.ErrValidation)
	}
	return &DocumentStore{pool: pool}, nil
}

var _ ports.DocumentStore = (*DocumentStore)(nil)

func documentWriteError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return shared.ErrConflict
		case "23503":
			return shared.ErrNotFound
		}
	}
	return err
}

const documentLinkCols = `id,tenant_id,integration_id,source_kind,source_ref,COALESCE(engagement_id,''),COALESCE(project_id,''),
    container,remote_page_id,remote_version,remote_url,content_hash,revision,retired_at,created_at,updated_at`

const documentIntentCols = `id,tenant_id,integration_id,source_kind,source_ref,COALESCE(engagement_id,''),COALESCE(project_id,''),
    container,COALESCE(link_id,''),action,request_key,payload_digest,content_hash,correlation_marker,state,version,attempts,
    lease_until,remote_id,remote_url,remote_version,error_code,created_at,updated_at`

// documentScopeArgs maps a target's scope to the two nullable scope columns.
func documentScopeArgs(t docpublish.Target) (engagement, project any) {
	if t.Scope == docpublish.Engagement {
		return t.ScopeID.String(), nil
	}
	return nil, t.ScopeID.String()
}

func documentScopeOf(engagement, project string) (docpublish.Scope, shared.ID) {
	if engagement != "" {
		return docpublish.Engagement, shared.ID(engagement)
	}
	return docpublish.Project, shared.ID(project)
}

func scanDocumentLink(row rowScanner) (docpublish.Link, error) {
	var l docpublish.Link
	var engagement, project string
	err := row.Scan(&l.ID, &l.TenantID, &l.IntegrationID, &l.SourceKind, &l.SourceRef, &engagement, &project,
		&l.Container, &l.RemotePageID, &l.RemoteVersion, &l.RemoteURL, &l.ContentHash, &l.Revision,
		&l.RetiredAt, &l.CreatedAt, &l.UpdatedAt)
	if err != nil {
		return docpublish.Link{}, err
	}
	l.Scope, l.ScopeID = documentScopeOf(engagement, project)
	l.CreatedAt, l.UpdatedAt = l.CreatedAt.UTC(), l.UpdatedAt.UTC()
	if l.RetiredAt != nil {
		at := l.RetiredAt.UTC()
		l.RetiredAt = &at
	}
	return l, nil
}

func scanDocumentIntent(row rowScanner) (docpublish.Intent, error) {
	var i docpublish.Intent
	var engagement, project, link string
	err := row.Scan(&i.ID, &i.TenantID, &i.IntegrationID, &i.SourceKind, &i.SourceRef, &engagement, &project,
		&i.Container, &link, &i.Action, &i.RequestKey, &i.PayloadDigest, &i.ContentHash, &i.Marker, &i.State,
		&i.Version, &i.Attempts, &i.LeaseUntil, &i.RemoteID, &i.RemoteURL, &i.RemoteVersion, &i.ErrorCode,
		&i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		return docpublish.Intent{}, err
	}
	i.Scope, i.ScopeID = documentScopeOf(engagement, project)
	i.LinkID = shared.ID(link)
	i.CreatedAt, i.UpdatedAt = i.CreatedAt.UTC(), i.UpdatedAt.UTC()
	if i.LeaseUntil != nil {
		lease := i.LeaseUntil.UTC()
		i.LeaseUntil = &lease
	}
	return i, nil
}

func (s *DocumentStore) GetLink(ctx context.Context, tenant, id shared.ID) (docpublish.Link, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Link{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return docpublish.Link{}, shared.ErrValidation
	}
	var link docpublish.Link
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		link, e = scanDocumentLink(tx.QueryRow(ctx, `SELECT `+documentLinkCols+` FROM document_links
            WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return docpublish.Link{}, shared.ErrNotFound
	}
	if err != nil {
		return docpublish.Link{}, fmt.Errorf("get document link: %w", err)
	}
	return link, nil
}

// selectDocumentLinkByTarget reads the one link a target addresses, optionally locking it.
func selectDocumentLinkByTarget(ctx context.Context, tx pgx.Tx, tenant shared.ID, t docpublish.Target, lock string) (docpublish.Link, error) {
	scopePredicate := "project_id=$6 AND engagement_id IS NULL"
	if t.Scope == docpublish.Engagement {
		scopePredicate = "engagement_id=$6 AND project_id IS NULL"
	}
	return scanDocumentLink(tx.QueryRow(ctx, `SELECT `+documentLinkCols+` FROM document_links
        WHERE tenant_id=$1 AND integration_id=$2 AND source_kind=$3 AND source_ref=$4 AND container=$5
            AND `+scopePredicate+` `+lock,
		tenant.String(), t.IntegrationID.String(), string(t.SourceKind), t.SourceRef, t.Container, t.ScopeID.String()))
}

func (s *DocumentStore) FindLink(ctx context.Context, tenant shared.ID, target docpublish.Target) (docpublish.Link, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Link{}, err
	}
	if tenant.IsZero() {
		return docpublish.Link{}, shared.ErrValidation
	}
	if err := target.Validate(); err != nil {
		return docpublish.Link{}, err
	}
	var link docpublish.Link
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		link, e = selectDocumentLinkByTarget(ctx, tx, tenant, target, "")
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return docpublish.Link{}, shared.ErrNotFound
	}
	if err != nil {
		return docpublish.Link{}, fmt.Errorf("find document link: %w", err)
	}
	return link, nil
}

func (s *DocumentStore) ListLinks(ctx context.Context, tenant shared.ID, scope docpublish.Scope, scopeID shared.ID, limit int) ([]docpublish.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || scopeID.IsZero() || limit < 1 || limit > docpublish.MaxListLimit {
		return nil, shared.ErrValidation
	}
	var column string
	switch scope {
	case docpublish.Engagement:
		column = "engagement_id"
	case docpublish.Project:
		column = "project_id"
	default:
		return nil, shared.ErrValidation
	}
	out := make([]docpublish.Link, 0)
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+documentLinkCols+` FROM document_links
            WHERE tenant_id=$1 AND `+column+`=$2 ORDER BY created_at DESC,id DESC LIMIT $3`,
			tenant.String(), scopeID.String(), limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			item, scanErr := scanDocumentLink(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list document links: %w", err)
	}
	return out, nil
}

func (s *DocumentStore) CreateOrGetIntent(ctx context.Context, tenant shared.ID, i docpublish.Intent) (docpublish.Intent, bool, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Intent{}, false, err
	}
	if err := i.Validate(); err != nil {
		return docpublish.Intent{}, false, err
	}
	if tenant.IsZero() || tenant != i.TenantID || i.State != writeintent.Pending || i.Version != 1 ||
		i.Attempts != 0 || i.LeaseUntil != nil {
		return docpublish.Intent{}, false, shared.ErrValidation
	}
	var saved docpublish.Intent
	created := false
	err := documentWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		byKey := func() (docpublish.Intent, error) {
			return scanDocumentIntent(tx.QueryRow(ctx, `SELECT `+documentIntentCols+` FROM document_intents
                WHERE tenant_id=$1 AND integration_id=$2 AND request_key=$3`,
				tenant.String(), i.IntegrationID.String(), i.RequestKey))
		}
		// A replay is answered before any rule below: a command that was valid when it was
		// recorded stays retrievable after its link exists.
		existing, e := byKey()
		if e == nil {
			if !existing.SameCommand(i) {
				return shared.ErrConflict
			}
			saved = existing
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		switch i.Action {
		case docpublish.Create:
			// The link exists, so its page does: a second create would make a duplicate page.
			_, e = selectDocumentLinkByTarget(ctx, tx, tenant, i.Target, "FOR KEY SHARE")
			if e == nil {
				// The original command may have committed and completed since byKey's
				// first READ COMMITTED snapshot. Give an identical replay its result.
				saved, e = byKey()
				if errors.Is(e, pgx.ErrNoRows) {
					return shared.ErrConflict
				}
				if e != nil {
					return e
				}
				if !saved.SameCommand(i) {
					return shared.ErrConflict
				}
				return nil
			}
			if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
		case docpublish.Update:
			link, linkErr := scanDocumentLink(tx.QueryRow(ctx, `SELECT `+documentLinkCols+` FROM document_links
                WHERE tenant_id=$1 AND id=$2 FOR KEY SHARE`, tenant.String(), i.LinkID.String()))
			if errors.Is(linkErr, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			if linkErr != nil {
				return linkErr
			}
			if link.Target != i.Target {
				return shared.ErrValidation
			}
			if link.RetiredAt != nil {
				return shared.ErrConflict
			}
		case docpublish.Purge:
			link, linkErr := scanDocumentLink(tx.QueryRow(ctx, `SELECT `+documentLinkCols+` FROM document_links
                WHERE tenant_id=$1 AND id=$2 FOR KEY SHARE`, tenant.String(), i.LinkID.String()))
			if errors.Is(linkErr, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			if linkErr != nil {
				return linkErr
			}
			if link.Target != i.Target || link.RetiredAt != nil {
				return shared.ErrConflict
			}
		}
		engagement, project := documentScopeArgs(i.Target)
		var link any
		if !i.LinkID.IsZero() {
			link = i.LinkID.String()
		}
		tag, e := tx.Exec(ctx, `INSERT INTO document_intents
            (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,project_id,container,link_id,action,
             request_key,payload_digest,content_hash,correlation_marker,state,version,attempts,lease_until,
             remote_id,remote_url,remote_version,error_code,created_at,updated_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
            ON CONFLICT (tenant_id,integration_id,request_key) DO NOTHING`,
			i.ID.String(), tenant.String(), i.IntegrationID.String(), string(i.SourceKind), i.SourceRef,
			engagement, project, i.Container, link, string(i.Action), i.RequestKey, i.PayloadDigest,
			i.ContentHash, i.Marker, string(i.State), i.Version, i.Attempts, nil, i.RemoteID, i.RemoteURL,
			i.RemoteVersion, i.ErrorCode, i.CreatedAt.UTC(), i.UpdatedAt.UTC())
		if e != nil {
			return e
		}
		created = tag.RowsAffected() == 1
		saved, e = byKey()
		if e != nil {
			return e
		}
		if !saved.SameCommand(i) {
			return shared.ErrConflict
		}
		return nil
	}))
	if err != nil {
		return docpublish.Intent{}, false, err
	}
	return saved, created, nil
}

func (s *DocumentStore) GetIntent(ctx context.Context, tenant, id shared.ID) (docpublish.Intent, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return docpublish.Intent{}, shared.ErrValidation
	}
	var i docpublish.Intent
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		i, e = scanDocumentIntent(tx.QueryRow(ctx, `SELECT `+documentIntentCols+` FROM document_intents
            WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return docpublish.Intent{}, shared.ErrNotFound
	}
	if err != nil {
		return docpublish.Intent{}, fmt.Errorf("get document intent: %w", err)
	}
	return i, nil
}

func (s *DocumentStore) TransitionIntent(ctx context.Context, tenant, id shared.ID, expected int, change docpublish.IntentTransition, at time.Time) (docpublish.Intent, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() || expected < 1 || at.IsZero() {
		return docpublish.Intent{}, shared.ErrValidation
	}
	var result docpublish.Intent
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		current, e := scanDocumentIntent(tx.QueryRow(ctx, `SELECT `+documentIntentCols+` FROM document_intents
            WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant.String(), id.String()))
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if e != nil {
			return e
		}
		if current.Version != expected {
			return shared.ErrConflict
		}
		next, e := current.Apply(change, at)
		if e != nil {
			return e
		}
		if next.State == writeintent.Done {
			if e = completeDocumentLink(ctx, tx, tenant, next); e != nil {
				return e
			}
		}
		result, e = scanDocumentIntent(tx.QueryRow(ctx, `UPDATE document_intents
            SET state=$3,version=$4,attempts=$5,lease_until=$6,remote_id=$7,remote_url=$8,remote_version=$9,
                error_code=$10,updated_at=$11
            WHERE tenant_id=$1 AND id=$2 AND version=$12 RETURNING `+documentIntentCols,
			tenant.String(), id.String(), string(next.State), next.Version, next.Attempts, next.LeaseUntil,
			next.RemoteID, next.RemoteURL, next.RemoteVersion, next.ErrorCode, next.UpdatedAt, expected))
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrConflict
		}
		return e
	})
	if err != nil {
		return docpublish.Intent{}, documentWriteError(err)
	}
	return result, nil
}

// completeDocumentLink writes the link a done intent leaves behind inside the transaction that
// finishes the intent. The link row is locked first, so racing completions for one page apply
// one at a time and each sees the other's result.
func completeDocumentLink(ctx context.Context, tx pgx.Tx, tenant shared.ID, done docpublish.Intent) error {
	var existing *docpublish.Link
	found, e := selectDocumentLinkByTarget(ctx, tx, tenant, done.Target, "FOR UPDATE")
	switch {
	case e == nil:
		existing = &found
	case !errors.Is(e, pgx.ErrNoRows):
		return e
	}
	link, changed, e := done.Complete(existing)
	if e != nil {
		return e
	}
	if !changed {
		return nil
	}
	if existing != nil {
		return updateDocumentLink(ctx, tx, tenant, link, existing.Revision)
	}
	engagement, project := documentScopeArgs(link.Target)
	tag, e := tx.Exec(ctx, `INSERT INTO document_links
        (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,project_id,container,
		 remote_page_id,remote_version,remote_url,content_hash,revision,retired_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ON CONFLICT ON CONSTRAINT document_links_target_unique DO NOTHING`,
		link.ID.String(), tenant.String(), link.IntegrationID.String(), string(link.SourceKind), link.SourceRef,
		engagement, project, link.Container, link.RemotePageID, link.RemoteVersion, link.RemoteURL,
		link.ContentHash, link.Revision, link.RetiredAt, link.CreatedAt.UTC(), link.UpdatedAt.UTC())
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// A concurrent completion created the link first. Decide again against what it wrote.
	winner, e := selectDocumentLinkByTarget(ctx, tx, tenant, done.Target, "FOR UPDATE")
	if errors.Is(e, pgx.ErrNoRows) {
		return shared.ErrConflict
	}
	if e != nil {
		return e
	}
	link, changed, e = done.Complete(&winner)
	if e != nil {
		return e
	}
	if !changed {
		return nil
	}
	return updateDocumentLink(ctx, tx, tenant, link, winner.Revision)
}

func updateDocumentLink(ctx context.Context, tx pgx.Tx, tenant shared.ID, link docpublish.Link, expectedRevision int) error {
	tag, err := tx.Exec(ctx, `UPDATE document_links
		SET remote_version=$3,remote_url=$4,content_hash=$5,revision=$6,retired_at=$7,updated_at=$8
        WHERE tenant_id=$1 AND id=$2 AND revision=$9`,
		tenant.String(), link.ID.String(), link.RemoteVersion, link.RemoteURL, link.ContentHash,
		link.Revision, link.RetiredAt, link.UpdatedAt.UTC(), expectedRevision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return shared.ErrConflict
	}
	return nil
}
