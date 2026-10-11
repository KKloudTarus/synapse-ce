package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The backfill reads users only under row locks inside a tenant transaction and never writes it:
// the legacy source is not repaired, and actor strings and audit hashes are never rewritten. Every
// derived row is keyed on the legacy user ID, so a retried batch converges on the same rows.

const (
	identityBackfillLockClass = "synapse.identity_backfill"
	identityBackfillMaxBatch  = 1000
	identityShadowDriftSample = 50
)

// StartRun takes the tenant fence with a new token, enables write-path projection for the tenant
// and resumes from the fence checkpoint.
func (s *IdentityFoundationStore) StartRun(ctx context.Context, tenantID, runID shared.ID, actor string, batchSize int, lease time.Duration, now time.Time) (ports.IdentityBackfillRun, error) {
	if runID.IsZero() || actor == "" || batchSize < 1 || batchSize > identityBackfillMaxBatch || lease <= 0 {
		return ports.IdentityBackfillRun{}, fmt.Errorf("%w: backfill run id, actor, batch size (1-%d) and lease are required", shared.ErrValidation, identityBackfillMaxBatch)
	}
	run := ports.IdentityBackfillRun{TenantID: tenantID, ID: runID}
	err := s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, identityBackfillLockClass, tenantID.String()); err != nil {
			return fmt.Errorf("backfill lock: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_backfill_fences (tenant_id, id, updated_at) VALUES ($1, 'identity', $2)
			ON CONFLICT (tenant_id) DO NOTHING`, tenantID.String(), now); err != nil {
			return fmt.Errorf("create backfill fence: %w", err)
		}
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_backfill_runs WHERE tenant_id=$1 AND state='running' AND updated_at > $2`,
			tenantID.String(), now.Add(-lease)).Scan(&live); err != nil {
			return fmt.Errorf("inspect live backfill runs: %w", err)
		}
		if live > 0 {
			return fmt.Errorf("%w: %w", shared.ErrConflict, ports.ErrIdentityFenceLost)
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_backfill_runs SET state='failed', last_error='lease expired', finished_at=$2, updated_at=$2
			WHERE tenant_id=$1 AND state='running'`, tenantID.String(), now); err != nil {
			return fmt.Errorf("expire stale backfill runs: %w", err)
		}
		var checkpoint string
		if err := tx.QueryRow(ctx, `UPDATE identity_backfill_fences SET fence_token=fence_token+1, run_id=$2, projection_enabled=true, updated_at=$3
			WHERE tenant_id=$1 RETURNING fence_token, checkpoint_user_id`, tenantID.String(), runID.String(), now).Scan(&run.FenceToken, &checkpoint); err != nil {
			return fmt.Errorf("advance backfill fence: %w", err)
		}
		run.CheckpointUserID = shared.ID(checkpoint)
		if _, err := tx.Exec(ctx, `INSERT INTO identity_backfill_runs (tenant_id, id, fence_token, actor, batch_size, checkpoint_user_id, started_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`, tenantID.String(), runID.String(), run.FenceToken, actor, batchSize, checkpoint, now); err != nil {
			return fmt.Errorf("record backfill run: %w", err)
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{
			Actor: actor, Action: "identity.backfill_started", Target: runID.String(), At: now,
			Metadata: map[string]string{"fence_token": strconv.FormatInt(run.FenceToken, 10), "checkpoint": checkpoint},
		})
	})
	return run, err
}

// checkFence locks the fence and fails when a newer run owns it. FOR NO KEY UPDATE serializes
// against other fence writers but not against the FOR KEY SHARE read in user writes (see
// identityProjectionEnabled); the tenant advisory lock already serializes runs.
func checkFence(ctx context.Context, tx pgx.Tx, run *ports.IdentityBackfillRun) (int, error) {
	var (
		token     int64
		batchSize int
	)
	if err := tx.QueryRow(ctx, `SELECT f.fence_token, r.batch_size FROM identity_backfill_fences f
		JOIN identity_backfill_runs r ON r.tenant_id=f.tenant_id AND r.id=$2
		WHERE f.tenant_id=$1 FOR NO KEY UPDATE OF f`, run.TenantID.String(), run.ID.String()).Scan(&token, &batchSize); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("%w: %w", shared.ErrConflict, ports.ErrIdentityFenceLost)
		}
		return 0, fmt.Errorf("check backfill fence: %w", err)
	}
	if token != run.FenceToken {
		return 0, fmt.Errorf("%w: %w", shared.ErrConflict, ports.ErrIdentityFenceLost)
	}
	return batchSize, nil
}

// ApplyBatch classifies and projects the next locked batch after the checkpoint.
func (s *IdentityFoundationStore) ApplyBatch(ctx context.Context, run *ports.IdentityBackfillRun, issuer string, classify ports.IdentityBackfillClassifier, now time.Time) (ports.IdentityBackfillBatch, error) {
	if run == nil || classify == nil {
		return ports.IdentityBackfillBatch{}, fmt.Errorf("%w: backfill run and classifier are required", shared.ErrValidation)
	}
	var out ports.IdentityBackfillBatch
	tenant := run.TenantID
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		// A batch holds FOR UPDATE locks on its users rows and, once it creates a person, the global
		// person-audit lock that user creation in every projected tenant needs. Bound both the wait
		// for a lock and each statement, so a stuck batch fails and rolls back quickly instead of
		// stalling other writers; the next run resumes from the last committed checkpoint.
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
			return fmt.Errorf("bound backfill lock wait: %w", err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '60s'`); err != nil {
			return fmt.Errorf("bound backfill statements: %w", err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, identityBackfillLockClass, tenant.String()); err != nil {
			return fmt.Errorf("backfill lock: %w", err)
		}
		batchSize, err := checkFence(ctx, tx, run)
		if err != nil {
			return err
		}
		connectionID, err := ensureLegacyConnection(ctx, tx, tenant, issuer, now)
		if err != nil {
			return err
		}
		legacy, err := lockLegacyBatch(ctx, tx, tenant, run.CheckpointUserID, batchSize)
		if err != nil {
			return err
		}
		if err := loadLegacyEvidence(ctx, tx, legacy); err != nil {
			return err
		}
		for i := range legacy {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := applyLegacyDecision(ctx, tx, legacy[i], classify(legacy[i]), run.ID, now); err != nil {
				return fmt.Errorf("backfill user %s: %w", legacy[i].ID, err)
			}
		}
		if err := reconcileLegacyAuthenticators(ctx, tx, tenant, connectionID, issuer, now); err != nil {
			return err
		}
		out.Processed = len(legacy)
		out.CheckpointUserID = run.CheckpointUserID
		if len(legacy) > 0 {
			out.CheckpointUserID = legacy[len(legacy)-1].ID
		}
		out.Done = len(legacy) < batchSize
		if _, err := tx.Exec(ctx, `UPDATE identity_backfill_fences SET checkpoint_user_id=$2, updated_at=$3 WHERE tenant_id=$1`,
			tenant.String(), out.CheckpointUserID.String(), now); err != nil {
			return fmt.Errorf("advance backfill checkpoint: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_backfill_runs SET processed=processed+$3, batches=batches+1, checkpoint_user_id=$4, updated_at=$5
			WHERE tenant_id=$1 AND id=$2`, tenant.String(), run.ID.String(), out.Processed, out.CheckpointUserID.String(), now); err != nil {
			return fmt.Errorf("advance backfill run: %w", err)
		}
		return nil
	})
	if err != nil {
		return ports.IdentityBackfillBatch{}, err
	}
	run.CheckpointUserID = out.CheckpointUserID
	run.Processed += out.Processed
	run.Batches++
	return out, nil
}

// ensureLegacyConnection pins the configured fixed OIDC issuer as a disabled connection.
func ensureLegacyConnection(ctx context.Context, tx pgx.Tx, tenantID shared.ID, issuer string, now time.Time) (shared.ID, error) {
	if issuer == "" {
		return "", nil
	}
	id := legacyIdentityID("connection_", tenantID, shared.ID(issuer))
	tag, err := tx.Exec(ctx, `INSERT INTO identity_connections (tenant_id, id, protocol, trust_namespace, display_name, enabled, created_at, updated_at)
		VALUES ($1,$2,'oidc',$3,'Legacy fixed OIDC issuer',false,$4,$4) ON CONFLICT (tenant_id, protocol, trust_namespace) DO NOTHING`,
		tenantID.String(), id.String(), issuer, now)
	if err != nil {
		return "", fmt.Errorf("pin legacy OIDC connection: %w", identityPersistenceError(err))
	}
	if tag.RowsAffected() == 1 {
		if _, err := tx.Exec(ctx, `INSERT INTO identity_connection_revisions (tenant_id, connection_id, revision, settings, actor, created_at)
			VALUES ($1,$2,1,jsonb_build_object('issuer', $3::text, 'provenance', 'legacy_fixed_tenant_oidc'),$4,$5)`,
			tenantID.String(), id.String(), issuer, identityProjectionActor, now); err != nil {
			return "", fmt.Errorf("record legacy OIDC connection revision: %w", err)
		}
		return id, nil
	}
	var existing string
	if err := tx.QueryRow(ctx, `SELECT id FROM identity_connections WHERE tenant_id=$1 AND protocol='oidc' AND trust_namespace=$2`,
		tenantID.String(), issuer).Scan(&existing); err != nil {
		return "", fmt.Errorf("read legacy OIDC connection: %w", err)
	}
	return shared.ID(existing), nil
}

func lockLegacyBatch(ctx context.Context, tx pgx.Tx, tenantID, after shared.ID, limit int) ([]ports.IdentityLegacyUser, error) {
	rows, err := tx.Query(ctx, `SELECT id, name, role, api_key_hash, disabled FROM users
		WHERE ownership_tenant_id=$1 AND id > $2 ORDER BY id LIMIT $3 FOR UPDATE`, tenantID.String(), after.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("lock legacy users: %w", err)
	}
	defer rows.Close()
	var out []ports.IdentityLegacyUser
	for rows.Next() {
		var (
			u        ports.IdentityLegacyUser
			id, role string
		)
		if err := rows.Scan(&id, &u.Name, &role, &u.APIKeyHash, &u.Disabled); err != nil {
			return nil, fmt.Errorf("scan legacy user: %w", err)
		}
		u.ID, u.TenantID, u.Role = shared.ID(id), tenantID, user.Role(role)
		out = append(out, u)
	}
	return out, rows.Err()
}

// loadLegacyEvidence reads issuance evidence, hash uniqueness and approved links for the whole
// locked batch with a fixed number of set-based queries. It runs before any person is created, so
// the global person-audit lock is not yet held while audit_log is read, and the number of queries
// per batch does not grow with the number of users.
func loadLegacyEvidence(ctx context.Context, tx pgx.Tx, batch []ports.IdentityLegacyUser) error {
	if len(batch) == 0 {
		return nil
	}
	tenant := batch[0].TenantID.String()
	ids := make([]string, len(batch))
	byID := make(map[string]*ports.IdentityLegacyUser, len(batch))
	var hashes, digests []string
	seenHash := map[string]bool{}
	for i := range batch {
		u := &batch[i]
		u.KeyEvidence, u.DuplicateHash, u.Links = ports.IdentityKeyNoEvidence, false, nil
		ids[i] = u.ID.String()
		byID[ids[i]] = u
		if seenHash[u.APIKeyHash] {
			continue
		}
		seenHash[u.APIKeyHash] = true
		hashes = append(hashes, u.APIKeyHash)
		if identityDigestPattern.MatchString(u.APIKeyHash) {
			digests = append(digests, u.APIKeyHash)
		}
	}
	if err := loadKeyEvidence(ctx, tx, tenant, ids, byID); err != nil {
		return err
	}
	if err := loadHashUniqueness(ctx, tx, tenant, ids, hashes, digests, batch); err != nil {
		return err
	}
	return loadApprovedLinks(ctx, tx, tenant, ids, byID)
}

// loadKeyEvidence picks, per user, the newest decisive key record: the newest user.created or
// user.api_key_rotated, or a newer user.disabled that replaced the key (api_key_revoked=true). An
// older disable without that flag left the issued key in place and re-enable restored it, so it
// is not decisive and is skipped. DISTINCT ON returns at most one row per user.
func loadKeyEvidence(ctx context.Context, tx pgx.Tx, tenant string, ids []string, byID map[string]*ports.IdentityLegacyUser) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (target) target, action FROM audit_log
		WHERE tenant_id=$1 AND hash_version=2 AND target = ANY($2)
		  AND action IN ('user.created', 'user.api_key_rotated', 'user.disabled')
		  AND (action <> 'user.disabled' OR COALESCE(metadata->>'api_key_revoked', '') = 'true')
		ORDER BY target, id DESC`, tenant, ids)
	if err != nil {
		return fmt.Errorf("read key issuance evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var target, action string
		if err := rows.Scan(&target, &action); err != nil {
			return fmt.Errorf("scan key issuance evidence: %w", err)
		}
		if u, ok := byID[target]; ok {
			u.KeyEvidence = keyEvidenceFor(action)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read key issuance evidence: %w", err)
	}
	return nil
}

// keyEvidenceFor maps the newest decisive audit action to its key evidence.
func keyEvidenceFor(action string) ports.IdentityKeyEvidence {
	if action == "user.disabled" {
		return ports.IdentityKeyRevokedByDisable
	}
	return ports.IdentityKeyIssued
}

// loadHashUniqueness marks users whose digest is not exclusively theirs: another users row holds
// the same value, or the digest already routes somewhere other than the user's own active derived
// credential.
func loadHashUniqueness(ctx context.Context, tx pgx.Tx, tenant string, ids, hashes, digests []string, batch []ports.IdentityLegacyUser) error {
	// users carries a global unique index on api_key_hash; this exact-value count detects a source
	// where that invariant was lost. It reads only the values already held by the batch.
	counts := make(map[string]int, len(hashes))
	if err := scanPairs(ctx, tx, "check legacy hash uniqueness", func(rows pgx.Rows) error {
		var hash string
		var n int
		if err := rows.Scan(&hash, &n); err != nil {
			return err
		}
		counts[hash] = n
		return nil
	}, `SELECT api_key_hash, count(*) FROM users WHERE api_key_hash = ANY($1) GROUP BY api_key_hash`, hashes); err != nil {
		return err
	}
	routed := make(map[string]string, len(digests))
	if len(digests) > 0 {
		if err := scanPairs(ctx, tx, "check digest uniqueness", func(rows pgx.Rows) error {
			var digest, routedTenant string
			if err := rows.Scan(&digest, &routedTenant); err != nil {
				return err
			}
			routed[digest] = routedTenant
			return nil
		}, `SELECT d.digest, r.tenant_id FROM unnest($1::text[]) AS d(digest)
			CROSS JOIN LATERAL synapse_identity_route_credential(d.digest) AS r`, digests); err != nil {
			return err
		}
	}
	// Each user's own derived credential, read through the unique (tenant_id, legacy_user_id)
	// partial index; the digest is compared in Go.
	type ownCredential struct {
		digest string
		active bool
	}
	own := map[string]ownCredential{}
	if len(routed) > 0 {
		if err := scanPairs(ctx, tx, "check digest ownership", func(rows pgx.Rows) error {
			var id string
			var c ownCredential
			if err := rows.Scan(&id, &c.digest, &c.active); err != nil {
				return err
			}
			own[id] = c
			return nil
		}, `SELECT legacy_user_id, digest, state='active' FROM identity_credentials
			WHERE tenant_id=$1 AND source='legacy_projection' AND legacy_user_id = ANY($2)`, tenant, ids); err != nil {
			return err
		}
	}
	for i := range batch {
		u := &batch[i]
		if counts[u.APIKeyHash] > 1 {
			u.DuplicateHash = true
		}
		routedTenant, ok := routed[u.APIKeyHash]
		if !ok {
			continue
		}
		// The digest already routes somewhere other than this user's own derived credential.
		c, owned := own[u.ID.String()]
		if routedTenant != tenant || !owned || !c.active || c.digest != u.APIKeyHash {
			u.DuplicateHash = true
		}
	}
	return nil
}

// scanPairs runs one read and hands every row to scan, wrapping failures with op.
func scanPairs(ctx context.Context, tx pgx.Tx, op string, scan func(pgx.Rows) error, sql string, args ...any) error {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// loadApprovedLinks reads every approved OIDC link of the batch with its approver: the actor of
// the newest user.oidc_identity_linked record naming that link, or empty for a link that predates
// operator-approved linking.
func loadApprovedLinks(ctx context.Context, tx pgx.Tx, tenant string, ids []string, byID map[string]*ports.IdentityLegacyUser) error {
	return scanPairs(ctx, tx, "lock approved OIDC links", func(rows pgx.Rows) error {
		var userID string
		var link ports.IdentityLegacyLink
		if err := rows.Scan(&userID, &link.Issuer, &link.Subject, &link.ApprovedBy); err != nil {
			return err
		}
		if u, ok := byID[userID]; ok {
			u.Links = append(u.Links, link)
		}
		return nil
	}, `WITH locked_links AS MATERIALIZED (
			SELECT l.id, l.user_id, l.issuer, l.subject, l.created_at
			  FROM oidc_external_identities l
			 WHERE l.tenant_id=$1 AND l.user_id = ANY($2)
			 ORDER BY l.id
			 FOR UPDATE
		), approvals AS (
			SELECT DISTINCT ON (a.target, a.metadata->>'link_id') a.target, a.metadata->>'link_id' AS link_id, a.actor
			  FROM audit_log a
			 WHERE a.tenant_id=$1 AND a.hash_version=2 AND a.action='user.oidc_identity_linked' AND a.target = ANY($2)
			 ORDER BY a.target, a.metadata->>'link_id', a.id DESC)
		SELECT l.user_id, l.issuer, l.subject, COALESCE(ap.actor, '')
		  FROM locked_links l
		  LEFT JOIN approvals ap ON ap.target=l.user_id AND ap.link_id=l.id
		 ORDER BY l.user_id, l.created_at, l.id`, tenant, ids)
}

// reconcileLegacyAuthenticators makes source=legacy_link rows an exact projection of the
// authoritative approved links for the configured issuer. Source rows are locked by ID before this
// function runs. Derived rows are then locked by subject, stale rows are removed, obsolete legacy
// bindings are replaced, and a native owner of an authoritative key fails the batch closed.
func reconcileLegacyAuthenticators(ctx context.Context, tx pgx.Tx, tenantID, connectionID shared.ID, issuer string, now time.Time) error {
	if connectionID.IsZero() || issuer == "" {
		return nil
	}
	tenant := tenantID.String()
	connection := connectionID.String()
	// Reconciliation is tenant-wide, so lock every authoritative row it compares rather than only
	// the current users batch. Existing link updates/deletes then serialize before any derived write.
	rows, err := tx.Query(ctx, `SELECT id FROM oidc_external_identities
		WHERE tenant_id=$1 AND issuer=$2
		ORDER BY id
		FOR UPDATE`, tenant, issuer)
	if err != nil {
		return fmt.Errorf("lock authoritative authenticators: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan authoritative authenticator: %w", err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("lock authoritative authenticators: %w", err)
	}
	rows, err = tx.Query(ctx, `SELECT protocol_subject, source
		FROM identity_authenticators
		WHERE tenant_id=$1 AND connection_id=$2
		ORDER BY protocol_subject
		FOR UPDATE`, tenant, connection)
	if err != nil {
		return fmt.Errorf("lock derived authenticators: %w", err)
	}
	for rows.Next() {
		var subject, source string
		if err := rows.Scan(&subject, &source); err != nil {
			rows.Close()
			return fmt.Errorf("scan derived authenticator: %w", err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("lock derived authenticators: %w", err)
	}

	// A native row can exist only after declaration. If an authoritative legacy link now claims its
	// canonical key, replacing it would silently transfer ownership across sources.
	var nativeSubject string
	err = tx.QueryRow(ctx, `SELECT a.protocol_subject
		FROM identity_authenticators a
		JOIN oidc_external_identities l
		  ON l.tenant_id=a.tenant_id AND l.issuer=$3 AND l.subject=a.protocol_subject
		WHERE a.tenant_id=$1 AND a.connection_id=$2 AND a.source='native'
		ORDER BY a.protocol_subject LIMIT 1`, tenant, connection, issuer).Scan(&nativeSubject)
	switch {
	case err == nil:
		return fmt.Errorf("%w: native authenticator conflicts with approved legacy subject %q", shared.ErrConflict, nativeSubject)
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("check native authenticator conflict: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM identity_authenticators a
		WHERE a.tenant_id=$1 AND a.connection_id=$2 AND a.source='legacy_link'
		  AND NOT EXISTS (
			SELECT 1 FROM oidc_external_identities l
			WHERE l.tenant_id=a.tenant_id AND l.issuer=$3 AND l.subject=a.protocol_subject
		  )`, tenant, connection, issuer); err != nil {
		return fmt.Errorf("remove stale legacy authenticators: %w", identityPersistenceError(err))
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identity_authenticators a
		USING oidc_external_identities l, identity_memberships m
		WHERE a.tenant_id=$1 AND a.connection_id=$2 AND a.source='legacy_link'
		  AND l.tenant_id=a.tenant_id AND l.issuer=$3 AND l.subject=a.protocol_subject
		  AND m.tenant_id=l.tenant_id AND m.legacy_user_id=l.user_id
		  AND (a.membership_id,a.person_id) IS DISTINCT FROM (m.id,m.person_id)`, tenant, connection, issuer); err != nil {
		return fmt.Errorf("replace rebound legacy authenticators: %w", identityPersistenceError(err))
	}
	if _, err := tx.Exec(ctx, `WITH approvals AS (
		SELECT DISTINCT ON (a.target,a.metadata->>'link_id') a.target, a.metadata->>'link_id' AS link_id, a.actor
		FROM audit_log a
		WHERE a.tenant_id=$1 AND a.hash_version=2 AND a.action='user.oidc_identity_linked'
		ORDER BY a.target,a.metadata->>'link_id',a.id DESC
	)
	INSERT INTO identity_authenticators
		(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,approved_by,source,created_at,updated_at)
	SELECT l.tenant_id,
	       'authenticator_'||substr(encode(digest(convert_to(l.tenant_id||E'\\000'||l.issuer||E'\\000'||l.subject,'UTF8'),'sha256'),'hex'),1,40),
	       $2,l.subject,m.id,m.person_id,COALESCE(NULLIF(ap.actor,''),'legacy-approved-link'),'legacy_link',$4,$4
	FROM oidc_external_identities l
	JOIN identity_memberships m ON m.tenant_id=l.tenant_id AND m.legacy_user_id=l.user_id
	LEFT JOIN approvals ap ON ap.target=l.user_id AND ap.link_id=l.id
	WHERE l.tenant_id=$1 AND l.issuer=$3
	ON CONFLICT (tenant_id,connection_id,protocol_subject) DO NOTHING`, tenant, connection, issuer, now); err != nil {
		return fmt.Errorf("insert approved legacy authenticators: %w", identityPersistenceError(err))
	}
	return nil
}

func applyLegacyDecision(ctx context.Context, tx pgx.Tx, u ports.IdentityLegacyUser, d ports.IdentityBackfillDecision, runID shared.ID, now time.Time) error {
	var personID, membershipID shared.ID
	if d.Project {
		var existingMembership, existingPerson string
		err := tx.QueryRow(ctx, `SELECT id, person_id FROM identity_memberships WHERE tenant_id=$1 AND legacy_user_id=$2 FOR UPDATE`,
			u.TenantID.String(), u.ID.String()).Scan(&existingMembership, &existingPerson)
		switch {
		case err == nil:
			membershipID, personID = shared.ID(existingMembership), shared.ID(existingPerson)
		case errors.Is(err, pgx.ErrNoRows):
			personID = legacyIdentityID("person_", u.TenantID, u.ID)
			membershipID = legacyIdentityID("membership_", u.TenantID, u.ID)
			if err := createLegacyPerson(ctx, tx, personID, "legacy user "+u.ID.String()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("read membership: %w", err)
		}
		legacy := &user.User{ID: u.ID, Name: u.Name, Role: u.Role, Disabled: u.Disabled, APIKeyHash: u.APIKeyHash}
		if err := upsertLegacyMembership(ctx, tx, u.TenantID, membershipID, personID, legacy, now); err != nil {
			return identityPersistenceError(err)
		}
		if d.ProjectCredential {
			if err := upsertLegacyCredential(ctx, tx, u.TenantID, membershipID, personID, u.ID, u.APIKeyHash, true, d.CredentialActive && !u.Disabled, now); err != nil {
				return identityPersistenceError(err)
			}
		} else if err := revokeLegacyCredential(ctx, tx, u, now); err != nil {
			return identityPersistenceError(err)
		}
	}
	return upsertBackfillItem(ctx, tx, u.TenantID, u.ID, d.Class, d.CredentialClass, personID, membershipID, u.APIKeyHash, runID, now)
}

// revokeLegacyCredential makes an existing derived credential unroutable when a rerun no longer
// finds issuance evidence, mirroring the current users hash so shadow parity still compares equal.
func revokeLegacyCredential(ctx context.Context, tx pgx.Tx, u ports.IdentityLegacyUser, now time.Time) error {
	var id, digest string
	err := tx.QueryRow(ctx, `SELECT id, digest FROM identity_credentials
		WHERE tenant_id=$1 AND legacy_user_id=$2 AND source='legacy_projection' FOR UPDATE`, u.TenantID.String(), u.ID.String()).Scan(&id, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lock legacy credential: %w", err)
	}
	if identityDigestPattern.MatchString(u.APIKeyHash) {
		digest = u.APIKeyHash
	}
	return setLegacyCredential(ctx, tx, u.TenantID, shared.ID(id), digest, false, false, now)
}

// FinishRun records the run outcome. A completed pass resets the checkpoint so the next run is a
// fresh verification pass.
func (s *IdentityFoundationStore) FinishRun(ctx context.Context, run ports.IdentityBackfillRun, failure error, now time.Time) error {
	return s.withIdentityTenant(ctx, run.TenantID, func(tx pgx.Tx) error {
		if _, err := checkFence(ctx, tx, &run); err != nil {
			return err
		}
		state, message := "completed", ""
		if failure != nil {
			state, message = "failed", failure.Error()
			if len(message) > 512 {
				message = message[:512]
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_backfill_runs SET state=$3, last_error=$4, finished_at=$5, updated_at=$5
			WHERE tenant_id=$1 AND id=$2`, run.TenantID.String(), run.ID.String(), state, message, now); err != nil {
			return fmt.Errorf("finish backfill run: %w", err)
		}
		if failure == nil {
			if _, err := tx.Exec(ctx, `UPDATE identity_backfill_fences SET checkpoint_user_id='', updated_at=$2 WHERE tenant_id=$1`, run.TenantID.String(), now); err != nil {
				return fmt.Errorf("reset backfill checkpoint: %w", err)
			}
		}
		return nil
	})
}

// RecordShadowReport compares users with the derived rows and appends the parity evidence. It
// only reads the legacy source.
func (s *IdentityFoundationStore) RecordShadowReport(ctx context.Context, tenantID, reportID, runID shared.ID, thresholds ports.IdentityShadowThresholds, now time.Time) (ports.IdentityShadowReport, error) {
	if reportID.IsZero() || thresholds.MaxDrift < 0 {
		return ports.IdentityShadowReport{}, fmt.Errorf("%w: report id and a non-negative drift threshold are required", shared.ErrValidation)
	}
	r := ports.IdentityShadowReport{ID: reportID, TenantID: tenantID}
	err := s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		t := tenantID.String()
		bootstrap := ports.IdentityBootstrapUserID.String()
		if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE u.id <> $2),
			count(*) FILTER (WHERE u.id = $2),
			count(*) FILTER (WHERE u.id <> $2 AND m.id IS NULL AND (i.id IS NULL OR i.classification IN ('migrated','suspended','ambiguous_unproven_key','ambiguous_foreign_link'))),
			count(*) FILTER (WHERE m.id IS NOT NULL AND m.role <> u.role),
			count(*) FILTER (WHERE m.id IS NOT NULL AND (m.state <> 'active') <> u.disabled),
			count(*) FILTER (WHERE i.credential_class = 'placeholder'),
			count(*) FILTER (WHERE i.classification LIKE 'ambiguous%')
			FROM users u
			LEFT JOIN identity_memberships m ON m.tenant_id=u.ownership_tenant_id AND m.legacy_user_id=u.id
			LEFT JOIN identity_backfill_items i ON i.tenant_id=u.ownership_tenant_id AND i.id=u.id
			WHERE u.ownership_tenant_id=$1`, t, bootstrap).Scan(
			&r.LegacyUsers, &r.BootstrapSkipped, &r.MissingMemberships, &r.RoleDrift, &r.StateDrift, &r.Placeholders, &r.Ambiguous); err != nil {
			return fmt.Errorf("shadow membership parity: %w", err)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, t).Scan(&r.Memberships); err != nil {
			return fmt.Errorf("shadow membership count: %w", err)
		}
		// Credential parity: every user classified with a real key has exactly one derived
		// credential whose digest equals users.api_key_hash and whose activity equals legacy usability.
		if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE i.credential_class = 'real' OR c.id IS NOT NULL),
			count(*) FILTER (WHERE c.id IS NOT NULL AND c.digest = u.api_key_hash AND (c.state = 'active') = (NOT u.disabled AND c.legacy_key_issued)),
			count(*) FILTER (WHERE (i.credential_class = 'real' AND c.id IS NULL)
			                   OR (c.id IS NOT NULL AND (c.digest <> u.api_key_hash OR (c.state = 'active') <> (NOT u.disabled AND c.legacy_key_issued))))
			FROM users u
			LEFT JOIN identity_backfill_items i ON i.tenant_id=u.ownership_tenant_id AND i.id=u.id
			LEFT JOIN identity_credentials c ON c.tenant_id=u.ownership_tenant_id AND c.legacy_user_id=u.id AND c.source='legacy_projection'
			WHERE u.ownership_tenant_id=$1 AND u.id <> $2`, t, bootstrap).Scan(&r.CredentialsExpected, &r.CredentialsMatched, &r.DigestMismatches); err != nil {
			return fmt.Errorf("shadow credential parity: %w", err)
		}
		// Authenticator parity: one approved source link under the configured connection has exactly
		// one approved legacy_link row with the membership/person derived from its current user.
		if err := tx.QueryRow(ctx, `WITH source_links AS (
			SELECT l.subject,m.id AS membership_id,m.person_id
			FROM oidc_external_identities l
			JOIN identity_connections cn ON cn.tenant_id=l.tenant_id AND cn.protocol='oidc' AND cn.trust_namespace=l.issuer
			JOIN identity_memberships m ON m.tenant_id=l.tenant_id AND m.legacy_user_id=l.user_id
			WHERE l.tenant_id=$1
		), derived AS (
			SELECT a.protocol_subject,a.membership_id,a.person_id,a.source,a.state
			FROM identity_authenticators a
			JOIN identity_connections cn ON cn.tenant_id=a.tenant_id AND cn.id=a.connection_id AND cn.protocol='oidc'
			WHERE a.tenant_id=$1
		), matched AS (
			SELECT s.subject FROM source_links s JOIN derived d ON d.protocol_subject=s.subject
			WHERE d.source='legacy_link' AND d.state='approved'
			  AND d.membership_id=s.membership_id AND d.person_id=s.person_id
		)
		SELECT (SELECT count(*) FROM source_links),
		       (SELECT count(*) FROM matched),
		       (SELECT count(*) FROM source_links)+(SELECT count(*) FROM derived)-2*(SELECT count(*) FROM matched)`, t).Scan(
			&r.AuthenticatorsExpected, &r.AuthenticatorsMatched, &r.AuthenticatorMismatches); err != nil {
			return fmt.Errorf("shadow authenticator parity: %w", err)
		}
		// Routing parity through the exact-digest function the authenticator will use: an active
		// credential routes to this tenant and kind; a revoked credential or unusable legacy hash
		// routes nowhere.
		if err := tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM identity_credentials c WHERE c.tenant_id=$1 AND c.state='active'
			   AND NOT EXISTS (SELECT 1 FROM synapse_identity_route_credential(c.digest) r WHERE r.tenant_id=c.tenant_id AND r.kind=c.kind))
			+ (SELECT count(*) FROM identity_credentials c WHERE c.tenant_id=$1 AND c.state='revoked'
			   AND NOT EXISTS (SELECT 1 FROM identity_credentials o WHERE o.tenant_id=c.tenant_id AND o.digest=c.digest AND o.state='active')
			   AND EXISTS (SELECT 1 FROM synapse_identity_route_credential(c.digest)))
			+ (SELECT count(*) FROM users u WHERE u.ownership_tenant_id=$1 AND u.id <> $2 AND u.disabled
			   AND EXISTS (SELECT 1 FROM synapse_identity_route_credential(u.api_key_hash)))`, t, bootstrap).Scan(&r.RoutingMismatches); err != nil {
			return fmt.Errorf("shadow routing parity: %w", err)
		}
		drifted, err := tx.Query(ctx, `SELECT u.id FROM users u
			LEFT JOIN identity_memberships m ON m.tenant_id=u.ownership_tenant_id AND m.legacy_user_id=u.id
			LEFT JOIN identity_backfill_items i ON i.tenant_id=u.ownership_tenant_id AND i.id=u.id
			LEFT JOIN identity_credentials c ON c.tenant_id=u.ownership_tenant_id AND c.legacy_user_id=u.id AND c.source='legacy_projection'
			WHERE u.ownership_tenant_id=$1 AND u.id <> $2 AND (
			  (m.id IS NULL AND (i.id IS NULL OR i.classification IN ('migrated','suspended','ambiguous_unproven_key','ambiguous_foreign_link')))
			  OR (m.id IS NOT NULL AND (m.role <> u.role OR (m.state <> 'active') <> u.disabled))
			  OR (i.credential_class = 'real' AND c.id IS NULL)
			  OR (c.id IS NOT NULL AND (c.digest <> u.api_key_hash OR (c.state='active') <> (NOT u.disabled AND c.legacy_key_issued))))
			ORDER BY u.id LIMIT $3`, t, bootstrap, identityShadowDriftSample)
		if err != nil {
			return fmt.Errorf("shadow drift sample: %w", err)
		}
		for drifted.Next() {
			var id string
			if err := drifted.Scan(&id); err != nil {
				drifted.Close()
				return fmt.Errorf("scan shadow drift: %w", err)
			}
			r.DriftedUserIDs = append(r.DriftedUserIDs, shared.ID(id))
		}
		drifted.Close()
		if err := drifted.Err(); err != nil {
			return fmt.Errorf("shadow drift sample: %w", err)
		}
		var phase string
		var projection bool
		err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT cutover_phase FROM identity_policies WHERE tenant_id=$1), 'legacy'),
			COALESCE((SELECT projection_enabled FROM identity_backfill_fences WHERE tenant_id=$1), false)`, t).Scan(&phase, &projection)
		if err != nil {
			return fmt.Errorf("shadow cutover state: %w", err)
		}
		r.DriftTotal = r.MissingMemberships + r.RoleDrift + r.StateDrift + r.DigestMismatches + r.RoutingMismatches + r.AuthenticatorMismatches
		r.Aborted = r.DriftTotal > thresholds.MaxDrift
		r.Ready = !r.Aborted && r.DriftTotal == 0 && r.Ambiguous == 0 && r.MissingMemberships == 0
		// Rollback is prepared while users is still authoritative: the derived rows can be dropped
		// without touching any users consumer.
		r.RollbackPrepared = phase != "declared"
		details, err := json.Marshal(map[string]any{"drifted_user_ids": r.DriftedUserIDs, "cutover_phase": phase, "projection_enabled": projection})
		if err != nil {
			return fmt.Errorf("encode shadow details: %w", err)
		}
		var run *string
		if !runID.IsZero() {
			v := runID.String()
			run = &v
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_shadow_reports
			(tenant_id, id, run_id, legacy_users, bootstrap_skipped, memberships, missing_memberships, credentials_expected, credentials_matched,
			 authenticators_expected, authenticators_matched, authenticator_mismatches, digest_mismatches, routing_mismatches, role_drift, state_drift,
			 placeholders, ambiguous, drift_total, max_drift, aborted, ready, rollback_prepared, details, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
			t, reportID.String(), run, r.LegacyUsers, r.BootstrapSkipped, r.Memberships, r.MissingMemberships, r.CredentialsExpected, r.CredentialsMatched,
			r.AuthenticatorsExpected, r.AuthenticatorsMatched, r.AuthenticatorMismatches, r.DigestMismatches, r.RoutingMismatches, r.RoleDrift, r.StateDrift,
			r.Placeholders, r.Ambiguous, r.DriftTotal, thresholds.MaxDrift, r.Aborted, r.Ready, r.RollbackPrepared, string(details), now); err != nil {
			return fmt.Errorf("record shadow report: %w", err)
		}
		return nil
	})
	return r, err
}

// Rollback drops the tenant's derived identity rows and disables projection. users, its consumers,
// the audit log, backfill runs and shadow reports are untouched.
func (s *IdentityFoundationStore) Rollback(ctx context.Context, tenantID shared.ID, actor string, now time.Time) error {
	if actor == "" {
		return fmt.Errorf("%w: rollback actor is required", shared.ErrValidation)
	}
	return s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, identityBackfillLockClass, tenantID.String()); err != nil {
			return fmt.Errorf("backfill lock: %w", err)
		}
		var phase string
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT cutover_phase FROM identity_policies WHERE tenant_id=$1), 'legacy')`, tenantID.String()).Scan(&phase); err != nil {
			return fmt.Errorf("read cutover phase: %w", err)
		}
		if phase == "declared" {
			return fmt.Errorf("%w: %w: tenant has declared cutover", shared.ErrConflict, ports.ErrIdentityLifecycle)
		}
		// Waits for every in-flight user write that read projection enabled and blocks new ones
		// until this rollback commits, so no derived row is written behind the deletes below.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM identity_backfill_fences WHERE tenant_id=$1 FOR UPDATE`, tenantID.String()); err != nil {
			return fmt.Errorf("lock backfill fence: %w", err)
		}
		counts := map[string]int64{}
		for _, step := range []struct{ name, sql string }{
			{"projection", `UPDATE identity_backfill_fences SET projection_enabled=false, checkpoint_user_id='', fence_token=fence_token+1, run_id='', updated_at=$2 WHERE tenant_id=$1`},
			{"runs", `UPDATE identity_backfill_runs SET state='failed', last_error='rolled back', finished_at=$2, updated_at=$2 WHERE tenant_id=$1 AND state='running'`},
			{"transactions", `DELETE FROM identity_transactions WHERE tenant_id=$1`},
			{"sessions", `DELETE FROM identity_sessions WHERE tenant_id=$1`},
			{"invitations", `DELETE FROM identity_invitations WHERE tenant_id=$1`},
			{"authenticators", `DELETE FROM identity_authenticators WHERE tenant_id=$1`},
			{"credentials", `DELETE FROM identity_credentials WHERE tenant_id=$1`},
			{"memberships", `DELETE FROM identity_memberships WHERE tenant_id=$1`},
			{"items", `DELETE FROM identity_backfill_items WHERE tenant_id=$1`},
			{"connections", `UPDATE identity_connections SET enabled=false, updated_at=GREATEST($2, created_at) WHERE tenant_id=$1 AND enabled`},
		} {
			args := []any{tenantID.String()}
			if strings.Contains(step.sql, "$2") {
				args = append(args, now)
			}
			tag, err := tx.Exec(ctx, step.sql, args...)
			if err != nil {
				return fmt.Errorf("rollback %s: %w", step.name, identityPersistenceError(err))
			}
			counts[step.name] = tag.RowsAffected()
		}
		meta := map[string]string{}
		for k, v := range counts {
			meta[k] = strconv.FormatInt(v, 10)
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{Actor: actor, Action: "identity.projection_rolled_back", Target: tenantID.String(), At: now, Metadata: meta})
	})
}
