package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Legacy projection keeps the derived identity rows of one legacy user equal to its users row.
// users.api_key_hash stays the only writer of record: this is called only from the UserRepository
// write methods, inside the same tenant transaction as the users write, so the users row, the
// derived credential and the exact-digest routing index commit or roll back together. No other
// code path writes a legacy-projection credential.

// legacyUserState is the users row as it was before the write.
type legacyUserState struct {
	exists   bool
	hash     string
	disabled bool
}

func lockLegacyUserState(ctx context.Context, tx pgx.Tx, tenantID shared.ID, id shared.ID) (legacyUserState, error) {
	var state legacyUserState
	err := tx.QueryRow(ctx, `SELECT api_key_hash, disabled FROM users WHERE ownership_tenant_id=$1 AND id=$2 FOR UPDATE`,
		tenantID.String(), id.String()).Scan(&state.hash, &state.disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return legacyUserState{}, nil
	}
	if err != nil {
		return legacyUserState{}, fmt.Errorf("lock legacy user: %w", err)
	}
	state.exists = true
	return state, nil
}

// identityProjectionEnabled reports whether the tenant's backfill has enabled write-path projection.
// The fence row is read FOR KEY SHARE. Rollback locks that row FOR UPDATE before it deletes any
// derived row, which conflicts with this lock: a user write either finishes before the rollback
// deletes, or waits and then reads projection disabled, so no derived row outlives a rollback. A
// backfill batch holds the fence only FOR NO KEY UPDATE, which does not conflict, so a user write
// holding its users row lock never waits on a batch that is itself waiting for that row.
func identityProjectionEnabled(ctx context.Context, tx pgx.Tx, tenantID shared.ID) (bool, error) {
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT projection_enabled FROM identity_backfill_fences WHERE tenant_id=$1 FOR KEY SHARE`, tenantID.String()).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read identity projection state: %w", err)
	}
	return enabled, nil
}

func legacyFingerprint(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:])
}

// projectLegacyUser mirrors u into its membership and credential. before is the locked prior row.
func projectLegacyUser(ctx context.Context, tx pgx.Tx, tenantID shared.ID, before legacyUserState, u *user.User, now time.Time) error {
	if u.ID == ports.IdentityBootstrapUserID {
		return nil
	}
	enabled, err := identityProjectionEnabled(ctx, tx, tenantID)
	if err != nil || !enabled {
		return err
	}
	var membershipID, personID string
	err = tx.QueryRow(ctx, `SELECT id, person_id FROM identity_memberships WHERE tenant_id=$1 AND legacy_user_id=$2 FOR UPDATE`,
		tenantID.String(), u.ID.String()).Scan(&membershipID, &personID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if before.exists {
			// An existing user without a membership is still awaiting (or blocked in) backfill
			// classification; the backfill reads the current row under lock when it gets there.
			return nil
		}
		return identityPersistenceError(projectNewLegacyUser(ctx, tx, tenantID, u, now))
	case err != nil:
		return fmt.Errorf("lock legacy membership: %w", err)
	}
	if err := syncLegacyMembership(ctx, tx, tenantID, shared.ID(membershipID), u, now); err != nil {
		return identityPersistenceError(err)
	}
	return identityPersistenceError(syncLegacyCredential(ctx, tx, tenantID, shared.ID(membershipID), shared.ID(personID), before, u, now))
}

// projectNewLegacyUser projects a user created through the legacy write path after projection was
// enabled. Its key was just issued by that write, so its credential is real.
func projectNewLegacyUser(ctx context.Context, tx pgx.Tx, tenantID shared.ID, u *user.User, now time.Time) error {
	personID := legacyIdentityID("person_", tenantID, u.ID)
	membershipID := legacyIdentityID("membership_", tenantID, u.ID)
	if err := createLegacyPerson(ctx, tx, personID, "legacy user "+u.ID.String()); err != nil {
		return err
	}
	if err := upsertLegacyMembership(ctx, tx, tenantID, membershipID, personID, u, now); err != nil {
		return err
	}
	class, credentialClass := ports.IdentityBackfillMigrated, ports.IdentityCredentialReal
	if u.Disabled {
		class = ports.IdentityBackfillSuspended
	}
	if identityDigestPattern.MatchString(u.APIKeyHash) {
		if err := upsertLegacyCredential(ctx, tx, tenantID, membershipID, personID, u.ID, u.APIKeyHash, true, !u.Disabled, now); err != nil {
			return err
		}
	} else {
		class, credentialClass = ports.IdentityBackfillAmbiguousCorrupt, ports.IdentityCredentialAmbiguous
	}
	return upsertBackfillItem(ctx, tx, tenantID, u.ID, class, credentialClass, personID, membershipID, u.APIKeyHash, "", now)
}

func legacyMembershipState(u *user.User) (state string, suspension *string) {
	if u.Disabled {
		manual := string(ports.IdentityTransitionManual)
		return string(ports.IdentityMembershipSuspended), &manual
	}
	return string(ports.IdentityMembershipActive), nil
}

func upsertLegacyMembership(ctx context.Context, tx pgx.Tx, tenantID, membershipID, personID shared.ID, u *user.User, now time.Time) error {
	state, suspension := legacyMembershipState(u)
	if _, err := tx.Exec(ctx, `INSERT INTO identity_memberships
		(tenant_id, id, person_id, legacy_user_id, role, state, suspension_source, last_transition_source, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'legacy_projection',$8,$8) ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID.String(), membershipID.String(), personID.String(), u.ID.String(), string(u.Role), state, suspension, now); err != nil {
		return fmt.Errorf("project membership: %w", err)
	}
	return syncLegacyMembership(ctx, tx, tenantID, membershipID, u, now)
}

func syncLegacyMembership(ctx context.Context, tx pgx.Tx, tenantID, membershipID shared.ID, u *user.User, now time.Time) error {
	state, suspension := legacyMembershipState(u)
	if _, err := tx.Exec(ctx, `UPDATE identity_memberships SET role=$3, state=$4, suspension_source=$5,
		last_transition_source='legacy_projection', updated_at=GREATEST($6, created_at)
		WHERE tenant_id=$1 AND id=$2 AND (role IS DISTINCT FROM $3 OR state IS DISTINCT FROM $4 OR suspension_source IS DISTINCT FROM $5)`,
		tenantID.String(), membershipID.String(), string(u.Role), state, suspension, now); err != nil {
		return fmt.Errorf("project membership: %w", err)
	}
	return nil
}

// syncLegacyCredential mirrors users.api_key_hash and users.disabled into the derived credential.
// The derived credential is routable only while the user is enabled and its digest came from key
// issuance. A hash change that coincides with disabling is the disable path replacing the key with
// an unusable digest, so it clears issuance; any other hash change is a rotation. Re-enabling
// without a rotation therefore restores exactly what users restores, which is nothing once the
// disable replaced the key.
func syncLegacyCredential(ctx context.Context, tx pgx.Tx, tenantID, membershipID, personID shared.ID, before legacyUserState, u *user.User, now time.Time) error {
	var (
		id, digest, state string
		issued            bool
	)
	err := tx.QueryRow(ctx, `SELECT id, digest, state, legacy_key_issued FROM identity_credentials
		WHERE tenant_id=$1 AND legacy_user_id=$2 AND source='legacy_projection' FOR UPDATE`, tenantID.String(), u.ID.String()).Scan(&id, &digest, &state, &issued)
	missing := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !missing {
		return fmt.Errorf("lock legacy credential: %w", err)
	}
	valid := identityDigestPattern.MatchString(u.APIKeyHash)
	nextIssued := issued
	if before.hash != u.APIKeyHash {
		// Disable and enable both replace the key with an unusable digest, so a hash change that
		// coincides with either transition is a revocation. Only a hash change that leaves the
		// disabled flag alone is a rotation.
		nextIssued = before.disabled == u.Disabled
	}
	if !valid {
		nextIssued = false
	}
	if missing {
		// A user without a derived credential (a placeholder or unproven hash) gains one only when
		// a key is actually issued to it.
		if !nextIssued || before.hash == u.APIKeyHash {
			return nil
		}
		if err := upsertLegacyCredential(ctx, tx, tenantID, membershipID, personID, u.ID, u.APIKeyHash, true, !u.Disabled, now); err != nil {
			return err
		}
		return markLegacyItem(ctx, tx, tenantID, u, ports.IdentityCredentialReal, now)
	}
	nextDigest := digest
	if valid {
		nextDigest = u.APIKeyHash
	}
	active := nextIssued && !u.Disabled
	if nextDigest == digest && nextIssued == issued && active == (state == "active") {
		return nil
	}
	if err := setLegacyCredential(ctx, tx, tenantID, shared.ID(id), nextDigest, nextIssued, active, now); err != nil {
		return err
	}
	class := ports.IdentityCredentialReal
	if !nextIssued {
		class = ports.IdentityCredentialDisabled
	}
	return markLegacyItem(ctx, tx, tenantID, u, class, now)
}

func upsertLegacyCredential(ctx context.Context, tx pgx.Tx, tenantID, membershipID, personID, userID shared.ID, digest string, issued, active bool, now time.Time) error {
	credentialID := legacyIdentityID("credential_", tenantID, userID)
	state, revokedAt := credentialState(active, now)
	tag, err := tx.Exec(ctx, `INSERT INTO identity_credentials
		(tenant_id, id, kind, digest, membership_id, person_id, legacy_user_id, source, legacy_key_issued, state, created_at, updated_at, revoked_at)
		VALUES ($1,$2,'api_key',$3,$4,$5,$6,'legacy_projection',$7,$8,$9,$9,$10) ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID.String(), credentialID.String(), digest, membershipID.String(), personID.String(), userID.String(), issued, state, now, revokedAt)
	if err != nil {
		return fmt.Errorf("project credential: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	return setLegacyCredential(ctx, tx, tenantID, credentialID, digest, issued, active, now)
}

func credentialState(active bool, now time.Time) (string, *time.Time) {
	if active {
		return "active", nil
	}
	return "revoked", &now
}

func setLegacyCredential(ctx context.Context, tx pgx.Tx, tenantID, credentialID shared.ID, digest string, issued, active bool, now time.Time) error {
	state, revokedAt := credentialState(active, now)
	if _, err := tx.Exec(ctx, `UPDATE identity_credentials SET digest=$3, legacy_key_issued=$4, state=$5,
		revoked_at=CASE WHEN $5='active' THEN NULL ELSE COALESCE(revoked_at, $6) END, updated_at=GREATEST($7, created_at)
		WHERE tenant_id=$1 AND id=$2 AND (digest IS DISTINCT FROM $3 OR legacy_key_issued IS DISTINCT FROM $4 OR state IS DISTINCT FROM $5)`,
		tenantID.String(), credentialID.String(), digest, issued, state, revokedAt, now); err != nil {
		return fmt.Errorf("project credential: %w", err)
	}
	return nil
}

// markLegacyItem records that the write path, not the backfill, last classified the user.
func markLegacyItem(ctx context.Context, tx pgx.Tx, tenantID shared.ID, u *user.User, credentialClass ports.IdentityCredentialClass, now time.Time) error {
	class := ports.IdentityBackfillMigrated
	if u.Disabled {
		class = ports.IdentityBackfillSuspended
	}
	if _, err := tx.Exec(ctx, `UPDATE identity_backfill_items SET classification=$3, credential_class=$4, source_fingerprint=$5, updated_at=$6
		WHERE tenant_id=$1 AND id=$2`, tenantID.String(), u.ID.String(), string(class), string(credentialClass), legacyFingerprint(u.APIKeyHash), now); err != nil {
		return fmt.Errorf("record projection classification: %w", err)
	}
	return nil
}

func upsertBackfillItem(ctx context.Context, tx pgx.Tx, tenantID, userID shared.ID, class ports.IdentityBackfillClass, credentialClass ports.IdentityCredentialClass,
	personID, membershipID shared.ID, hash string, runID shared.ID, now time.Time) error {
	var person, membership, run *string
	if !personID.IsZero() {
		v := personID.String()
		person = &v
	}
	if !membershipID.IsZero() {
		v := membershipID.String()
		membership = &v
	}
	if !runID.IsZero() {
		v := runID.String()
		run = &v
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_backfill_items
		(tenant_id, id, classification, credential_class, person_id, membership_id, source_fingerprint, run_id, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (tenant_id, id) DO UPDATE SET classification=EXCLUDED.classification, credential_class=EXCLUDED.credential_class,
		  person_id=EXCLUDED.person_id, membership_id=EXCLUDED.membership_id, source_fingerprint=EXCLUDED.source_fingerprint,
		  run_id=EXCLUDED.run_id, updated_at=EXCLUDED.updated_at`,
		tenantID.String(), userID.String(), string(class), string(credentialClass), person, membership, legacyFingerprint(hash), run, now); err != nil {
		return fmt.Errorf("record backfill item: %w", err)
	}
	return nil
}
