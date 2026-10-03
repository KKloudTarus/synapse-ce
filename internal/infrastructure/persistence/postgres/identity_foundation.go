package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// IdentityFoundationStore persists the additive identity model of migration 0206. Global access is
// limited to the SECURITY DEFINER functions of that migration; every other statement runs inside a
// tenant-bound RLS transaction.
type IdentityFoundationStore struct {
	pool                  *pgxpool.Pool
	authorizationCapacity int
}

// NewIdentityFoundationStore returns a store backed by pool.
func NewIdentityFoundationStore(pool *pgxpool.Pool) (*IdentityFoundationStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: identity foundation store requires a pool", shared.ErrValidation)
	}
	return &IdentityFoundationStore{pool: pool, authorizationCapacity: 256}, nil
}

var (
	_ ports.IdentityCredentialRouter     = (*IdentityFoundationStore)(nil)
	_ ports.IdentityMembershipProjection = (*IdentityFoundationStore)(nil)
	_ ports.IdentityPersonCommands       = (*IdentityFoundationStore)(nil)
	_ ports.IdentityMembershipStore      = (*IdentityFoundationStore)(nil)
	_ ports.IdentityAuditDeliveryStore   = (*IdentityFoundationStore)(nil)
	_ ports.IdentityBackfillStore        = (*IdentityFoundationStore)(nil)
	_ ports.IdentityCutoverStore         = (*IdentityFoundationStore)(nil)
)

var identityDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// identityProjectionActor attributes platform person audit written by the legacy projection.
const identityProjectionActor = "system:identity-projection"

// identityPersistenceError maps the stable SQLSTATEs raised by the 0206 guards to domain errors.
func identityPersistenceError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "SYN01":
		return fmt.Errorf("%w: %w: %s", shared.ErrConflict, ports.ErrIdentityNotRepresentable, pgErr.Message)
	case "SYN02":
		return fmt.Errorf("%w: %w: %s", shared.ErrConflict, ports.ErrIdentityLifecycle, pgErr.Message)
	case "SYN03":
		return fmt.Errorf("%w: %w: %s", shared.ErrConflict, ports.ErrIdentityCutover, pgErr.Message)
	case "P0002":
		return fmt.Errorf("%w: %s", shared.ErrNotFound, pgErr.Message)
	case "22023", "23514":
		return fmt.Errorf("%w: %s", shared.ErrValidation, pgErr.Message)
	case "23503":
		return fmt.Errorf("%w: identity reference does not belong to this tenant or person", shared.ErrValidation)
	}
	return err
}

// legacyIdentityID derives a stable identifier for a row projected from one legacy user, so the
// projection and every backfill retry converge on the same rows.
func legacyIdentityID(prefix string, tenantID shared.ID, userID shared.ID) shared.ID {
	sum := sha256.Sum256([]byte(tenantID.String() + "\x00" + userID.String()))
	return shared.ID(prefix + hex.EncodeToString(sum[:20]))
}

func randomIdentityDigest() (string, error) {
	b := make([]byte, sha256.Size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate unusable digest: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// withIdentityTenant joins a transaction bound to tenantID by TenantTransactionRunner, or opens a
// new tenant transaction.
func (s *IdentityFoundationStore) withIdentityTenant(ctx context.Context, tenantID shared.ID, fn func(pgx.Tx) error) error {
	if tenantID.IsZero() {
		return fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	return WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		return identityPersistenceError(fn(tx))
	})
}

// RouteCredentialDigest is the exact-digest routing exception. It reveals only (tenant, kind).
func (s *IdentityFoundationStore) RouteCredentialDigest(ctx context.Context, digest string) (ports.IdentityCredentialRoute, error) {
	if !identityDigestPattern.MatchString(digest) {
		return ports.IdentityCredentialRoute{}, fmt.Errorf("route credential: %w", shared.ErrNotFound)
	}
	var tenant, kind string
	err := s.pool.QueryRow(ctx, `SELECT tenant_id, kind FROM synapse_identity_route_credential($1)`, digest).Scan(&tenant, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.IdentityCredentialRoute{}, fmt.Errorf("route credential: %w", shared.ErrNotFound)
	}
	if err != nil {
		return ports.IdentityCredentialRoute{}, fmt.Errorf("route credential: %w", err)
	}
	route := ports.IdentityCredentialRoute{TenantID: shared.ID(tenant), Kind: ports.IdentityCredentialKind(kind)}
	if !route.Kind.Valid() {
		return ports.IdentityCredentialRoute{}, fmt.Errorf("route credential: unknown kind %q", kind)
	}
	return route, nil
}

// ActiveMembershipsForPerson is the exact-authenticated-person projection exception.
func (s *IdentityFoundationStore) ActiveMembershipsForPerson(ctx context.Context, credentialDigest string, personID shared.ID) ([]ports.IdentityMembershipChoice, error) {
	out := []ports.IdentityMembershipChoice{}
	if !identityDigestPattern.MatchString(credentialDigest) || personID.IsZero() {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT tenant_id, membership_id, tenant_label, role FROM synapse_identity_person_memberships($1, $2)`,
		credentialDigest, personID.String())
	if err != nil {
		return nil, fmt.Errorf("project person memberships: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tenant, membership, label, role string
		if err := rows.Scan(&tenant, &membership, &label, &role); err != nil {
			return nil, fmt.Errorf("scan person membership: %w", err)
		}
		out = append(out, ports.IdentityMembershipChoice{TenantID: shared.ID(tenant), MembershipID: shared.ID(membership), TenantLabel: label, Role: user.Role(role)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("project person memberships: %w", err)
	}
	return out, nil
}

// PersonEpoch reads the current epoch of the credential-bound person.
func (s *IdentityFoundationStore) PersonEpoch(ctx context.Context, credentialDigest string, personID shared.ID) (int64, error) {
	if !identityDigestPattern.MatchString(credentialDigest) || personID.IsZero() {
		return 0, fmt.Errorf("person epoch: %w", shared.ErrNotFound)
	}
	var epoch *int64
	if err := s.pool.QueryRow(ctx, `SELECT synapse_identity_person_epoch($1, $2)`, credentialDigest, personID.String()).Scan(&epoch); err != nil {
		return 0, fmt.Errorf("person epoch: %w", err)
	}
	if epoch == nil {
		return 0, fmt.Errorf("person epoch: %w", shared.ErrNotFound)
	}
	return *epoch, nil
}

// ApplyPersonCommand runs the platform-owned person command. Inside a bound tenant transaction it
// joins that transaction, so a caller's consequential mutation and the person audit commit
// together; otherwise it is one autocommit statement. The runtime role holds no EXECUTE on the
// command, so this succeeds only on a pool connected as a platform operator (the schema owner).
func (s *IdentityFoundationStore) ApplyPersonCommand(ctx context.Context, personID shared.ID, action ports.IdentityPersonAction, actor, reason string) (ports.IdentityPersonCommandResult, error) {
	if bound, ok := ctx.Value(tenantTransactionKey{}).(tenantTransaction); ok {
		return applyPersonCommand(ctx, bound.tx, personID, action, actor, reason)
	}
	return scanPersonCommand(action, s.pool.QueryRow(ctx, personCommandSQL, personID.String(), string(action), actor, reason))
}

const personCommandSQL = `SELECT person_epoch, audit_id, obligations FROM synapse_identity_person_command($1, $2, $3, $4)`

func applyPersonCommand(ctx context.Context, tx pgx.Tx, personID shared.ID, action ports.IdentityPersonAction, actor, reason string) (ports.IdentityPersonCommandResult, error) {
	return scanPersonCommand(action, tx.QueryRow(ctx, personCommandSQL, personID.String(), string(action), actor, reason))
}

// createLegacyPerson idempotently creates the person of a projected legacy user through the only
// person command the runtime role may run. The database fixes the action and the audit actor
// (identityProjectionActor).
func createLegacyPerson(ctx context.Context, tx pgx.Tx, personID shared.ID, reason string) error {
	_, err := scanPersonCommand(ports.IdentityPersonCreated,
		tx.QueryRow(ctx, `SELECT person_epoch, audit_id, obligations FROM synapse_identity_create_person($1, $2)`, personID.String(), reason))
	return err
}

func scanPersonCommand(action ports.IdentityPersonAction, row pgx.Row) (ports.IdentityPersonCommandResult, error) {
	var out ports.IdentityPersonCommandResult
	err := row.Scan(&out.PersonEpoch, &out.AuditID, &out.Obligations)
	if err != nil {
		return ports.IdentityPersonCommandResult{}, fmt.Errorf("person command %s: %w", action, identityPersistenceError(err))
	}
	return out, nil
}

const identityMembershipCols = `tenant_id, id, person_id, COALESCE(legacy_user_id, ''), role, state, COALESCE(suspension_source, ''), epoch, version, updated_at`

func scanIdentityMembership(row pgx.Row) (ports.IdentityMembership, error) {
	var (
		m                                                   ports.IdentityMembership
		tenant, id, person, legacy, role, state, suspension string
	)
	if err := row.Scan(&tenant, &id, &person, &legacy, &role, &state, &suspension, &m.Epoch, &m.Version, &m.UpdatedAt); err != nil {
		return ports.IdentityMembership{}, err
	}
	m.TenantID, m.ID, m.PersonID, m.LegacyUserID = shared.ID(tenant), shared.ID(id), shared.ID(person), shared.ID(legacy)
	m.Role, m.State, m.SuspensionSource = user.Role(role), ports.IdentityMembershipState(state), ports.IdentityTransitionSource(suspension)
	return m, nil
}

// GetMembership reads one membership of tenantID.
func (s *IdentityFoundationStore) GetMembership(ctx context.Context, tenantID, membershipID shared.ID) (ports.IdentityMembership, error) {
	var out ports.IdentityMembership
	err := s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		m, err := scanIdentityMembership(tx.QueryRow(ctx, `SELECT `+identityMembershipCols+` FROM identity_memberships WHERE tenant_id=$1 AND id=$2`, tenantID.String(), membershipID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("get membership: %w", shared.ErrNotFound)
		}
		out = m
		return err
	})
	return out, err
}

// AddMembership adds an existing person to tenantID. Before the tenant declares cutover this is
// not representable and returns ErrIdentityNotRepresentable. The person gains a tenant-local users
// row whose id is the membership legacy user ID, so every existing users(ownership_tenant_id, id)
// foreign key accepts the member without a second global users row for the same legacy ID.
func (s *IdentityFoundationStore) AddMembership(ctx context.Context, tenantID, personID shared.ID, name string, role user.Role, actor string, at time.Time) (ports.IdentityMembership, error) {
	if !role.Valid() || personID.IsZero() || actor == "" {
		return ports.IdentityMembership{}, fmt.Errorf("%w: membership role, person and actor are required", shared.ErrValidation)
	}
	// The projected users row never carries a usable bearer key: after declaration the member
	// authenticates through identity credentials, not users.api_key_hash.
	unusable, err := randomIdentityDigest()
	if err != nil {
		return ports.IdentityMembership{}, err
	}
	projected, err := user.New(legacyIdentityID("member_", tenantID, personID), tenantID.String(), name, role, unusable, at)
	if err != nil {
		return ports.IdentityMembership{}, err
	}
	membershipID := legacyIdentityID("membership_", tenantID, personID)
	var out ports.IdentityMembership
	err = s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT synapse_identity_project_member_user($1,$2,$3,$4,$5,$6)`,
			tenantID.String(), projected.ID.String(), projected.Name, string(role), unusable, at); err != nil {
			return fmt.Errorf("project member user: %w", err)
		}
		m, err := scanIdentityMembership(tx.QueryRow(ctx, `INSERT INTO identity_memberships
			(tenant_id, id, person_id, legacy_user_id, role, state, last_transition_source, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,'active','manual',$6,$6) RETURNING `+identityMembershipCols,
			tenantID.String(), membershipID.String(), personID.String(), projected.ID.String(), string(role), at))
		if err != nil {
			return fmt.Errorf("add membership: %w", err)
		}
		out = m
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{
			Actor: actor, Action: "identity.membership_added", Target: m.ID.String(), At: at,
			Metadata: map[string]string{"person_id": personID.String(), "legacy_user_id": projected.ID.String(), "role": string(role)},
		})
	})
	return out, err
}

// ChangeMembership applies one audited lifecycle or role command. It serializes against other
// administrator changes by locking the tenant's active administrator rows in id order, so two
// concurrent demotions cannot remove the last administrator.
func (s *IdentityFoundationStore) ChangeMembership(ctx context.Context, tenantID, membershipID shared.ID, change ports.IdentityMembershipChange) (ports.IdentityMembership, error) {
	if change.Actor == "" || change.At.IsZero() {
		return ports.IdentityMembership{}, fmt.Errorf("%w: membership change actor and time are required", shared.ErrValidation)
	}
	var out ports.IdentityMembership
	err := s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Representability first: before declaration users is the writer of record, so no native
		// membership change is meaningful regardless of the roster.
		var phase string
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT cutover_phase FROM identity_policies WHERE tenant_id=$1 FOR UPDATE), 'legacy')`, tenantID.String()).Scan(&phase); err != nil {
			return fmt.Errorf("read cutover phase: %w", err)
		}
		if phase != "declared" {
			return fmt.Errorf("%w: %w: tenant has not declared cutover", shared.ErrConflict, ports.ErrIdentityNotRepresentable)
		}
		admins, err := lockActiveAdmins(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		current, err := scanIdentityMembership(tx.QueryRow(ctx, `SELECT `+identityMembershipCols+` FROM identity_memberships WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), membershipID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("change membership: %w", shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("change membership: %w", err)
		}
		if change.ExpectedVersion != 0 && change.ExpectedVersion != current.Version {
			return fmt.Errorf("%w: membership version is %d, not %d", shared.ErrConflict, current.Version, change.ExpectedVersion)
		}
		role, state, suspension, transition := current.Role, current.State, "", string(ports.IdentityTransitionManual)
		source := change.Source
		if source == "" {
			source = ports.IdentityTransitionManual
		}
		if source != ports.IdentityTransitionManual && source != ports.IdentityTransitionSignal {
			return fmt.Errorf("%w: unknown transition source %q", shared.ErrValidation, source)
		}
		var approvedBy *string
		var rejoinedAt *time.Time
		switch change.Kind {
		case ports.IdentityMembershipChangeRole:
			if !change.Role.Valid() {
				return fmt.Errorf("%w: invalid role", shared.ErrValidation)
			}
			role = change.Role
			if state == ports.IdentityMembershipSuspended {
				suspension = string(current.SuspensionSource)
			}
		case ports.IdentityMembershipChangeSuspend:
			state, suspension, transition = ports.IdentityMembershipSuspended, string(source), string(source)
		case ports.IdentityMembershipChangeReactivate:
			state, transition = ports.IdentityMembershipActive, string(source)
		case ports.IdentityMembershipChangeRemove:
			state = ports.IdentityMembershipRemoved
		case ports.IdentityMembershipChangeRejoin:
			if change.ApprovedBy == "" {
				return fmt.Errorf("%w: rejoin requires an approver", shared.ErrValidation)
			}
			state, transition = ports.IdentityMembershipActive, "rejoin"
			approvedBy, rejoinedAt = &change.ApprovedBy, &change.At
		default:
			return fmt.Errorf("%w: unknown membership change %q", shared.ErrValidation, change.Kind)
		}
		wasAdmin := current.Role == user.RoleAdmin && current.State == ports.IdentityMembershipActive
		staysAdmin := role == user.RoleAdmin && state == ports.IdentityMembershipActive
		if wasAdmin && !staysAdmin && admins <= 1 {
			return fmt.Errorf("%w: cannot remove the last active administrator of tenant %q", shared.ErrConflict, tenantID)
		}
		var suspensionArg *string
		if suspension != "" {
			suspensionArg = &suspension
		}
		updated, err := scanIdentityMembership(tx.QueryRow(ctx, `UPDATE identity_memberships SET role=$3, state=$4, suspension_source=$5,
			last_transition_source=$6, rejoin_approved_by=COALESCE($7, rejoin_approved_by), rejoined_at=COALESCE($8, rejoined_at), updated_at=$9
			WHERE tenant_id=$1 AND id=$2 RETURNING `+identityMembershipCols,
			tenantID.String(), membershipID.String(), string(role), string(state), suspensionArg, transition, approvedBy, rejoinedAt, change.At))
		if err != nil {
			return fmt.Errorf("change membership: %w", err)
		}
		if !updated.LegacyUserID.IsZero() {
			// After declaration the membership is authoritative; keep its tenant-local users row
			// consistent so ownership, assignee and inbox eligibility follow it.
			if _, err := tx.Exec(ctx, `SELECT synapse_identity_mirror_member_user($1,$2,$3)`,
				tenantID.String(), updated.ID.String(), change.At); err != nil {
				return fmt.Errorf("mirror membership user: %w", err)
			}
		}
		out = updated
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{
			Actor: change.Actor, Action: "identity.membership_" + string(change.Kind), Target: membershipID.String(), At: change.At,
			Metadata: map[string]string{
				"person_id": updated.PersonID.String(), "role": string(updated.Role), "state": string(updated.State),
				"source": string(source), "epoch": strconv.FormatInt(updated.Epoch, 10),
			},
		})
	})
	return out, err
}

func lockActiveAdmins(ctx context.Context, tx pgx.Tx, tenantID shared.ID) (int, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM identity_memberships WHERE tenant_id=$1 AND role='admin' AND state='active' ORDER BY id FOR UPDATE`, tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("lock administrators: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("lock administrators: %w", err)
	}
	return count, nil
}

// CurrentEpochs returns the revocation epochs a session must still match.
func (s *IdentityFoundationStore) CurrentEpochs(ctx context.Context, tenantID, membershipID, connectionID shared.ID, credentialDigest string) (ports.IdentityEpochs, error) {
	var out ports.IdentityEpochs
	var personID string
	err := s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT person_id, epoch FROM identity_memberships WHERE tenant_id=$1 AND id=$2 AND state='active'`,
			tenantID.String(), membershipID.String()).Scan(&personID, &out.Membership)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("membership epoch: %w", shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("membership epoch: %w", err)
		}
		if !connectionID.IsZero() {
			err := tx.QueryRow(ctx, `SELECT epoch FROM identity_connections WHERE tenant_id=$1 AND id=$2 AND enabled`,
				tenantID.String(), connectionID.String()).Scan(&out.Connection)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("connection epoch: %w", shared.ErrNotFound)
			}
			if err != nil {
				return fmt.Errorf("connection epoch: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return ports.IdentityEpochs{}, err
	}
	person, err := s.PersonEpoch(ctx, credentialDigest, shared.ID(personID))
	if err != nil {
		return ports.IdentityEpochs{}, err
	}
	out.Person = person
	return out, nil
}

// identityDeliveryBackoff bounds the delay before the next delivery attempt.
func identityDeliveryBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 10 {
		attempts = 10
	}
	return time.Duration(1<<uint(attempts-1)) * 30 * time.Second
}

// DeliverPersonAudit appends up to limit due person-audit obligations to the tenant audit chain.
// Each delivery runs in a savepoint: a failed append increments the attempt counter and schedules a
// bounded retry, and the final permitted failure marks the obligation exhausted. The audit append is
// idempotent on the obligation, so a crash after commit cannot duplicate it.
func (s *IdentityFoundationStore) DeliverPersonAudit(ctx context.Context, tenantID shared.ID, now time.Time, limit int) (ports.IdentityDeliveryStats, error) {
	if limit < 1 || limit > 500 {
		return ports.IdentityDeliveryStats{}, fmt.Errorf("%w: delivery limit must be between 1 and 500", shared.ErrValidation)
	}
	var stats ports.IdentityDeliveryStats
	err := s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, person_id, actor, action, reason, audit_hash, occurred_at, attempts, max_attempts
			FROM identity_person_audit_deliveries
			WHERE tenant_id=$1 AND state='pending' AND next_attempt_at <= $2
			ORDER BY next_attempt_at, id LIMIT $3 FOR UPDATE SKIP LOCKED`, tenantID.String(), now, limit)
		if err != nil {
			return fmt.Errorf("claim person audit deliveries: %w", err)
		}
		type obligation struct {
			id                                    int64
			person, actor, action, reason, digest string
			occurred                              time.Time
			attempts, max                         int
		}
		var due []obligation
		for rows.Next() {
			var o obligation
			if err := rows.Scan(&o.id, &o.person, &o.actor, &o.action, &o.reason, &o.digest, &o.occurred, &o.attempts, &o.max); err != nil {
				rows.Close()
				return fmt.Errorf("scan person audit delivery: %w", err)
			}
			due = append(due, o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("claim person audit deliveries: %w", err)
		}
		for _, o := range due {
			id := strconv.FormatInt(o.id, 10)
			appendErr := appendOnNested(ctx, tx, tenantID, ports.AuditEntry{
				Actor: o.actor, Action: "identity." + o.action, Target: o.person, At: o.occurred,
				Metadata: map[string]string{"idempotency_key": "person-audit:" + id, "person_audit_id": id, "person_audit_hash": o.digest, "reason": o.reason},
			})
			attempts := o.attempts + 1
			if appendErr == nil {
				if _, err := tx.Exec(ctx, `UPDATE identity_person_audit_deliveries SET state='delivered', attempts=$3, last_attempt_at=$4,
					delivered_at=$4, last_error='' WHERE tenant_id=$1 AND id=$2`, tenantID.String(), o.id, attempts, now); err != nil {
					return fmt.Errorf("mark person audit delivered: %w", err)
				}
				stats.Delivered++
				continue
			}
			state := "pending"
			if attempts >= o.max {
				state = "exhausted"
				stats.Exhausted++
			} else {
				stats.Failed++
			}
			message := appendErr.Error()
			if len(message) > 512 {
				message = message[:512]
			}
			if _, err := tx.Exec(ctx, `UPDATE identity_person_audit_deliveries SET state=$3, attempts=$4, last_attempt_at=$5,
				next_attempt_at=$6, last_error=$7 WHERE tenant_id=$1 AND id=$2`,
				tenantID.String(), o.id, state, attempts, now, now.Add(identityDeliveryBackoff(attempts)), message); err != nil {
				return fmt.Errorf("record person audit delivery failure: %w", err)
			}
		}
		return nil
	})
	return stats, err
}

// DeliveryStatus reports the observable delivery state of tenantID.
func (s *IdentityFoundationStore) DeliveryStatus(ctx context.Context, tenantID shared.ID) (ports.IdentityDeliveryStatus, error) {
	var out ports.IdentityDeliveryStatus
	err := s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var oldest *time.Time
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='pending'), count(*) FILTER (WHERE state='delivered'),
			count(*) FILTER (WHERE state='exhausted'), COALESCE(max(attempts), 0), min(created_at) FILTER (WHERE state='pending')
			FROM identity_person_audit_deliveries WHERE tenant_id=$1`, tenantID.String()).Scan(
			&out.Pending, &out.Delivered, &out.Exhausted, &out.MaxAttempts, &oldest); err != nil {
			return fmt.Errorf("person audit delivery status: %w", err)
		}
		if oldest != nil {
			out.OldestPending = *oldest
		}
		return nil
	})
	return out, err
}
