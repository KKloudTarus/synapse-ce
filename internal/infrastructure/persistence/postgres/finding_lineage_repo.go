package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const findingIdentityColumns = `tenant_id,cycle_id,id,producer_kind,finding_kind,canonicalization_version,
	fingerprint_schema_version,lineage_fingerprint,target_identity_schema_version,target_identity_canonical,
	canonical_identity_fields,first_seen_snapshot_id,created_at`

const findingObservationColumns = `tenant_id,cycle_id,id,snapshot_id,identity_id,producer_kind,finding_kind,target_canonical,
	source_finding_id,source_occurrence_id,severity,risk_score_milli,component_version,location,reachability,
	evidence_digest,scanner_provenance,observed_at`

const findingCandidateColumns = `tenant_id,cycle_id,snapshot_id,id,producer_kind,finding_kind,reason,fingerprint_schema_version,
	fingerprint,source_reference_hash,candidate_set_hash,status,version,created_at,resolved_at,superseded_at,
	COALESCE(superseded_by_candidate_id,'')`

type FindingLineageRepository struct{ pool *pgxpool.Pool }

func NewFindingLineageRepository(pool *pgxpool.Pool) *FindingLineageRepository {
	return &FindingLineageRepository{pool: pool}
}

var _ ports.FindingLineageRepository = (*FindingLineageRepository)(nil)

func (repository *FindingLineageRepository) CreateIdentityWithObservation(ctx context.Context, identity findinglineage.Identity, observation findinglineage.Observation) error {
	identity.TenantID = shared.TenantOrDefault(identity.TenantID)
	observation.TenantID = shared.TenantOrDefault(observation.TenantID)
	if err := identity.Validate(); err != nil {
		return err
	}
	if err := observation.Validate(); err != nil {
		return err
	}
	if identity.TenantID != observation.TenantID || identity.CycleID != observation.CycleID || identity.ID != observation.IdentityID ||
		identity.FirstSeenSnapshotID != observation.SnapshotID || identity.ProducerKind != observation.ProducerKind ||
		identity.FindingKind != observation.FindingKind || identity.TargetIdentityCanonical != observation.TargetCanonical {
		return fmt.Errorf("%w: identity and first observation do not share ownership", shared.ErrValidation)
	}
	provenance, err := json.Marshal(observation.ScannerProvenance)
	if err != nil {
		return fmt.Errorf("encode finding observation provenance: %w", err)
	}
	return WithTenant(ctx, repository.pool, identity.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO finding_identities(
			tenant_id,cycle_id,id,producer_kind,finding_kind,canonicalization_version,fingerprint_schema_version,
			lineage_fingerprint,target_identity_schema_version,target_identity_canonical,canonical_identity_fields,
			first_seen_snapshot_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			identity.TenantID.String(), identity.CycleID.String(), identity.ID.String(), identity.ProducerKind, identity.FindingKind,
			identity.CanonicalizationVersion, identity.FingerprintSchemaVersion, identity.LineageFingerprint,
			identity.TargetIdentitySchemaVersion, identity.TargetIdentityCanonical, identity.CanonicalIdentityFields,
			identity.FirstSeenSnapshotID.String(), identity.CreatedAt); err != nil {
			return mapPostgresError(err, "create finding identity")
		}
		if err := insertFindingObservation(ctx, tx, observation, provenance); err != nil {
			return err
		}
		return nil
	})
}

func (repository *FindingLineageRepository) AppendObservation(ctx context.Context, observation findinglineage.Observation) error {
	observation.TenantID = shared.TenantOrDefault(observation.TenantID)
	if err := observation.Validate(); err != nil {
		return err
	}
	provenance, err := json.Marshal(observation.ScannerProvenance)
	if err != nil {
		return fmt.Errorf("encode finding observation provenance: %w", err)
	}
	return WithTenant(ctx, repository.pool, observation.TenantID.String(), func(tx pgx.Tx) error {
		existing, err := loadFindingObservation(ctx, tx, observation.TenantID, observation.CycleID, observation.ID, "")
		if err == nil {
			if reflect.DeepEqual(existing, observation) {
				return nil
			}
			return fmt.Errorf("%w: observation id was reused", shared.ErrConflict)
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return err
		}
		if err := insertFindingObservation(ctx, tx, observation, provenance); err != nil {
			return err
		}
		return nil
	})
}

func (repository *FindingLineageRepository) AppendAlias(ctx context.Context, alias findinglineage.Alias) (bool, error) {
	alias.TenantID = shared.TenantOrDefault(alias.TenantID)
	if err := alias.Validate(); err != nil {
		return false, err
	}
	created := false
	err := WithTenant(ctx, repository.pool, alias.TenantID.String(), func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO finding_identity_aliases(
			tenant_id,cycle_id,id,identity_id,producer_kind,finding_kind,target_canonical,schema_version,fingerprint,approved_by,approved_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING RETURNING id`,
			alias.TenantID.String(), alias.CycleID.String(), alias.ID.String(), alias.IdentityID.String(), alias.ProducerKind,
			alias.FindingKind, alias.TargetCanonical, alias.SchemaVersion, alias.Fingerprint, alias.ApprovedBy, alias.ApprovedAt).Scan(&id)
		if err == nil {
			created = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return mapPostgresError(err, "append finding identity alias")
		}
		var existingID string
		err = tx.QueryRow(ctx, `SELECT id FROM finding_identity_aliases WHERE tenant_id=$1 AND cycle_id=$2 AND identity_id=$3
			AND producer_kind=$4 AND finding_kind=$5 AND target_canonical=$6 AND schema_version=$7 AND fingerprint=$8`,
			alias.TenantID.String(), alias.CycleID.String(), alias.IdentityID.String(), alias.ProducerKind, alias.FindingKind,
			alias.TargetCanonical, alias.SchemaVersion, alias.Fingerprint).Scan(&existingID)
		if err == nil {
			return nil
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: alias id was reused", shared.ErrConflict)
		}
		return fmt.Errorf("read finding alias replay: %w", err)
	})
	return created, err
}

func (repository *FindingLineageRepository) GetIdentity(ctx context.Context, tenantID, cycleID, identityID shared.ID) (findinglineage.Identity, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var identity findinglineage.Identity
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		loaded, err := loadFindingIdentity(ctx, tx, tenantID, cycleID, identityID)
		if err != nil {
			return err
		}
		identity = loaded
		return nil
	})
	return identity, err
}

func (repository *FindingLineageRepository) GetObservation(ctx context.Context, tenantID, cycleID, observationID shared.ID) (findinglineage.Observation, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var observation findinglineage.Observation
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		loaded, err := loadFindingObservation(ctx, tx, tenantID, cycleID, observationID, "")
		if err != nil {
			return err
		}
		observation = loaded
		return nil
	})
	return observation, err
}

func (repository *FindingLineageRepository) GetObservationBySource(ctx context.Context, tenantID, cycleID, snapshotID shared.ID, producerKind, findingKind, targetCanonical, sourceFindingID, sourceOccurrenceID string) (findinglineage.Observation, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var observation findinglineage.Observation
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		loaded, err := scanFindingObservation(tx.QueryRow(ctx, `SELECT `+findingObservationColumns+` FROM finding_observations
			WHERE tenant_id=$1 AND cycle_id=$2 AND snapshot_id=$3 AND producer_kind=$4 AND finding_kind=$5
			AND target_canonical=$6 AND source_finding_id=$7 AND source_occurrence_id=$8`, tenantID.String(), cycleID.String(),
			snapshotID.String(), producerKind, findingKind, targetCanonical, sourceFindingID, sourceOccurrenceID))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		observation = loaded
		return nil
	})
	return observation, err
}

func (repository *FindingLineageRepository) FindIdentitiesByProducerID(ctx context.Context, tenantID, cycleID shared.ID, producerKind, findingKind, targetCanonical, sourceID string) ([]findinglineage.Identity, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	return repository.findIdentities(ctx, tenantID, `SELECT DISTINCT `+prefixedColumns("i", findingIdentityColumns)+`
		FROM finding_identities i JOIN finding_observations o
		ON o.tenant_id=i.tenant_id AND o.cycle_id=i.cycle_id AND o.identity_id=i.id
		WHERE o.tenant_id=$1 AND o.cycle_id=$2 AND o.producer_kind=$3 AND o.finding_kind=$4 AND o.target_canonical=$5
		AND (o.source_finding_id=$6 OR o.source_occurrence_id=$6) ORDER BY i.id`,
		tenantID.String(), cycleID.String(), producerKind, findingKind, targetCanonical, sourceID)
}

func (repository *FindingLineageRepository) FindIdentitiesByFingerprint(ctx context.Context, tenantID, cycleID shared.ID, producerKind, findingKind string, schemaVersion int, targetCanonical, fingerprint string) ([]findinglineage.Identity, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	return repository.findIdentities(ctx, tenantID, `SELECT `+findingIdentityColumns+` FROM finding_identities
		WHERE tenant_id=$1 AND cycle_id=$2 AND producer_kind=$3 AND finding_kind=$4 AND fingerprint_schema_version=$5
		AND target_identity_canonical=$6 AND lineage_fingerprint=$7 ORDER BY id`,
		tenantID.String(), cycleID.String(), producerKind, findingKind, schemaVersion, targetCanonical, fingerprint)
}

func (repository *FindingLineageRepository) FindIdentitiesByAlias(ctx context.Context, tenantID, cycleID shared.ID, producerKind, findingKind string, schemaVersion int, targetCanonical, fingerprint string) ([]findinglineage.Identity, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	return repository.findIdentities(ctx, tenantID, `SELECT DISTINCT `+prefixedColumns("i", findingIdentityColumns)+`
		FROM finding_identities i JOIN finding_identity_aliases a
		ON a.tenant_id=i.tenant_id AND a.cycle_id=i.cycle_id AND a.identity_id=i.id
		WHERE a.tenant_id=$1 AND a.cycle_id=$2 AND a.producer_kind=$3 AND a.finding_kind=$4 AND a.schema_version=$5
		AND a.target_canonical=$6 AND a.fingerprint=$7 ORDER BY i.id`,
		tenantID.String(), cycleID.String(), producerKind, findingKind, schemaVersion, targetCanonical, fingerprint)
}

func (repository *FindingLineageRepository) ListObservationsBySnapshot(ctx context.Context, tenantID, cycleID, snapshotID shared.ID) ([]findinglineage.Observation, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	observations := make([]findinglineage.Observation, 0)
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+findingObservationColumns+` FROM finding_observations
			WHERE tenant_id=$1 AND cycle_id=$2 AND snapshot_id=$3 ORDER BY id`, tenantID.String(), cycleID.String(), snapshotID.String())
		if err != nil {
			return fmt.Errorf("list finding observations: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			observation, err := scanFindingObservation(rows)
			if err != nil {
				return err
			}
			observations = append(observations, observation)
		}
		return rows.Err()
	})
	return observations, err
}

func (repository *FindingLineageRepository) ListOpenCandidatesBySnapshot(ctx context.Context, tenantID, cycleID, snapshotID shared.ID) ([]findinglineage.MatchCandidate, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	candidates := make([]findinglineage.MatchCandidate, 0)
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM finding_match_candidates
			WHERE tenant_id=$1 AND cycle_id=$2 AND snapshot_id=$3 AND status='open' ORDER BY id`,
			tenantID.String(), cycleID.String(), snapshotID.String())
		if err != nil {
			return fmt.Errorf("list open finding candidates: %w", err)
		}
		var ids []shared.ID
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, id := range ids {
			candidate, err := loadFindingCandidate(ctx, tx, tenantID, cycleID, id, false)
			if err != nil {
				return err
			}
			candidates = append(candidates, candidate)
		}
		return nil
	})
	return candidates, err
}

func (repository *FindingLineageRepository) ListActiveOverridesBySnapshot(ctx context.Context, tenantID, cycleID, snapshotID shared.ID) ([]findinglineage.OverrideEvent, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	events := make([]findinglineage.OverrideEvent, 0)
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (e.source_observation_id)
			e.tenant_id,e.cycle_id,e.id,e.action,e.source_observation_id,COALESCE(e.source_identity_id,''),
			COALESCE(e.target_observation_id,''),e.target_identity_id,e.actor,e.reason,e.expected_version,e.version,
			COALESCE(e.prior_event_id,''),e.content_hash,e.created_at
			FROM finding_match_override_events e
			JOIN finding_observations o ON o.tenant_id=e.tenant_id AND o.cycle_id=e.cycle_id AND o.id=e.source_observation_id
			WHERE e.tenant_id=$1 AND e.cycle_id=$2 AND o.snapshot_id=$3
			ORDER BY e.source_observation_id,e.version DESC`, tenantID.String(), cycleID.String(), snapshotID.String())
		if err != nil {
			return fmt.Errorf("list active finding overrides by snapshot: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			event, err := scanFindingOverride(rows)
			if err != nil {
				return err
			}
			events = append(events, event)
		}
		return rows.Err()
	})
	return events, err
}

func (repository *FindingLineageRepository) CreateCandidate(ctx context.Context, candidate findinglineage.MatchCandidate, supersessionEventID shared.ID) (findinglineage.MatchCandidate, bool, error) {
	candidate.TenantID = shared.TenantOrDefault(candidate.TenantID)
	if err := candidate.Validate(); err != nil {
		return findinglineage.MatchCandidate{}, false, err
	}
	var stored findinglineage.MatchCandidate
	created := false
	err := WithTenant(ctx, repository.pool, candidate.TenantID.String(), func(tx pgx.Tx) error {
		lockKey := lineageLockKey(candidate.TenantID.String(), candidate.CycleID.String(), candidate.SnapshotID.String(), candidate.ProducerKind, string(candidate.Reason), candidate.SourceReferenceHash)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
			return fmt.Errorf("lock finding match candidate subject: %w", err)
		}
		existing, err := loadFindingCandidateByIdempotency(ctx, tx, candidate)
		if err == nil {
			stored = existing
			return nil
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return err
		}
		prior, err := loadOpenFindingCandidateBySubject(ctx, tx, candidate)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return err
		}
		if err == nil {
			if supersessionEventID.IsZero() {
				return fmt.Errorf("%w: supersession event id is required", shared.ErrValidation)
			}
			priorEventID, err := latestFindingResolutionID(ctx, tx, prior.TenantID, prior.CycleID, prior.ID)
			if err != nil {
				return err
			}
			updated, event, err := findinglineage.ResolveCandidate(prior, supersessionEventID, findinglineage.ResolutionSupersede,
				"system:finding-lineage", "candidate_ref_set_changed", candidate.Refs, candidate.ID, prior.Version, priorEventID, candidate.CreatedAt)
			if err != nil {
				return err
			}
			if err := updateFindingCandidateCAS(ctx, tx, updated, prior.Version); err != nil {
				return err
			}
			if err := insertFindingResolution(ctx, tx, event); err != nil {
				return err
			}
		}
		if err := insertFindingCandidate(ctx, tx, candidate); err != nil {
			return err
		}
		stored, created = candidate, true
		return nil
	})
	return stored, created, err
}

func (repository *FindingLineageRepository) GetCandidate(ctx context.Context, tenantID, cycleID, candidateID shared.ID) (findinglineage.MatchCandidate, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var candidate findinglineage.MatchCandidate
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		loaded, err := loadFindingCandidate(ctx, tx, tenantID, cycleID, candidateID, false)
		if err != nil {
			return err
		}
		candidate = loaded
		return nil
	})
	return candidate, err
}

func (repository *FindingLineageRepository) ResolveCandidateCAS(ctx context.Context, updated findinglineage.MatchCandidate, event findinglineage.ResolutionEvent) (findinglineage.MatchCandidate, findinglineage.ResolutionEvent, bool, error) {
	updated.TenantID = shared.TenantOrDefault(updated.TenantID)
	event.TenantID = shared.TenantOrDefault(event.TenantID)
	if err := updated.Validate(); err != nil {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, err
	}
	if err := event.Validate(); err != nil {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, err
	}
	var storedCandidate findinglineage.MatchCandidate
	var storedEvent findinglineage.ResolutionEvent
	applied := false
	err := WithTenant(ctx, repository.pool, event.TenantID.String(), func(tx pgx.Tx) error {
		existing, err := loadFindingResolutionByID(ctx, tx, event.TenantID, event.CycleID, event.ID)
		if err == nil {
			if existing.ContentHash != event.ContentHash {
				return fmt.Errorf("%w: resolution event id was reused", shared.ErrConflict)
			}
			storedEvent = existing
			storedCandidate, err = loadFindingCandidate(ctx, tx, event.TenantID, event.CycleID, event.CandidateID, false)
			return err
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return err
		}
		current, err := loadFindingCandidate(ctx, tx, event.TenantID, event.CycleID, event.CandidateID, true)
		if err != nil {
			return err
		}
		priorEventID, err := latestFindingResolutionID(ctx, tx, event.TenantID, event.CycleID, event.CandidateID)
		if err != nil {
			return err
		}
		if priorEventID != event.PriorEventID {
			return fmt.Errorf("%w: resolution prior event changed", shared.ErrConflict)
		}
		wantUpdated, wantEvent, err := findinglineage.ResolveCandidate(current, event.ID, event.Action, event.Actor, event.Reason,
			event.AfterRefs, event.SuccessorCandidateID, event.ExpectedVersion, event.PriorEventID, event.CreatedAt)
		if err != nil {
			return err
		}
		if !samePostgresCandidateResolution(wantUpdated, updated) || wantEvent.ContentHash != event.ContentHash {
			return fmt.Errorf("%w: resolution event does not match candidate", shared.ErrValidation)
		}
		if err := updateFindingCandidateCAS(ctx, tx, wantUpdated, event.ExpectedVersion); err != nil {
			return err
		}
		if err := insertFindingResolution(ctx, tx, wantEvent); err != nil {
			return err
		}
		storedCandidate, storedEvent, applied = wantUpdated, wantEvent, true
		return nil
	})
	return storedCandidate, storedEvent, applied, err
}

func (repository *FindingLineageRepository) ListCandidateResolutions(ctx context.Context, tenantID, cycleID, candidateID shared.ID) ([]findinglineage.ResolutionEvent, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	events := make([]findinglineage.ResolutionEvent, 0)
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,cycle_id,candidate_id,id,action,actor,reason,before_refs,after_refs,
			COALESCE(successor_candidate_id,''),expected_version,version,COALESCE(prior_event_id,''),content_hash,created_at
			FROM finding_match_resolution_events WHERE tenant_id=$1 AND cycle_id=$2 AND candidate_id=$3 ORDER BY version`,
			tenantID.String(), cycleID.String(), candidateID.String())
		if err != nil {
			return fmt.Errorf("list finding match resolutions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			event, err := scanFindingResolution(rows)
			if err != nil {
				return err
			}
			events = append(events, event)
		}
		return rows.Err()
	})
	return events, err
}

func (repository *FindingLineageRepository) GetActiveOverride(ctx context.Context, tenantID, cycleID, sourceObservationID shared.ID) (findinglineage.OverrideEvent, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var event findinglineage.OverrideEvent
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		loaded, err := loadActiveFindingOverride(ctx, tx, tenantID, cycleID, sourceObservationID, false)
		if err != nil {
			return err
		}
		event = loaded
		return nil
	})
	return event, err
}

func (repository *FindingLineageRepository) AppendOverrideCAS(ctx context.Context, event findinglineage.OverrideEvent) (findinglineage.OverrideEvent, bool, error) {
	event.TenantID = shared.TenantOrDefault(event.TenantID)
	if err := event.Validate(); err != nil {
		return findinglineage.OverrideEvent{}, false, err
	}
	var stored findinglineage.OverrideEvent
	applied := false
	err := WithTenant(ctx, repository.pool, event.TenantID.String(), func(tx pgx.Tx) error {
		lockKey := lineageLockKey(event.TenantID.String(), event.CycleID.String(), event.SourceObservationID.String())
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
			return fmt.Errorf("lock finding override stream: %w", err)
		}
		existing, err := loadFindingOverrideByID(ctx, tx, event.TenantID, event.CycleID, event.ID)
		if err == nil {
			if existing.ContentHash != event.ContentHash {
				return fmt.Errorf("%w: override event id was reused", shared.ErrConflict)
			}
			stored = existing
			return nil
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return err
		}
		active, err := loadActiveFindingOverride(ctx, tx, event.TenantID, event.CycleID, event.SourceObservationID, true)
		if errors.Is(err, shared.ErrNotFound) {
			active = findinglineage.OverrideEvent{}
		} else if err != nil {
			return err
		}
		if active.Version != event.ExpectedVersion || active.ID != event.PriorEventID {
			return fmt.Errorf("%w: override version changed", shared.ErrConflict)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO finding_match_override_events(
			tenant_id,cycle_id,id,action,source_observation_id,source_identity_id,target_observation_id,target_identity_id,
			actor,reason,expected_version,version,prior_event_id,content_hash,created_at)
			VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,$12,NULLIF($13,''),$14,$15)`,
			event.TenantID.String(), event.CycleID.String(), event.ID.String(), string(event.Action), event.SourceObservationID.String(),
			event.SourceIdentityID.String(), event.TargetObservationID.String(), event.TargetIdentityID.String(), event.Actor, event.Reason,
			event.ExpectedVersion, event.Version, event.PriorEventID.String(), event.ContentHash, event.CreatedAt); err != nil {
			return mapPostgresError(err, "append finding match override")
		}
		stored, applied = event, true
		return nil
	})
	return stored, applied, err
}

func (repository *FindingLineageRepository) ListOverrideEvents(ctx context.Context, tenantID, cycleID, sourceObservationID shared.ID) ([]findinglineage.OverrideEvent, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	events := make([]findinglineage.OverrideEvent, 0)
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,cycle_id,id,action,source_observation_id,COALESCE(source_identity_id,''),
			COALESCE(target_observation_id,''),target_identity_id,actor,reason,expected_version,version,COALESCE(prior_event_id,''),content_hash,created_at
			FROM finding_match_override_events WHERE tenant_id=$1 AND cycle_id=$2 AND source_observation_id=$3 ORDER BY version`,
			tenantID.String(), cycleID.String(), sourceObservationID.String())
		if err != nil {
			return fmt.Errorf("list finding match overrides: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			event, err := scanFindingOverride(rows)
			if err != nil {
				return err
			}
			events = append(events, event)
		}
		return rows.Err()
	})
	return events, err
}

func (repository *FindingLineageRepository) AppendSkip(ctx context.Context, record findinglineage.SkipRecord) (bool, error) {
	record.TenantID = shared.TenantOrDefault(record.TenantID)
	if err := record.Validate(); err != nil {
		return false, err
	}
	created := false
	err := WithTenant(ctx, repository.pool, record.TenantID.String(), func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO finding_lineage_skip_records(
			tenant_id,cycle_id,snapshot_id,id,producer_kind,finding_kind,reason,source_reference_hash,detail_code,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING RETURNING id`,
			record.TenantID.String(), record.CycleID.String(), record.SnapshotID.String(), record.ID.String(), record.ProducerKind,
			record.FindingKind, string(record.Reason), record.SourceReferenceHash, record.DetailCode, record.CreatedAt).Scan(&id)
		if err == nil {
			created = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return mapPostgresError(err, "append finding lineage skip")
		}
		var existingID string
		err = tx.QueryRow(ctx, `SELECT id FROM finding_lineage_skip_records WHERE tenant_id=$1 AND cycle_id=$2 AND snapshot_id=$3
			AND producer_kind=$4 AND reason=$5 AND source_reference_hash=$6`, record.TenantID.String(), record.CycleID.String(),
			record.SnapshotID.String(), record.ProducerKind, string(record.Reason), record.SourceReferenceHash).Scan(&existingID)
		if err == nil {
			return nil
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: skip record id was reused", shared.ErrConflict)
		}
		return fmt.Errorf("read finding lineage skip replay: %w", err)
	})
	return created, err
}

func (repository *FindingLineageRepository) ListSkipsBySnapshot(ctx context.Context, tenantID, cycleID, snapshotID shared.ID) ([]findinglineage.SkipRecord, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	records := make([]findinglineage.SkipRecord, 0)
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,cycle_id,snapshot_id,id,producer_kind,finding_kind,reason,source_reference_hash,detail_code,created_at
			FROM finding_lineage_skip_records WHERE tenant_id=$1 AND cycle_id=$2 AND snapshot_id=$3 ORDER BY id`,
			tenantID.String(), cycleID.String(), snapshotID.String())
		if err != nil {
			return fmt.Errorf("list finding lineage skips: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var record findinglineage.SkipRecord
			var tenant, cycle, snapshot, id, reason string
			if err := rows.Scan(&tenant, &cycle, &snapshot, &id, &record.ProducerKind, &record.FindingKind, &reason,
				&record.SourceReferenceHash, &record.DetailCode, &record.CreatedAt); err != nil {
				return fmt.Errorf("scan finding lineage skip: %w", err)
			}
			record.TenantID, record.CycleID, record.SnapshotID, record.ID = shared.ID(tenant), shared.ID(cycle), shared.ID(snapshot), shared.ID(id)
			record.Reason = findinglineage.SkipReason(reason)
			records = append(records, record)
		}
		return rows.Err()
	})
	return records, err
}

func (repository *FindingLineageRepository) findIdentities(ctx context.Context, tenantID shared.ID, query string, args ...any) ([]findinglineage.Identity, error) {
	identities := make([]findinglineage.Identity, 0)
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("find finding identities: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			identity, err := scanFindingIdentity(rows)
			if err != nil {
				return err
			}
			identities = append(identities, identity)
		}
		return rows.Err()
	})
	return identities, err
}

func insertFindingObservation(ctx context.Context, tx pgx.Tx, observation findinglineage.Observation, provenance []byte) error {
	if _, err := tx.Exec(ctx, `INSERT INTO finding_observations(
		tenant_id,cycle_id,id,snapshot_id,identity_id,producer_kind,finding_kind,target_canonical,source_finding_id,
		source_occurrence_id,severity,risk_score_milli,component_version,location,reachability,evidence_digest,scanner_provenance,observed_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		observation.TenantID.String(), observation.CycleID.String(), observation.ID.String(), observation.SnapshotID.String(),
		observation.IdentityID.String(), observation.ProducerKind, observation.FindingKind, observation.TargetCanonical,
		observation.SourceFindingID, observation.SourceOccurrenceID, string(observation.Severity), observation.RiskScoreMilli,
		observation.ComponentVersion, observation.Location, observation.Reachability, observation.EvidenceDigest, provenance, observation.ObservedAt); err != nil {
		return mapPostgresError(err, "append finding observation")
	}
	return nil
}

func insertFindingCandidate(ctx context.Context, tx pgx.Tx, candidate findinglineage.MatchCandidate) error {
	if _, err := tx.Exec(ctx, `INSERT INTO finding_match_candidates(
		tenant_id,cycle_id,snapshot_id,id,producer_kind,finding_kind,reason,fingerprint_schema_version,fingerprint,
		source_reference_hash,candidate_set_hash,status,version,created_at,resolved_at,superseded_at,superseded_by_candidate_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NULLIF($17,''))`,
		candidate.TenantID.String(), candidate.CycleID.String(), candidate.SnapshotID.String(), candidate.ID.String(),
		candidate.ProducerKind, candidate.FindingKind, string(candidate.Reason), candidate.FingerprintSchemaVersion,
		candidate.Fingerprint, candidate.SourceReferenceHash, candidate.CandidateSetHash, string(candidate.Status), candidate.Version,
		candidate.CreatedAt, candidate.ResolvedAt, candidate.SupersededAt, candidate.SupersededByCandidateID.String()); err != nil {
		return mapPostgresError(err, "create finding match candidate")
	}
	for _, reference := range candidate.Refs {
		payload := reference.ReasonPayload
		if payload == nil {
			payload = map[string]string{}
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode finding candidate reference payload: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO finding_match_candidate_refs(
			tenant_id,cycle_id,candidate_id,position,role,identity_id,observation_id,external_reference_hash,
			match_method,score_milli,confidence,reason_payload)
			VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),$9,$10,$11,$12)`,
			candidate.TenantID.String(), candidate.CycleID.String(), candidate.ID.String(), reference.Position, string(reference.Role),
			reference.IdentityID.String(), reference.ObservationID.String(), reference.ExternalReferenceHash, string(reference.Method),
			reference.ScoreMilli, string(reference.Confidence), encoded); err != nil {
			return mapPostgresError(err, "create finding match candidate reference")
		}
	}
	return nil
}

func updateFindingCandidateCAS(ctx context.Context, tx pgx.Tx, candidate findinglineage.MatchCandidate, expectedVersion int64) error {
	result, err := tx.Exec(ctx, `UPDATE finding_match_candidates SET status=$4,version=$5,resolved_at=$6,superseded_at=$7,
		superseded_by_candidate_id=NULLIF($8,'') WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3 AND status='open' AND version=$9`,
		candidate.TenantID.String(), candidate.CycleID.String(), candidate.ID.String(), string(candidate.Status), candidate.Version,
		candidate.ResolvedAt, candidate.SupersededAt, candidate.SupersededByCandidateID.String(), expectedVersion)
	if err != nil {
		return mapPostgresError(err, "resolve finding match candidate")
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("%w: candidate version or status changed", shared.ErrConflict)
	}
	return nil
}

func insertFindingResolution(ctx context.Context, tx pgx.Tx, event findinglineage.ResolutionEvent) error {
	beforeValues := event.BeforeRefs
	if beforeValues == nil {
		beforeValues = []findinglineage.CandidateRef{}
	}
	afterValues := event.AfterRefs
	if afterValues == nil {
		afterValues = []findinglineage.CandidateRef{}
	}
	beforeRefs, err := json.Marshal(beforeValues)
	if err != nil {
		return fmt.Errorf("encode finding resolution before refs: %w", err)
	}
	afterRefs, err := json.Marshal(afterValues)
	if err != nil {
		return fmt.Errorf("encode finding resolution after refs: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO finding_match_resolution_events(
		tenant_id,cycle_id,candidate_id,id,action,actor,reason,before_refs,after_refs,successor_candidate_id,
		expected_version,version,prior_event_id,content_hash,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,''),$11,$12,NULLIF($13,''),$14,$15)`,
		event.TenantID.String(), event.CycleID.String(), event.CandidateID.String(), event.ID.String(), string(event.Action),
		event.Actor, event.Reason, beforeRefs, afterRefs, event.SuccessorCandidateID.String(), event.ExpectedVersion,
		event.Version, event.PriorEventID.String(), event.ContentHash, event.CreatedAt); err != nil {
		return mapPostgresError(err, "append finding match resolution")
	}
	return nil
}

func loadFindingIdentity(ctx context.Context, tx pgx.Tx, tenantID, cycleID, identityID shared.ID) (findinglineage.Identity, error) {
	identity, err := scanFindingIdentity(tx.QueryRow(ctx, `SELECT `+findingIdentityColumns+` FROM finding_identities
		WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`, tenantID.String(), cycleID.String(), identityID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return findinglineage.Identity{}, shared.ErrNotFound
	}
	return identity, err
}

func scanFindingIdentity(row rowScanner) (findinglineage.Identity, error) {
	var identity findinglineage.Identity
	var tenantID, cycleID, id, firstSnapshotID string
	if err := row.Scan(&tenantID, &cycleID, &id, &identity.ProducerKind, &identity.FindingKind, &identity.CanonicalizationVersion,
		&identity.FingerprintSchemaVersion, &identity.LineageFingerprint, &identity.TargetIdentitySchemaVersion,
		&identity.TargetIdentityCanonical, &identity.CanonicalIdentityFields, &firstSnapshotID, &identity.CreatedAt); err != nil {
		return findinglineage.Identity{}, err
	}
	identity.TenantID, identity.CycleID, identity.ID, identity.FirstSeenSnapshotID = shared.ID(tenantID), shared.ID(cycleID), shared.ID(id), shared.ID(firstSnapshotID)
	if err := identity.Validate(); err != nil {
		return findinglineage.Identity{}, fmt.Errorf("validate persisted finding identity: %w", err)
	}
	return identity, nil
}

func loadFindingObservation(ctx context.Context, tx pgx.Tx, tenantID, cycleID, observationID shared.ID, suffix string) (findinglineage.Observation, error) {
	observation, err := scanFindingObservation(tx.QueryRow(ctx, `SELECT `+findingObservationColumns+` FROM finding_observations
		WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3 `+suffix, tenantID.String(), cycleID.String(), observationID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return findinglineage.Observation{}, shared.ErrNotFound
	}
	return observation, err
}

func scanFindingObservation(row rowScanner) (findinglineage.Observation, error) {
	var observation findinglineage.Observation
	var tenantID, cycleID, id, snapshotID, identityID, severity string
	var provenance []byte
	if err := row.Scan(&tenantID, &cycleID, &id, &snapshotID, &identityID, &observation.ProducerKind, &observation.FindingKind,
		&observation.TargetCanonical, &observation.SourceFindingID, &observation.SourceOccurrenceID, &severity,
		&observation.RiskScoreMilli, &observation.ComponentVersion, &observation.Location, &observation.Reachability,
		&observation.EvidenceDigest, &provenance, &observation.ObservedAt); err != nil {
		return findinglineage.Observation{}, err
	}
	observation.TenantID, observation.CycleID, observation.ID = shared.ID(tenantID), shared.ID(cycleID), shared.ID(id)
	observation.SnapshotID, observation.IdentityID, observation.Severity = shared.ID(snapshotID), shared.ID(identityID), shared.Severity(severity)
	if err := json.Unmarshal(provenance, &observation.ScannerProvenance); err != nil {
		return findinglineage.Observation{}, fmt.Errorf("decode finding observation provenance: %w", err)
	}
	if err := observation.Validate(); err != nil {
		return findinglineage.Observation{}, fmt.Errorf("validate persisted finding observation: %w", err)
	}
	return observation, nil
}

func loadFindingCandidateByIdempotency(ctx context.Context, tx pgx.Tx, candidate findinglineage.MatchCandidate) (findinglineage.MatchCandidate, error) {
	loaded, err := scanFindingCandidate(tx.QueryRow(ctx, `SELECT `+findingCandidateColumns+` FROM finding_match_candidates
		WHERE tenant_id=$1 AND cycle_id=$2 AND snapshot_id=$3 AND producer_kind=$4 AND reason=$5 AND candidate_set_hash=$6`,
		candidate.TenantID.String(), candidate.CycleID.String(), candidate.SnapshotID.String(), candidate.ProducerKind,
		string(candidate.Reason), candidate.CandidateSetHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return findinglineage.MatchCandidate{}, shared.ErrNotFound
	}
	if err != nil {
		return findinglineage.MatchCandidate{}, err
	}
	return loadFindingCandidateRefs(ctx, tx, loaded)
}

func loadOpenFindingCandidateBySubject(ctx context.Context, tx pgx.Tx, candidate findinglineage.MatchCandidate) (findinglineage.MatchCandidate, error) {
	loaded, err := scanFindingCandidate(tx.QueryRow(ctx, `SELECT `+findingCandidateColumns+` FROM finding_match_candidates
		WHERE tenant_id=$1 AND cycle_id=$2 AND snapshot_id=$3 AND producer_kind=$4 AND reason=$5 AND source_reference_hash=$6
		AND status='open' FOR UPDATE`, candidate.TenantID.String(), candidate.CycleID.String(), candidate.SnapshotID.String(),
		candidate.ProducerKind, string(candidate.Reason), candidate.SourceReferenceHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return findinglineage.MatchCandidate{}, shared.ErrNotFound
	}
	if err != nil {
		return findinglineage.MatchCandidate{}, err
	}
	return loadFindingCandidateRefs(ctx, tx, loaded)
}

func loadFindingCandidate(ctx context.Context, tx pgx.Tx, tenantID, cycleID, candidateID shared.ID, forUpdate bool) (findinglineage.MatchCandidate, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	loaded, err := scanFindingCandidate(tx.QueryRow(ctx, `SELECT `+findingCandidateColumns+` FROM finding_match_candidates
		WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`+suffix, tenantID.String(), cycleID.String(), candidateID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return findinglineage.MatchCandidate{}, shared.ErrNotFound
	}
	if err != nil {
		return findinglineage.MatchCandidate{}, err
	}
	return loadFindingCandidateRefs(ctx, tx, loaded)
}

func scanFindingCandidate(row rowScanner) (findinglineage.MatchCandidate, error) {
	var candidate findinglineage.MatchCandidate
	var tenantID, cycleID, snapshotID, id, reason, status, successorID string
	if err := row.Scan(&tenantID, &cycleID, &snapshotID, &id, &candidate.ProducerKind, &candidate.FindingKind, &reason,
		&candidate.FingerprintSchemaVersion, &candidate.Fingerprint, &candidate.SourceReferenceHash, &candidate.CandidateSetHash,
		&status, &candidate.Version, &candidate.CreatedAt, &candidate.ResolvedAt, &candidate.SupersededAt, &successorID); err != nil {
		return findinglineage.MatchCandidate{}, err
	}
	candidate.TenantID, candidate.CycleID, candidate.SnapshotID, candidate.ID = shared.ID(tenantID), shared.ID(cycleID), shared.ID(snapshotID), shared.ID(id)
	candidate.Reason, candidate.Status = findinglineage.CandidateReason(reason), findinglineage.CandidateStatus(status)
	candidate.SupersededByCandidateID = shared.ID(successorID)
	return candidate, nil
}

func loadFindingCandidateRefs(ctx context.Context, tx pgx.Tx, candidate findinglineage.MatchCandidate) (findinglineage.MatchCandidate, error) {
	rows, err := tx.Query(ctx, `SELECT position,role,COALESCE(identity_id,''),COALESCE(observation_id,''),
		COALESCE(external_reference_hash,''),match_method,score_milli,confidence,reason_payload
		FROM finding_match_candidate_refs WHERE tenant_id=$1 AND cycle_id=$2 AND candidate_id=$3 ORDER BY position`,
		candidate.TenantID.String(), candidate.CycleID.String(), candidate.ID.String())
	if err != nil {
		return findinglineage.MatchCandidate{}, fmt.Errorf("load finding candidate refs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var reference findinglineage.CandidateRef
		var role, identityID, observationID, method, confidence string
		var payload []byte
		if err := rows.Scan(&reference.Position, &role, &identityID, &observationID, &reference.ExternalReferenceHash,
			&method, &reference.ScoreMilli, &confidence, &payload); err != nil {
			return findinglineage.MatchCandidate{}, fmt.Errorf("scan finding candidate ref: %w", err)
		}
		reference.Role, reference.IdentityID, reference.ObservationID = findinglineage.ReferenceRole(role), shared.ID(identityID), shared.ID(observationID)
		reference.Method, reference.Confidence = findinglineage.MatchMethod(method), findinglineage.Confidence(confidence)
		if err := json.Unmarshal(payload, &reference.ReasonPayload); err != nil {
			return findinglineage.MatchCandidate{}, fmt.Errorf("decode finding candidate ref payload: %w", err)
		}
		candidate.Refs = append(candidate.Refs, reference)
	}
	if err := rows.Err(); err != nil {
		return findinglineage.MatchCandidate{}, err
	}
	if err := candidate.Validate(); err != nil {
		return findinglineage.MatchCandidate{}, fmt.Errorf("validate persisted finding candidate: %w", err)
	}
	return candidate, nil
}

func latestFindingResolutionID(ctx context.Context, tx pgx.Tx, tenantID, cycleID, candidateID shared.ID) (shared.ID, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM finding_match_resolution_events WHERE tenant_id=$1 AND cycle_id=$2 AND candidate_id=$3
		ORDER BY version DESC LIMIT 1`, tenantID.String(), cycleID.String(), candidateID.String()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load latest finding resolution: %w", err)
	}
	return shared.ID(id), nil
}

func loadFindingResolutionByID(ctx context.Context, tx pgx.Tx, tenantID, cycleID, eventID shared.ID) (findinglineage.ResolutionEvent, error) {
	event, err := scanFindingResolution(tx.QueryRow(ctx, `SELECT tenant_id,cycle_id,candidate_id,id,action,actor,reason,before_refs,after_refs,
		COALESCE(successor_candidate_id,''),expected_version,version,COALESCE(prior_event_id,''),content_hash,created_at
		FROM finding_match_resolution_events WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`, tenantID.String(), cycleID.String(), eventID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return findinglineage.ResolutionEvent{}, shared.ErrNotFound
	}
	return event, err
}

func scanFindingResolution(row rowScanner) (findinglineage.ResolutionEvent, error) {
	var event findinglineage.ResolutionEvent
	var tenantID, cycleID, candidateID, id, action, successorID, priorEventID string
	var beforeRefs, afterRefs []byte
	if err := row.Scan(&tenantID, &cycleID, &candidateID, &id, &action, &event.Actor, &event.Reason, &beforeRefs, &afterRefs,
		&successorID, &event.ExpectedVersion, &event.Version, &priorEventID, &event.ContentHash, &event.CreatedAt); err != nil {
		return findinglineage.ResolutionEvent{}, err
	}
	event.TenantID, event.CycleID, event.CandidateID, event.ID = shared.ID(tenantID), shared.ID(cycleID), shared.ID(candidateID), shared.ID(id)
	event.Action, event.SuccessorCandidateID, event.PriorEventID = findinglineage.ResolutionAction(action), shared.ID(successorID), shared.ID(priorEventID)
	if err := json.Unmarshal(beforeRefs, &event.BeforeRefs); err != nil {
		return findinglineage.ResolutionEvent{}, fmt.Errorf("decode finding resolution before refs: %w", err)
	}
	if err := json.Unmarshal(afterRefs, &event.AfterRefs); err != nil {
		return findinglineage.ResolutionEvent{}, fmt.Errorf("decode finding resolution after refs: %w", err)
	}
	if err := event.Validate(); err != nil {
		return findinglineage.ResolutionEvent{}, fmt.Errorf("validate persisted finding resolution: %w", err)
	}
	return event, nil
}

func loadActiveFindingOverride(ctx context.Context, tx pgx.Tx, tenantID, cycleID, sourceObservationID shared.ID, forUpdate bool) (findinglineage.OverrideEvent, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	event, err := scanFindingOverride(tx.QueryRow(ctx, `SELECT tenant_id,cycle_id,id,action,source_observation_id,COALESCE(source_identity_id,''),
		COALESCE(target_observation_id,''),target_identity_id,actor,reason,expected_version,version,COALESCE(prior_event_id,''),content_hash,created_at
		FROM finding_match_override_events WHERE tenant_id=$1 AND cycle_id=$2 AND source_observation_id=$3
		ORDER BY version DESC LIMIT 1`+suffix, tenantID.String(), cycleID.String(), sourceObservationID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return findinglineage.OverrideEvent{}, shared.ErrNotFound
	}
	return event, err
}

func loadFindingOverrideByID(ctx context.Context, tx pgx.Tx, tenantID, cycleID, eventID shared.ID) (findinglineage.OverrideEvent, error) {
	event, err := scanFindingOverride(tx.QueryRow(ctx, `SELECT tenant_id,cycle_id,id,action,source_observation_id,COALESCE(source_identity_id,''),
		COALESCE(target_observation_id,''),target_identity_id,actor,reason,expected_version,version,COALESCE(prior_event_id,''),content_hash,created_at
		FROM finding_match_override_events WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`, tenantID.String(), cycleID.String(), eventID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return findinglineage.OverrideEvent{}, shared.ErrNotFound
	}
	return event, err
}

func scanFindingOverride(row rowScanner) (findinglineage.OverrideEvent, error) {
	var event findinglineage.OverrideEvent
	var tenantID, cycleID, id, action, sourceObservationID, sourceIdentityID, targetObservationID, targetIdentityID, priorEventID string
	if err := row.Scan(&tenantID, &cycleID, &id, &action, &sourceObservationID, &sourceIdentityID, &targetObservationID,
		&targetIdentityID, &event.Actor, &event.Reason, &event.ExpectedVersion, &event.Version, &priorEventID,
		&event.ContentHash, &event.CreatedAt); err != nil {
		return findinglineage.OverrideEvent{}, err
	}
	event.TenantID, event.CycleID, event.ID, event.Action = shared.ID(tenantID), shared.ID(cycleID), shared.ID(id), findinglineage.OverrideAction(action)
	event.SourceObservationID, event.SourceIdentityID = shared.ID(sourceObservationID), shared.ID(sourceIdentityID)
	event.TargetObservationID, event.TargetIdentityID = shared.ID(targetObservationID), shared.ID(targetIdentityID)
	event.PriorEventID = shared.ID(priorEventID)
	if err := event.Validate(); err != nil {
		return findinglineage.OverrideEvent{}, fmt.Errorf("validate persisted finding override: %w", err)
	}
	return event, nil
}

func prefixedColumns(prefix, columns string) string {
	parts := strings.Split(columns, ",")
	for index, part := range parts {
		parts[index] = prefix + "." + strings.TrimSpace(part)
	}
	return strings.Join(parts, ",")
}

func lineageLockKey(parts ...string) string {
	var builder strings.Builder
	for _, part := range parts {
		fmt.Fprintf(&builder, "%d:%s", len(part), part)
	}
	return builder.String()
}

func samePostgresCandidateResolution(left, right findinglineage.MatchCandidate) bool {
	return left.TenantID == right.TenantID && left.CycleID == right.CycleID && left.ID == right.ID &&
		left.Status == right.Status && left.Version == right.Version && left.SupersededByCandidateID == right.SupersededByCandidateID &&
		samePostgresOptionalTime(left.ResolvedAt, right.ResolvedAt) && samePostgresOptionalTime(left.SupersededAt, right.SupersededAt)
}

func samePostgresOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}
