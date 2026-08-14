package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AdvisoryMaterializer struct{ pool *pgxpool.Pool }

func NewAdvisoryMaterializer(pool *pgxpool.Pool) *AdvisoryMaterializer {
	return &AdvisoryMaterializer{pool: pool}
}

var _ ports.AdvisoryMaterializer = (*AdvisoryMaterializer)(nil)
var _ ports.AdvisoryStore = (*AdvisoryMaterializer)(nil)
var _ ports.AdvisoryEvaluationCheckpointStore = (*AdvisoryMaterializer)(nil)
var _ ports.VulnerabilityAdvisoryReadStore = (*AdvisoryMaterializer)(nil)

func (r *AdvisoryMaterializer) CurrentSourceRecordIDs(ctx context.Context, sourceID string, yield func(string) error) error {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" || yield == nil {
		return fmt.Errorf("%w: source id and callback are required", shared.ErrValidation)
	}
	rows, err := r.pool.Query(ctx, `SELECT record_id FROM advisory_observations WHERE source_id=$1 AND is_current ORDER BY record_id COLLATE "C"`, sourceID)
	if err != nil {
		return fmt.Errorf("list current source observations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var recordID string
		if err := rows.Scan(&recordID); err != nil {
			return fmt.Errorf("scan current source observation: %w", err)
		}
		if err := yield(recordID); err != nil {
			return err
		}
	}
	return rows.Err()
}

type canonicalRevisionEnvelope struct {
	Version int                `json:"version"`
	Value   advisory.Canonical `json:"canonical"`
}

func (r *AdvisoryMaterializer) Materialize(ctx context.Context, records []advisory.ObservationRecord) (advisory.MaterializationResult, error) {
	if err := advisory.ValidateBatch(records); err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("validate advisory batch: %w", err)
	}
	normalized, identityIDs, err := normalizeObservationBatch(records)
	if err != nil {
		return advisory.MaterializationResult{}, err
	}
	syncRunIDs := observationSyncRunIDs(normalized)
	tenantID, hasTenant := shared.TenantFrom(ctx)
	if len(syncRunIDs) > 0 && !hasTenant {
		return advisory.MaterializationResult{}, fmt.Errorf("%w: sync run provenance requires tenant context", shared.ErrValidation)
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("begin advisory materialization: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if len(syncRunIDs) > 0 {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenantID.String()); err != nil {
			return advisory.MaterializationResult{}, fmt.Errorf("set advisory provenance tenant: %w", err)
		}
		for _, runID := range syncRunIDs {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1 FROM vulnerability_sync_runs runs
				JOIN jobs ON jobs.id=runs.durable_job_id AND jobs.tenant_id=$2
				WHERE runs.id=$1
			)`, runID.String(), tenantID.String()).Scan(&exists); err != nil {
				return advisory.MaterializationResult{}, fmt.Errorf("verify sync run %s: %w", runID, err)
			}
			if !exists {
				return advisory.MaterializationResult{}, fmt.Errorf("sync run %s: %w", runID, shared.ErrNotFound)
			}
		}
	}

	for _, identityID := range identityIDs {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, identityID); err != nil {
			return advisory.MaterializationResult{}, fmt.Errorf("lock advisory identity: %w", err)
		}
	}
	for _, record := range normalized {
		if err := r.upsertObservation(ctx, tx, record); err != nil {
			return advisory.MaterializationResult{}, err
		}
	}

	observations, err := r.loadConnectedObservations(ctx, tx, identityIDs)
	if err != nil {
		return advisory.MaterializationResult{}, err
	}
	canonical, err := advisory.Merge(observations)
	if err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("merge advisory observations: %w", err)
	}
	canonicalIDs := append([]string{canonical.Advisory.ID}, canonical.Advisory.Aliases...)
	if err := r.validateAliases(ctx, tx, canonical.Advisory.ID, canonicalIDs); err != nil {
		return advisory.MaterializationResult{}, err
	}

	contentHash, err := canonical.ContentHash()
	if err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("hash canonical advisory: %w", err)
	}
	previous, previousHash, previousRevision, err := loadPreviousCanonical(ctx, tx, canonical.Advisory.ID)
	if err != nil {
		return advisory.MaterializationResult{}, err
	}
	result := advisory.MaterializationResult{Canonical: canonical, ContentHash: contentHash, Revision: previousRevision}
	if previousHash != "" {
		result.ChangedFields = advisory.Diff(previous, canonical)
	}

	projection, err := json.Marshal(canonical.Advisory)
	if err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("marshal canonical projection: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO advisories (id, data, created_at, updated_at)
		VALUES ($1, $2, now(), now())
		ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()`, canonical.Advisory.ID, projection); err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("upsert canonical advisory: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM advisory_affects WHERE advisory_id=$1`, canonical.Advisory.ID); err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("clear canonical affects: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM advisory_cpe_affects WHERE advisory_id=$1`, canonical.Advisory.ID); err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("clear canonical CPE affects: %w", err)
	}
	seenCPEs := map[string]struct{}{}
	for _, current := range canonical.Advisory.CPEs {
		parsed, err := sbom.ParseCPE23(current.Criteria)
		if err != nil || parsed.Part == "*" || parsed.Part == "-" || parsed.Vendor == "*" || parsed.Vendor == "-" || parsed.Product == "*" || parsed.Product == "-" {
			continue
		}
		key := parsed.Part + "\x00" + parsed.Vendor + "\x00" + parsed.Product
		if _, ok := seenCPEs[key]; ok {
			continue
		}
		seenCPEs[key] = struct{}{}
		if _, err := tx.Exec(ctx, `INSERT INTO advisory_cpe_affects(advisory_id,cpe_part,cpe_vendor,cpe_product) VALUES($1,$2,$3,$4)`, canonical.Advisory.ID, parsed.Part, parsed.Vendor, parsed.Product); err != nil {
			return advisory.MaterializationResult{}, fmt.Errorf("insert canonical CPE affect: %w", err)
		}
	}
	seenAffects := map[string]struct{}{}
	for _, affected := range canonical.Advisory.Affected {
		if affected.Ecosystem == "" || affected.Package == "" {
			continue
		}
		key := affected.Ecosystem + "\x00" + affected.Package
		if _, ok := seenAffects[key]; ok {
			continue
		}
		seenAffects[key] = struct{}{}
		if _, err := tx.Exec(ctx, `INSERT INTO advisory_affects(advisory_id, ecosystem, package) VALUES($1,$2,$3)`, canonical.Advisory.ID, affected.Ecosystem, affected.Package); err != nil {
			return advisory.MaterializationResult{}, fmt.Errorf("insert canonical affect: %w", err)
		}
	}
	if err := r.replaceAliases(ctx, tx, canonical.Advisory.ID, canonicalIDs); err != nil {
		return advisory.MaterializationResult{}, err
	}

	if previousHash != contentHash {
		revisionData, err := json.Marshal(canonicalRevisionEnvelope{Version: 1, Value: canonical})
		if err != nil {
			return advisory.MaterializationResult{}, fmt.Errorf("marshal canonical revision: %w", err)
		}
		fields, err := json.Marshal(append([]advisory.ChangedField{}, result.ChangedFields...))
		if err != nil {
			return advisory.MaterializationResult{}, fmt.Errorf("marshal canonical changes: %w", err)
		}
		revision := previousRevision + 1
		if _, err := tx.Exec(ctx, `
			INSERT INTO advisory_revisions(advisory_id, revision, content_hash, data, changed_fields)
			VALUES($1,$2,$3,$4,$5)`, canonical.Advisory.ID, revision, contentHash, revisionData, fields); err != nil {
			return advisory.MaterializationResult{}, fmt.Errorf("insert canonical revision: %w", err)
		}
		for _, runID := range syncRunIDs {
			tag, err := tx.Exec(ctx, `INSERT INTO advisory_revision_sync_runs(advisory_id,revision,sync_run_id)
				SELECT $1,$2,runs.id FROM vulnerability_sync_runs runs
				JOIN jobs ON jobs.id=runs.durable_job_id AND jobs.tenant_id=$4
				WHERE runs.id=$3`, canonical.Advisory.ID, revision, runID.String(), tenantID.String())
			if err != nil {
				return advisory.MaterializationResult{}, fmt.Errorf("link canonical revision to sync run: %w", err)
			}
			if tag.RowsAffected() != 1 {
				return advisory.MaterializationResult{}, fmt.Errorf("sync run %s: %w", runID, shared.ErrNotFound)
			}
		}
		result.Revision = revision
		result.CreatedRevision = true
	}
	if err := tx.Commit(ctx); err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("commit advisory materialization: %w", err)
	}
	return result, nil
}

func normalizeObservationBatch(records []advisory.ObservationRecord) ([]advisory.ObservationRecord, []string, error) {
	normalized := make([]advisory.ObservationRecord, 0, len(records))
	seen := map[string]string{}
	identities := map[string]struct{}{}
	for _, record := range records {
		normalizedRecord, err := record.Normalize()
		if err != nil {
			return nil, nil, fmt.Errorf("normalize advisory observation: %w", err)
		}
		hash, err := normalizedRecord.ContentHash()
		if err != nil {
			return nil, nil, err
		}
		key := normalizedRecord.Observation.SourceID + "\x00" + normalizedRecord.Observation.RecordID
		if oldHash, ok := seen[key]; ok && oldHash != hash {
			return nil, nil, fmt.Errorf("%w: provider record %s appears with two payloads", shared.ErrConflict, key)
		}
		seen[key] = hash
		for _, id := range normalizedRecord.IdentityIDs() {
			identities[id] = struct{}{}
		}
		normalized = append(normalized, normalizedRecord)
	}
	identityIDs := make([]string, 0, len(identities))
	for id := range identities {
		identityIDs = append(identityIDs, id)
	}
	sort.Strings(identityIDs)
	return normalized, identityIDs, nil
}

func (r *AdvisoryMaterializer) upsertObservation(ctx context.Context, tx pgx.Tx, record advisory.ObservationRecord) error {
	hash, err := record.ContentHash()
	if err != nil {
		return fmt.Errorf("hash observation: %w", err)
	}
	payload, err := json.Marshal(record.Observation)
	if err != nil {
		return fmt.Errorf("marshal observation: %w", err)
	}
	id := observationID(record.Observation.SourceID, record.Observation.RecordID, hash)
	if _, err := tx.Exec(ctx, `UPDATE advisory_observations SET is_current=FALSE WHERE source_id=$1 AND record_id=$2 AND is_current`, record.Observation.SourceID, record.Observation.RecordID); err != nil {
		return fmt.Errorf("retire prior observation: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO advisory_observations(id, source_id, record_id, identity_ids, normalized_payload, raw_payload, raw_reference, content_hash, sync_run_id, is_current, observed_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),TRUE,$10)
		ON CONFLICT (source_id, record_id, content_hash) DO UPDATE SET
			identity_ids=EXCLUDED.identity_ids, normalized_payload=EXCLUDED.normalized_payload,
			raw_payload=EXCLUDED.raw_payload, raw_reference=EXCLUDED.raw_reference,
			sync_run_id=EXCLUDED.sync_run_id, is_current=TRUE, observed_at=EXCLUDED.observed_at`,
		id, record.Observation.SourceID, record.Observation.RecordID, record.IdentityIDs(), payload, record.RawPayload, record.RawReference, hash, record.SyncRunID, record.ObservedAt); err != nil {
		return fmt.Errorf("upsert advisory observation: %w", err)
	}
	return nil
}

func observationID(sourceID, recordID, hash string) string {
	digest := sha256.Sum256([]byte(sourceID + "\x00" + recordID + "\x00" + hash))
	return hex.EncodeToString(digest[:])
}

func (r *AdvisoryMaterializer) loadConnectedObservations(ctx context.Context, tx pgx.Tx, identities []string) ([]advisory.Observation, error) {
	known := map[string]struct{}{}
	for _, identity := range identities {
		known[identity] = struct{}{}
	}
	var observations []advisory.Observation
	for {
		ids := make([]string, 0, len(known))
		for id := range known {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		rows, err := tx.Query(ctx, `SELECT normalized_payload FROM advisory_observations WHERE is_current AND identity_ids && $1::text[]`, ids)
		if err != nil {
			return nil, fmt.Errorf("load connected observations: %w", err)
		}
		observations = observations[:0]
		changed := false
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan advisory observation: %w", err)
			}
			var observation advisory.Observation
			if err := json.Unmarshal(payload, &observation); err != nil {
				rows.Close()
				return nil, fmt.Errorf("decode advisory observation: %w", err)
			}
			observations = append(observations, observation)
			for _, id := range observationIDs(observation) {
				if _, ok := known[id]; !ok {
					known[id] = struct{}{}
					changed = true
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("iterate advisory observations: %w", err)
		}
		rows.Close()
		if !changed {
			break
		}
	}
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].SourceID+"\x00"+observations[i].RecordID < observations[j].SourceID+"\x00"+observations[j].RecordID
	})
	return observations, nil
}

func observationIDs(observation advisory.Observation) []string {
	ids := append([]string{observation.Advisory.ID}, observation.Advisory.Aliases...)
	seen := map[string]struct{}{}
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id != "" {
			seen[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (r *AdvisoryMaterializer) validateAliases(ctx context.Context, tx pgx.Tx, canonicalID string, ids []string) error {
	rows, err := tx.Query(ctx, `SELECT alias_id, canonical_id FROM advisory_aliases WHERE alias_id = ANY($1::text[]) FOR UPDATE`, ids)
	if err != nil {
		return fmt.Errorf("load advisory aliases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var aliasID, existingCanonical string
		if err := rows.Scan(&aliasID, &existingCanonical); err != nil {
			return fmt.Errorf("scan advisory alias: %w", err)
		}
		if existingCanonical != canonicalID {
			return fmt.Errorf("%w: alias %s maps to %s", advisory.ErrAliasConflict, aliasID, existingCanonical)
		}
	}
	return rows.Err()
}

func (r *AdvisoryMaterializer) replaceAliases(ctx context.Context, tx pgx.Tx, canonicalID string, ids []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM advisory_aliases WHERE canonical_id=$1`, canonicalID); err != nil {
		return fmt.Errorf("replace advisory aliases: %w", err)
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `INSERT INTO advisory_aliases(alias_id, canonical_id) VALUES($1,$2)`, id, canonicalID); err != nil {
			return fmt.Errorf("insert advisory alias: %w", err)
		}
	}
	return nil
}

func loadPreviousCanonical(ctx context.Context, tx pgx.Tx, id string) (advisory.Canonical, string, int64, error) {
	var payload []byte
	var hash string
	var revision int64
	err := tx.QueryRow(ctx, `SELECT data, content_hash, revision FROM advisory_revisions WHERE advisory_id=$1 ORDER BY revision DESC LIMIT 1`, id).Scan(&payload, &hash, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return advisory.Canonical{}, "", 0, nil
	}
	if err != nil {
		return advisory.Canonical{}, "", 0, fmt.Errorf("load advisory revision: %w", err)
	}
	canonical, err := decodeCanonical(payload)
	if err != nil {
		return advisory.Canonical{}, "", 0, err
	}
	return canonical, hash, revision, nil
}

func decodeCanonical(payload []byte) (advisory.Canonical, error) {
	var envelope canonicalRevisionEnvelope
	if err := json.Unmarshal(payload, &envelope); err == nil && envelope.Version == 1 {
		return envelope.Value, nil
	}
	var legacy advisory.Advisory
	if err := json.Unmarshal(payload, &legacy); err != nil {
		return advisory.Canonical{}, fmt.Errorf("decode canonical projection: %w", err)
	}
	return advisory.Canonical{Advisory: legacy, Status: advisory.StatusActive}, nil
}

func (r *AdvisoryMaterializer) GetCanonical(ctx context.Context, id string) (advisory.Canonical, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	var canonicalID string
	if err := r.pool.QueryRow(ctx, `SELECT canonical_id FROM advisory_aliases WHERE alias_id=$1`, id).Scan(&canonicalID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return advisory.Canonical{}, fmt.Errorf("resolve advisory alias: %w", err)
		}
		canonicalID = id
	}
	var payload []byte
	err := r.pool.QueryRow(ctx, `SELECT data FROM advisory_revisions WHERE advisory_id=$1 ORDER BY revision DESC LIMIT 1`, canonicalID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		err = r.pool.QueryRow(ctx, `SELECT data FROM advisories WHERE id=$1`, canonicalID).Scan(&payload)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return advisory.Canonical{}, fmt.Errorf("advisory %s: %w", id, shared.ErrNotFound)
	}
	if err != nil {
		return advisory.Canonical{}, fmt.Errorf("load canonical advisory: %w", err)
	}
	return decodeCanonical(payload)
}

func (r *AdvisoryMaterializer) GetCanonicalAtRevision(ctx context.Context, id string, revision int64) (advisory.Canonical, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	var canonicalID string
	if err := r.pool.QueryRow(ctx, `SELECT canonical_id FROM advisory_aliases WHERE alias_id=$1`, id).Scan(&canonicalID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return advisory.Canonical{}, fmt.Errorf("resolve advisory alias: %w", err)
		}
		canonicalID = id
	}
	var payload []byte
	if err := r.pool.QueryRow(ctx, `SELECT data FROM advisory_revisions WHERE advisory_id=$1 AND revision=$2`, canonicalID, revision).Scan(&payload); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return advisory.Canonical{}, fmt.Errorf("advisory %s revision %d: %w", id, revision, shared.ErrNotFound)
		}
		return advisory.Canonical{}, fmt.Errorf("load canonical advisory revision: %w", err)
	}
	return decodeCanonical(payload)
}

func (r *AdvisoryMaterializer) CurrentRevision(ctx context.Context, id string) (int64, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	var canonicalID string
	if err := r.pool.QueryRow(ctx, `SELECT canonical_id FROM advisory_aliases WHERE alias_id=$1`, id).Scan(&canonicalID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("resolve advisory alias: %w", err)
		}
		canonicalID = id
	}
	var revision int64
	if err := r.pool.QueryRow(ctx, `SELECT revision FROM advisory_revisions WHERE advisory_id=$1 ORDER BY revision DESC LIMIT 1`, canonicalID).Scan(&revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("advisory %s: %w", id, shared.ErrNotFound)
		}
		return 0, fmt.Errorf("load current advisory revision: %w", err)
	}
	return revision, nil
}

func (r *AdvisoryMaterializer) ByPackage(ctx context.Context, ecosystem, packageName string) ([]advisory.Advisory, error) {
	rows, err := r.pool.Query(ctx, `SELECT a.data FROM advisories a JOIN advisory_affects af ON af.advisory_id=a.id WHERE af.ecosystem=$1 AND af.package=$2 ORDER BY a.id COLLATE "C"`, ecosystem, packageName)
	if err != nil {
		return nil, fmt.Errorf("list canonical advisories by package: %w", err)
	}
	defer rows.Close()
	out := make([]advisory.Advisory, 0)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan canonical advisory by package: %w", err)
		}
		var item advisory.Advisory
		if err := json.Unmarshal(payload, &item); err != nil {
			return nil, fmt.Errorf("decode canonical advisory by package: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *AdvisoryMaterializer) ByCPE(ctx context.Context, part, vendor, product string) ([]advisory.Advisory, error) {
	rows, err := r.pool.Query(ctx, `SELECT a.data FROM advisories a JOIN advisory_cpe_affects af ON af.advisory_id=a.id WHERE af.cpe_part=$1 AND af.cpe_vendor=$2 AND af.cpe_product=$3 ORDER BY a.id COLLATE "C"`, strings.ToLower(strings.TrimSpace(part)), strings.ToLower(strings.TrimSpace(vendor)), strings.ToLower(strings.TrimSpace(product)))
	if err != nil {
		return nil, fmt.Errorf("list canonical advisories by CPE: %w", err)
	}
	defer rows.Close()
	out := make([]advisory.Advisory, 0)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan canonical advisory by CPE: %w", err)
		}
		var item advisory.Advisory
		if err := json.Unmarshal(payload, &item); err != nil {
			return nil, fmt.Errorf("decode canonical advisory by CPE: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *AdvisoryMaterializer) ListAdvisoryRevisions(ctx context.Context, after string, snapshotAt time.Time, limit int) (ports.AdvisoryRevisionPage, error) {
	if snapshotAt.IsZero() {
		return ports.AdvisoryRevisionPage{}, fmt.Errorf("%w: advisory corpus snapshot time is required", shared.ErrValidation)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `SELECT advisory_id,revision,created_at FROM (
		SELECT DISTINCT ON (advisory_id) advisory_id,revision,created_at
		FROM advisory_revisions WHERE advisory_id>$1 AND created_at<=$2
		ORDER BY advisory_id,revision DESC
	) latest ORDER BY advisory_id COLLATE "C" LIMIT $3`, strings.ToUpper(strings.TrimSpace(after)), snapshotAt, limit+1)
	if err != nil {
		return ports.AdvisoryRevisionPage{}, fmt.Errorf("list advisory corpus: %w", err)
	}
	defer rows.Close()
	page := ports.AdvisoryRevisionPage{}
	for rows.Next() {
		var item ports.AdvisoryRevisionRef
		if err := rows.Scan(&item.ID, &item.Revision, &item.CreatedAt); err != nil {
			return ports.AdvisoryRevisionPage{}, fmt.Errorf("scan advisory corpus: %w", err)
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return ports.AdvisoryRevisionPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.Next = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

func (r *AdvisoryMaterializer) AdvisoryRevisionAt(ctx context.Context, advisoryID string, snapshotAt time.Time) (ports.AdvisoryRevisionRef, error) {
	advisoryID = strings.ToUpper(strings.TrimSpace(advisoryID))
	if advisoryID == "" || snapshotAt.IsZero() {
		return ports.AdvisoryRevisionRef{}, fmt.Errorf("%w: advisory corpus snapshot identity is required", shared.ErrValidation)
	}
	var canonicalID string
	if err := r.pool.QueryRow(ctx, `SELECT canonical_id FROM advisory_aliases WHERE alias_id=$1`, advisoryID).Scan(&canonicalID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return ports.AdvisoryRevisionRef{}, fmt.Errorf("resolve advisory alias: %w", err)
		}
		canonicalID = advisoryID
	}
	var item ports.AdvisoryRevisionRef
	if err := r.pool.QueryRow(ctx, `SELECT advisory_id,revision,created_at FROM advisory_revisions WHERE advisory_id=$1 AND created_at<=$2 ORDER BY revision DESC LIMIT 1`, canonicalID, snapshotAt).Scan(&item.ID, &item.Revision, &item.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ports.AdvisoryRevisionRef{}, fmt.Errorf("advisory %s at snapshot: %w", advisoryID, shared.ErrNotFound)
		}
		return ports.AdvisoryRevisionRef{}, fmt.Errorf("load advisory revision at snapshot: %w", err)
	}
	return item, nil
}

func (r *AdvisoryMaterializer) MarkAdvisoryEvaluated(ctx context.Context, tenantID shared.ID, advisoryID string, revision int64, evaluatedAt time.Time) error {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	advisoryID = strings.ToUpper(strings.TrimSpace(advisoryID))
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID || advisoryID == "" || revision <= 0 || evaluatedAt.IsZero() {
		return fmt.Errorf("%w: advisory evaluation checkpoint is invalid", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM advisory_revisions WHERE advisory_id=$1 AND revision=$2)`, advisoryID, revision).Scan(&exists); err != nil {
			return fmt.Errorf("check advisory revision: %w", err)
		}
		if !exists {
			return fmt.Errorf("advisory %s revision %d: %w", advisoryID, revision, shared.ErrNotFound)
		}
		_, err := tx.Exec(ctx, `INSERT INTO advisory_evaluation_checkpoints(tenant_id,advisory_id,evaluated_revision,evaluated_at)
			VALUES($1,$2,$3,$4)
			ON CONFLICT (tenant_id,advisory_id) DO UPDATE SET
				evaluated_revision=GREATEST(advisory_evaluation_checkpoints.evaluated_revision,EXCLUDED.evaluated_revision),
				evaluated_at=CASE WHEN EXCLUDED.evaluated_revision>advisory_evaluation_checkpoints.evaluated_revision THEN EXCLUDED.evaluated_at ELSE advisory_evaluation_checkpoints.evaluated_at END`,
			tenantID.String(), advisoryID, revision, evaluatedAt.UTC())
		if err != nil {
			return fmt.Errorf("mark advisory evaluated: %w", err)
		}
		return nil
	})
}

func (r *AdvisoryMaterializer) OldestUnevaluatedAdvisory(ctx context.Context, tenantID shared.ID) (*vulnerabilityintel.EvaluationLag, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var lag *vulnerabilityintel.EvaluationLag
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var item vulnerabilityintel.EvaluationLag
		err := tx.QueryRow(ctx, `WITH current_revisions AS (
				SELECT advisory_id,max(revision) AS current_revision FROM advisory_revisions GROUP BY advisory_id
			), lagged AS (
				SELECT current_revisions.advisory_id,current_revisions.current_revision,
					COALESCE(checkpoints.evaluated_revision,0) AS evaluated_revision,
					min(revisions.created_at) AS changed_at
				FROM current_revisions
				LEFT JOIN advisory_evaluation_checkpoints checkpoints
					ON checkpoints.tenant_id=$1 AND checkpoints.advisory_id=current_revisions.advisory_id
				JOIN advisory_revisions revisions
					ON revisions.advisory_id=current_revisions.advisory_id
					AND revisions.revision>COALESCE(checkpoints.evaluated_revision,0)
				WHERE COALESCE(checkpoints.evaluated_revision,0)<current_revisions.current_revision
				GROUP BY current_revisions.advisory_id,current_revisions.current_revision,checkpoints.evaluated_revision
			)
			SELECT advisory_id,current_revision,evaluated_revision,changed_at FROM lagged ORDER BY changed_at,advisory_id COLLATE "C" LIMIT 1`, tenantID.String()).Scan(&item.AdvisoryID, &item.CurrentRevision, &item.EvaluatedRevision, &item.ChangedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load oldest unevaluated advisory: %w", err)
		}
		lag = &item
		return nil
	})
	return lag, err
}

func (r *AdvisoryMaterializer) ListVulnerabilityAdvisories(ctx context.Context, tenantID shared.ID, query vulnerabilityintel.AdvisoryQuery) (vulnerabilityintel.AdvisoryPage, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return vulnerabilityintel.AdvisoryPage{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	query = query.Normalize()
	if err := validateAdvisoryQuery(query); err != nil {
		return vulnerabilityintel.AdvisoryPage{}, err
	}
	statuses := make([]string, 0, len(query.Statuses))
	for _, status := range query.Statuses {
		statuses = append(statuses, string(status))
	}
	var kev bool
	if query.KEV != nil {
		kev = *query.KEV
	}
	var minCVSS, maxCVSS float64
	if query.MinCVSS != nil {
		minCVSS = *query.MinCVSS
	}
	if query.MaxCVSS != nil {
		maxCVSS = *query.MaxCVSS
	}
	rows, err := r.pool.Query(ctx, `WITH latest AS (
			SELECT DISTINCT ON (advisory_id) advisory_id,revision,data,changed_fields,created_at
			FROM advisory_revisions ORDER BY advisory_id,revision DESC
		)
		SELECT advisory_id,revision,data,changed_fields,created_at FROM latest
		WHERE advisory_id>$1
		AND (cardinality($2::text[])=0 OR data#>>'{canonical,Status}'=ANY($2::text[]))
		AND ($3='' OR lower(advisory_id) LIKE '%'||lower($3)||'%' OR lower(COALESCE(data#>>'{canonical,Advisory,Summary}','')) LIKE '%'||lower($3)||'%'
			OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(COALESCE(data#>'{canonical,Advisory,Aliases}','[]'::jsonb)) alias WHERE lower(alias) LIKE '%'||lower($3)||'%'))
		AND (NOT $4 OR COALESCE((data#>>'{canonical,KEV}')::boolean,false)=$5)
		AND (NOT $6 OR COALESCE((data#>>'{canonical,Advisory,CVSSScore}')::double precision,0)>=$7)
		AND (NOT $8 OR COALESCE((data#>>'{canonical,Advisory,CVSSScore}')::double precision,0)<=$9)
		AND ($10='' OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(COALESCE(data#>'{canonical,Sources}','[]'::jsonb)) source WHERE lower(source) LIKE '%'||lower($10)||'%'))
		ORDER BY advisory_id COLLATE "C" LIMIT $11`, query.AfterID, statuses, query.Search, query.KEV != nil, kev, query.MinCVSS != nil, minCVSS, query.MaxCVSS != nil, maxCVSS, query.Source, query.Limit+1)
	if err != nil {
		return vulnerabilityintel.AdvisoryPage{}, fmt.Errorf("list vulnerability advisories: %w", err)
	}
	defer rows.Close()
	page := vulnerabilityintel.AdvisoryPage{}
	for rows.Next() {
		var advisoryID string
		var item vulnerabilityintel.AdvisoryItem
		var payload, fields []byte
		if err := rows.Scan(&advisoryID, &item.Revision, &payload, &fields, &item.ChangedAt); err != nil {
			return vulnerabilityintel.AdvisoryPage{}, fmt.Errorf("scan vulnerability advisory: %w", err)
		}
		canonical, err := decodeCanonical(payload)
		if err != nil {
			return vulnerabilityintel.AdvisoryPage{}, err
		}
		if err := json.Unmarshal(fields, &item.ChangedFields); err != nil {
			return vulnerabilityintel.AdvisoryPage{}, fmt.Errorf("decode vulnerability advisory changes: %w", err)
		}
		item.Canonical = canonical
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return vulnerabilityintel.AdvisoryPage{}, err
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		page.Next = page.Items[len(page.Items)-1].Canonical.Advisory.ID
	}
	return page, nil
}

func (r *AdvisoryMaterializer) CountVulnerabilityAdvisoriesChangedSince(ctx context.Context, since time.Time) (int64, error) {
	if _, ok := shared.TenantFrom(ctx); !ok || since.IsZero() {
		return 0, fmt.Errorf("%w: tenant context and since are required", shared.ErrValidation)
	}
	var count int64
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM (
		SELECT DISTINCT ON (advisory_id) advisory_id,created_at FROM advisory_revisions ORDER BY advisory_id,revision DESC
	) latest WHERE created_at>=$1`, since).Scan(&count); err != nil {
		return 0, fmt.Errorf("count changed vulnerability advisories: %w", err)
	}
	return count, nil
}

func (r *AdvisoryMaterializer) ListVulnerabilityAdvisoryRevisions(ctx context.Context, query vulnerabilityintel.AdvisoryRevisionQuery) (vulnerabilityintel.AdvisoryRevisionPage, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return vulnerabilityintel.AdvisoryRevisionPage{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	query.AdvisoryID = strings.ToUpper(strings.TrimSpace(query.AdvisoryID))
	query.Limit = vulnerabilityintel.NormalizeLimit(query.Limit)
	if query.AdvisoryID == "" || query.BeforeRevision < 0 {
		return vulnerabilityintel.AdvisoryRevisionPage{}, fmt.Errorf("%w: advisory revision query is invalid", shared.ErrValidation)
	}
	var canonicalID string
	if err := r.pool.QueryRow(ctx, `SELECT canonical_id FROM advisory_aliases WHERE alias_id=$1`, query.AdvisoryID).Scan(&canonicalID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return vulnerabilityintel.AdvisoryRevisionPage{}, fmt.Errorf("resolve advisory alias: %w", err)
		}
		canonicalID = query.AdvisoryID
	}
	page := vulnerabilityintel.AdvisoryRevisionPage{}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT revisions.revision,revisions.data,revisions.changed_fields,revisions.created_at,
			COALESCE(array_agg(links.sync_run_id ORDER BY links.sync_run_id) FILTER (WHERE jobs.id IS NOT NULL),'{}')
			FROM advisory_revisions revisions
			LEFT JOIN advisory_revision_sync_runs links ON links.advisory_id=revisions.advisory_id AND links.revision=revisions.revision
			LEFT JOIN vulnerability_sync_runs runs ON runs.id=links.sync_run_id
			LEFT JOIN jobs ON jobs.id=runs.durable_job_id AND jobs.tenant_id=$4
			WHERE revisions.advisory_id=$1 AND ($2=0 OR revisions.revision<$2)
			GROUP BY revisions.advisory_id,revisions.revision,revisions.data,revisions.changed_fields,revisions.created_at
			ORDER BY revisions.revision DESC LIMIT $3`, canonicalID, query.BeforeRevision, query.Limit+1, tenantID.String())
		if err != nil {
			return fmt.Errorf("list advisory revisions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item vulnerabilityintel.AdvisoryRevisionItem
			var payload, fields []byte
			var syncRunIDs []string
			if err := rows.Scan(&item.Revision, &payload, &fields, &item.ChangedAt, &syncRunIDs); err != nil {
				return fmt.Errorf("scan advisory revision: %w", err)
			}
			item.SyncRunIDs = make([]shared.ID, len(syncRunIDs))
			for index, runID := range syncRunIDs {
				item.SyncRunIDs[index] = shared.ID(runID)
			}
			canonical, err := decodeCanonical(payload)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(fields, &item.ChangedFields); err != nil {
				return fmt.Errorf("decode advisory revision changes: %w", err)
			}
			item.Canonical = canonical
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return vulnerabilityintel.AdvisoryRevisionPage{}, err
	}
	if len(page.Items) == 0 {
		if _, err := r.GetCanonical(ctx, canonicalID); err != nil {
			return vulnerabilityintel.AdvisoryRevisionPage{}, err
		}
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		page.Next = page.Items[len(page.Items)-1].Revision
	}
	return page, nil
}

func (r *AdvisoryMaterializer) ListVulnerabilitySyncRunRevisions(ctx context.Context, runIDs []shared.ID, limitPerRun int) (map[shared.ID]vulnerabilityintel.AdvisoryRevisionLinkPage, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	if limitPerRun <= 0 || limitPerRun > vulnerabilityintel.MaxPageSize {
		return nil, fmt.Errorf("%w: invalid sync run revision limit", shared.ErrValidation)
	}
	ids := make([]string, 0, len(runIDs))
	for _, runID := range runIDs {
		if !runID.IsZero() {
			ids = append(ids, runID.String())
		}
	}
	out := make(map[shared.ID]vulnerabilityintel.AdvisoryRevisionLinkPage, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `WITH ranked AS (
			SELECT links.sync_run_id,revisions.advisory_id,revisions.revision,revisions.created_at,
				row_number() OVER (PARTITION BY links.sync_run_id ORDER BY revisions.created_at DESC,revisions.advisory_id,revisions.revision DESC) AS rank
			FROM advisory_revision_sync_runs links
			JOIN advisory_revisions revisions ON revisions.advisory_id=links.advisory_id AND revisions.revision=links.revision
			JOIN vulnerability_sync_runs runs ON runs.id=links.sync_run_id
			JOIN jobs ON jobs.id=runs.durable_job_id AND jobs.tenant_id=$2
			WHERE links.sync_run_id=ANY($1::text[])
		)
		SELECT sync_run_id,advisory_id,revision,created_at FROM ranked WHERE rank<=$3 ORDER BY sync_run_id,rank`, ids, tenantID.String(), limitPerRun+1)
		if err != nil {
			return fmt.Errorf("list sync run advisory revisions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var runID shared.ID
			var link vulnerabilityintel.AdvisoryRevisionLink
			if err := rows.Scan(&runID, &link.AdvisoryID, &link.Revision, &link.ChangedAt); err != nil {
				return fmt.Errorf("scan sync run advisory revision: %w", err)
			}
			page := out[runID]
			if len(page.Items) < limitPerRun {
				page.Items = append(page.Items, link)
			} else {
				page.Truncated = true
			}
			out[runID] = page
		}
		return rows.Err()
	})
	return out, err
}

func observationSyncRunIDs(records []advisory.ObservationRecord) []shared.ID {
	seen := map[shared.ID]struct{}{}
	for _, record := range records {
		runID := shared.ID(strings.TrimSpace(record.SyncRunID))
		if !runID.IsZero() {
			seen[runID] = struct{}{}
		}
	}
	out := make([]shared.ID, 0, len(seen))
	for runID := range seen {
		out = append(out, runID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func validateAdvisoryQuery(query vulnerabilityintel.AdvisoryQuery) error {
	for _, status := range query.Statuses {
		if !status.Valid() {
			return fmt.Errorf("%w: invalid advisory status", shared.ErrValidation)
		}
	}
	if query.MinCVSS != nil && (*query.MinCVSS < 0 || *query.MinCVSS > 10) || query.MaxCVSS != nil && (*query.MaxCVSS < 0 || *query.MaxCVSS > 10) || query.MinCVSS != nil && query.MaxCVSS != nil && *query.MinCVSS > *query.MaxCVSS {
		return fmt.Errorf("%w: invalid CVSS range", shared.ErrValidation)
	}
	return nil
}
