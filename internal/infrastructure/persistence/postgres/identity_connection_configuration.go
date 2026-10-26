package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const legacyFixedTenantOIDCProvenance = "legacy_fixed_tenant_oidc"

// legacyConfigurationState is the bounded result of the shared read/write scaffold guard.
// It carries only the first configured trust pin, never revision settings or sealed secrets.
type legacyConfigurationState struct {
	id         shared.ID
	issuer     string
	configured ports.IdentityOIDCSettings
}

func (s legacyConfigurationState) pending(tenant shared.ID) (bool, ports.IdentityOIDCSettings) {
	if s.id != legacyIdentityID("connection_", tenant, shared.ID(s.issuer)) {
		return false, ports.IdentityOIDCSettings{}
	}
	return true, s.configured
}

// loadLegacyConfigurationStates applies the complete structural guard in PostgreSQL and returns
// one bounded row per valid candidate. Native connections and malformed scaffolds are rejected
// before their revision history crosses the process boundary.
func loadLegacyConfigurationStates(ctx context.Context, tx pgx.Tx, tenant shared.ID, ids []string) (map[shared.ID]legacyConfigurationState, error) {
	if len(ids) == 0 {
		return map[shared.ID]legacyConfigurationState{}, nil
	}
	rows, err := tx.Query(ctx, `WITH cutover AS (
		SELECT COALESCE((SELECT cutover_phase FROM identity_policies WHERE tenant_id=$1),'legacy') AS phase,
		EXISTS(SELECT 1 FROM identity_cutover_ledger WHERE tenant_id=$1 AND action='declared') AS declared,
		EXISTS(SELECT 1 FROM identity_cutover_ledger WHERE tenant_id=$1 AND action='contracted') AS contracted
	), candidates AS (
		SELECT c.id,c.trust_namespace,c.version
		FROM identity_connections c
		JOIN identity_connection_revisions r1 ON r1.tenant_id=c.tenant_id AND r1.connection_id=c.id AND r1.revision=1
		CROSS JOIN cutover
		WHERE c.tenant_id=$1 AND c.id=ANY($2) AND c.protocol='oidc' AND NOT c.enabled AND c.revision=1 AND c.epoch=1
		  AND cutover.declared AND NOT cutover.contracted AND cutover.phase='declared'
		  AND r1.settings=jsonb_build_object('issuer',c.trust_namespace,'provenance',$3::text)
		  AND r1.actor=$4 AND r1.created_at=c.created_at
	)
	SELECT c.id,c.trust_namespace,COALESCE(r2.settings->>'client_id',''),COALESCE(r2.settings->>'redirect_url','')
	FROM candidates c
	CROSS JOIN LATERAL (
		SELECT count(*)::int AS revision_count,max(revision) AS max_revision
		FROM identity_connection_revisions r WHERE r.tenant_id=$1 AND r.connection_id=c.id
	) history
	LEFT JOIN identity_connection_revisions r2 ON r2.tenant_id=$1 AND r2.connection_id=c.id AND r2.revision=2
	WHERE (history.revision_count=1 AND history.max_revision=1 AND c.version=1)
	   OR (history.revision_count>=2 AND history.max_revision=history.revision_count
		AND r2.settings ?& ARRAY['client_id','redirect_url','sealed_client_secret']
		AND r2.settings-ARRAY['client_id','redirect_url','sealed_client_secret']='{}'::jsonb
		AND jsonb_typeof(r2.settings->'client_id')='string' AND r2.settings->>'client_id'<>''
		AND jsonb_typeof(r2.settings->'redirect_url')='string' AND r2.settings->>'redirect_url'<>''
		AND jsonb_typeof(r2.settings->'sealed_client_secret')='string' AND r2.settings->>'sealed_client_secret'<>''
		AND NOT EXISTS (
			SELECT 1 FROM identity_connection_revisions r
			WHERE r.tenant_id=$1 AND r.connection_id=c.id AND r.revision>=2 AND (
				NOT (r.settings ?& ARRAY['client_id','redirect_url','sealed_client_secret'])
				OR r.settings-ARRAY['client_id','redirect_url','sealed_client_secret']<>'{}'::jsonb
				OR jsonb_typeof(r.settings->'client_id')<>'string' OR r.settings->>'client_id'=''
				OR jsonb_typeof(r.settings->'redirect_url')<>'string' OR r.settings->>'redirect_url'=''
				OR jsonb_typeof(r.settings->'sealed_client_secret')<>'string' OR r.settings->>'sealed_client_secret'=''
				OR r.settings->>'client_id' IS DISTINCT FROM r2.settings->>'client_id'
				OR r.settings->>'redirect_url' IS DISTINCT FROM r2.settings->>'redirect_url'
			)
		)
	)`, tenant.String(), ids, legacyFixedTenantOIDCProvenance, identityProjectionActor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[shared.ID]legacyConfigurationState, len(ids))
	for rows.Next() {
		var id, issuer, clientID, redirectURL string
		if err := rows.Scan(&id, &issuer, &clientID, &redirectURL); err != nil {
			return nil, err
		}
		out[shared.ID(id)] = legacyConfigurationState{id: shared.ID(id), issuer: issuer, configured: ports.IdentityOIDCSettings{ClientID: clientID, RedirectURL: redirectURL}}
	}
	return out, rows.Err()
}

func loadLegacyConfigurationState(ctx context.Context, tx pgx.Tx, tenant, id shared.ID) (legacyConfigurationState, bool, error) {
	states, err := loadLegacyConfigurationStates(ctx, tx, tenant, []string{id.String()})
	if err != nil {
		return legacyConfigurationState{}, false, err
	}
	state, ok := states[id]
	return state, ok, nil
}

// populateLegacyConfigurationPending adds administrative metadata with one batched lookup. Login
// and GetIdentityConnection keep their existing projections and therefore cannot observe it.
func populateLegacyConfigurationPending(ctx context.Context, tx pgx.Tx, tenant shared.ID, connections []ports.IdentityConnection) error {
	ids := make([]string, 0, len(connections))
	for _, connection := range connections {
		ids = append(ids, connection.ID.String())
	}
	states, err := loadLegacyConfigurationStates(ctx, tx, tenant, ids)
	if err != nil {
		return err
	}
	for i := range connections {
		state, ok := states[connections[i].ID]
		if !ok {
			continue
		}
		pending, configured := state.pending(tenant)
		if pending {
			connections[i].ConfigurationPending = true
			connections[i].ConfigurationClientID = configured.ClientID
		}
	}
	return nil
}
