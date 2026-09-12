package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (r *OwnershipRepository) CreateSnapshot(ctx context.Context, s ownership.Snapshot) error {
	if _, err := s.Parse(); err != nil {
		return err
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if tenant != s.TenantID {
			return shared.ErrValidation
		}
		_, err := tx.Exec(ctx, `INSERT INTO ownership_snapshots(tenant_id,engagement_id,id,repository,source_revision,file_path,content,content_hash,parser_version,trust,approved_by,accept_diagnostics,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, tenant, s.EngagementID, s.ID, s.Repository, s.Revision, s.FilePath, s.Content, s.Hash, s.ParserVersion, s.Trust, s.ApprovedBy, s.AcceptDiagnostics, s.CreatedAt)
		return err
	})
}

func ownershipSnapshot(ctx context.Context, tx pgx.Tx, tenant, id shared.ID) (s ownership.Snapshot, err error) {
	err = tx.QueryRow(ctx, `SELECT tenant_id,engagement_id,id,repository,source_revision,file_path,content,content_hash,parser_version,trust,approved_by,accept_diagnostics,created_at FROM ownership_snapshots WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&s.TenantID, &s.EngagementID, &s.ID, &s.Repository, &s.Revision, &s.FilePath, &s.Content, &s.Hash, &s.ParserVersion, &s.Trust, &s.ApprovedBy, &s.AcceptDiagnostics, &s.CreatedAt)
	return
}
func (r *OwnershipRepository) GetSnapshot(ctx context.Context, id shared.ID) (s ownership.Snapshot, err error) {
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var e error
		s, e = ownershipSnapshot(ctx, tx, tenant, id)
		return e
	})
	return
}

func ownershipVersion(ctx context.Context, tx pgx.Tx, tenant, policy shared.ID, version int) (p ownership.PolicyVersion, err error) {
	var data []byte
	err = tx.QueryRow(ctx, `SELECT payload FROM ownership_policy_versions WHERE tenant_id=$1 AND policy_id=$2 AND version=$3`, tenant, policy, version).Scan(&data)
	if err == nil {
		err = json.Unmarshal(data, &p)
		p.TenantID = tenant
	}
	return
}
func (r *OwnershipRepository) GetPolicyVersion(ctx context.Context, id shared.ID, version int) (p ownership.PolicyVersion, err error) {
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var e error
		p, e = ownershipVersion(ctx, tx, tenant, id, version)
		return e
	})
	return
}

func (r *OwnershipRepository) CreatePolicyVersion(ctx context.Context, p ownership.PolicyVersion) error {
	if err := p.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(data) > 8*1024*1024 {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if tenant != p.TenantID {
			return shared.ErrValidation
		}
		if err := ownershipPolicyScopeLock(ctx, tx, tenant, p.EngagementID, true); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO ownership_policies(tenant_id,engagement_id,id,repository) VALUES($1,$2,$3,$4) ON CONFLICT (tenant_id,id) DO NOTHING`, tenant, p.EngagementID, p.PolicyID, p.Repository)
		if err != nil {
			return err
		}
		var engagement shared.ID
		var repository string
		if err := tx.QueryRow(ctx, `SELECT engagement_id,repository FROM ownership_policies WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, p.PolicyID).Scan(&engagement, &repository); err != nil {
			return err
		}
		if engagement != p.EngagementID || repository != p.Repository {
			return shared.ErrConflict
		}
		var next int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM ownership_policy_versions WHERE tenant_id=$1 AND policy_id=$2`, tenant, p.PolicyID).Scan(&next); err != nil {
			return err
		}
		if next != p.Version {
			return shared.ErrConflict
		}
		if !p.SnapshotID.IsZero() {
			s, err := ownershipSnapshot(ctx, tx, tenant, p.SnapshotID)
			if err != nil {
				return err
			}
			if _, err := ownership.NewResolver(p, &s); err != nil {
				return err
			}
		}
		teams, projects, assets := ownershipPolicyRefs(p)
		if err := ownershipActiveTeams(ctx, tx, tenant, teams); err != nil {
			return err
		}
		for _, rule := range p.Rules {
			for _, eng := range rule.When.EngagementIDs {
				if eng != p.EngagementID {
					return shared.ErrValidation
				}
			}
		}
		for _, m := range p.Mappings {
			if !m.SuggestedUserID.IsZero() {
				if err := ownershipEligibleUser(ctx, tx, tenant, m.SuggestedUserID, m.TeamID, true); err != nil {
					return err
				}
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO ownership_policy_versions(tenant_id,engagement_id,policy_id,version,snapshot_id,content_hash,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, tenant, p.EngagementID, p.PolicyID, p.Version, nullableID(p.SnapshotID), p.Hash(), data, p.CreatedAt)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ownership_policy_team_refs(tenant_id,policy_id,version,team_id) SELECT $1,$2,$3,unnest($4::text[])`, tenant, p.PolicyID, p.Version, teams); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ownership_policy_project_refs(tenant_id,policy_id,version,project_id) SELECT $1,$2,$3,unnest($4::text[])`, tenant, p.PolicyID, p.Version, projects); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ownership_policy_asset_refs(tenant_id,policy_id,version,asset_id) SELECT $1,$2,$3,unnest($4::text[])`, tenant, p.PolicyID, p.Version, assets)
		return err
	})
}

func ownershipPolicyRefs(p ownership.PolicyVersion) (teams, projects, assets []string) {
	for _, m := range p.Mappings {
		teams = append(teams, m.TeamID.String())
	}
	for _, m := range p.Assets {
		teams = append(teams, m.TeamID.String())
		assets = append(assets, m.AssetID.String())
	}
	for _, rule := range p.Rules {
		if !rule.TeamID.IsZero() {
			teams = append(teams, rule.TeamID.String())
		}
		for _, id := range rule.When.ProjectIDs {
			projects = append(projects, id.String())
		}
		for _, id := range rule.When.AssetIDs {
			assets = append(assets, id.String())
		}
	}
	slices.Sort(teams)
	slices.Sort(projects)
	slices.Sort(assets)
	return slices.Compact(teams), slices.Compact(projects), slices.Compact(assets)
}

func ownershipActiveTeams(ctx context.Context, tx pgx.Tx, tenant shared.ID, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT id,archived FROM ownership_teams WHERE tenant_id=$1 AND id=ANY($2::text[]) ORDER BY id FOR SHARE`, tenant, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		var archived bool
		if err := rows.Scan(&id, &archived); err != nil {
			return err
		}
		if archived {
			return shared.ErrValidation
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != len(ids) {
		return shared.ErrNotFound
	}
	return nil
}

func (r *OwnershipRepository) ActivatePolicy(ctx context.Context, a ports.OwnershipActivation) error {
	if a.PolicyID.IsZero() || a.ExpectedRevision < 1 || a.Version < 0 || a.Version > 0 && a.ExpectedHash == "" {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var engagement shared.ID
		if err := tx.QueryRow(ctx, `SELECT engagement_id FROM ownership_policies WHERE tenant_id=$1 AND id=$2`, tenant, a.PolicyID).Scan(&engagement); err != nil {
			return err
		}
		if err := ownershipPolicyScopeLock(ctx, tx, tenant, engagement, true); err != nil {
			return err
		}
		var revision int
		if err := tx.QueryRow(ctx, `SELECT revision FROM ownership_policies WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, a.PolicyID).Scan(&revision); err != nil {
			return err
		}
		if revision != a.ExpectedRevision {
			return shared.ErrConflict
		}
		var active any
		if a.Version > 0 {
			p, err := ownershipVersion(ctx, tx, tenant, a.PolicyID, a.Version)
			if err != nil {
				return err
			}
			if p.Hash() != a.ExpectedHash {
				return shared.ErrConflict
			}
			if !p.SnapshotID.IsZero() {
				s, err := ownershipSnapshot(ctx, tx, tenant, p.SnapshotID)
				if err != nil {
					return err
				}
				parsed, err := s.Parse()
				if err != nil {
					return err
				}
				if s.Trust == "untrusted" || len(parsed.Diagnostics) > 0 && !s.AcceptDiagnostics {
					return shared.ErrValidation
				}
			}
			teams, _, _ := ownershipPolicyRefs(p)
			if err := ownershipActiveTeams(ctx, tx, tenant, teams); err != nil {
				return err
			}
			active = a.Version
		}
		return ownershipCAS(tx.Exec(ctx, `UPDATE ownership_policies SET active_version=$3,revision=revision+1,activated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$4`, tenant, a.PolicyID, active, revision))
	})
}

func (r *OwnershipRepository) GetActivePolicy(ctx context.Context, eng shared.ID, repo string) (out ports.OwnershipPolicy, err error) {
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var data []byte
		err := tx.QueryRow(ctx, `SELECT v.payload,p.revision FROM ownership_policies p JOIN ownership_policy_versions v ON v.tenant_id=p.tenant_id AND v.policy_id=p.id AND v.version=p.active_version WHERE p.tenant_id=$1 AND p.engagement_id=$2 AND p.repository IN ('',$3) ORDER BY (p.repository=$3) DESC LIMIT 1`, tenant, eng, repo).Scan(&data, &out.Revision)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(data, &out.Version); err != nil {
			return err
		}
		out.Version.TenantID = tenant
		return nil
	})
	return
}

func ownershipCheckPolicy(ctx context.Context, tx pgx.Tx, tenant shared.ID, m ports.OwnershipMutation) error {
	if err := ownershipPolicyScopeLock(ctx, tx, tenant, m.EngagementID, false); err != nil {
		return err
	}
	var selected shared.ID
	if err := tx.QueryRow(ctx, `SELECT id FROM ownership_policies WHERE tenant_id=$1 AND engagement_id=$2 AND active_version IS NOT NULL AND repository IN ('',$3) ORDER BY (repository=$3) DESC LIMIT 1`, tenant, m.EngagementID, m.Repository).Scan(&selected); err != nil {
		return err
	}
	if selected != m.PolicyID {
		return shared.ErrConflict
	}
	var active *int
	var revision int
	var engagement shared.ID
	if err := tx.QueryRow(ctx, `SELECT active_version,revision,engagement_id FROM ownership_policies WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, m.PolicyID).Scan(&active, &revision, &engagement); err != nil {
		return err
	}
	if engagement != m.EngagementID || active == nil || *active != m.PolicyVersion || revision != m.ExpectedPolicyRevision {
		return shared.ErrConflict
	}
	p, err := ownershipVersion(ctx, tx, tenant, m.PolicyID, m.PolicyVersion)
	if err != nil {
		return err
	}
	if p.Hash() != m.Result.PolicyHash {
		return shared.ErrConflict
	}
	if !m.TeamID.IsZero() {
		var id string
		err := tx.QueryRow(ctx, `SELECT team_id FROM ownership_policy_team_refs WHERE tenant_id=$1 AND policy_id=$2 AND version=$3 AND team_id=$4`, tenant, m.PolicyID, m.PolicyVersion, m.TeamID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrValidation
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Scope locks also cover policy insertion: a newly activated repository-specific
// policy cannot race a worker committing the engagement fallback it supersedes.
func ownershipPolicyScopeLock(ctx context.Context, tx pgx.Tx, tenant, engagement shared.ID, exclusive bool) error {
	key, _ := json.Marshal([]shared.ID{tenant, engagement})
	query := `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`
	if exclusive {
		query = `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`
	}
	_, err := tx.Exec(ctx, query, "ownership-policy:"+string(key))
	return err
}
