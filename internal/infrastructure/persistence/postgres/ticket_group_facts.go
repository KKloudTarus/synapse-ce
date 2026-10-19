package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.TicketGroupFactsReader = (*TicketStore)(nil)

func (s *TicketStore) GroupTicketFacts(ctx context.Context, tenant, mappingID, projectID shared.ID, vulnerability string, candidate ports.TicketGroupMember) (out []ports.TicketGroupFact, err error) {
	if tenant.IsZero() || mappingID.IsZero() || projectID.IsZero() || strings.TrimSpace(vulnerability) == "" || len(vulnerability) > 255 || candidate.EngagementID.IsZero() || candidate.FindingID.IsZero() {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var valid bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ticket_mappings WHERE tenant_id=$1 AND id=$2 AND project_id=$3 AND grouping_mode='vulnerability_project' AND data_class='detail')`, tenant.String(), mappingID.String(), projectID.String()).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return shared.ErrNotFound
		}
		var f finding.Finding
		var advisory string
		err := tx.QueryRow(ctx, `SELECT f.kind,f.evidence_score,f.proposed_by,COALESCE(f.advisory_id,'') FROM findings f JOIN engagements e ON e.tenant_id=f.tenant_id AND e.id=f.engagement_id WHERE f.tenant_id=$1 AND f.engagement_id=$2 AND f.id=$3 AND e.project_id=$4`, tenant.String(), candidate.EngagementID.String(), candidate.FindingID.String(), projectID.String()).Scan(&f.Kind, &f.EvidenceScore, &f.ProposedBy, &advisory)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(advisory) != vulnerability || !f.CanPromote() {
			return shared.ErrForbidden
		}
		rows, err := tx.Query(ctx, `WITH members AS (
   SELECT gm.engagement_id,gm.finding_id FROM ticket_group_members gm JOIN ticket_groups g ON g.tenant_id=gm.tenant_id AND g.id=gm.group_id
   WHERE g.tenant_id=$1 AND g.mapping_id=$2 AND g.project_id=$3 AND g.vulnerability_id=$4
   UNION SELECT $5::text,$6::text
  ) SELECT DISTINCT f.engagement_id,f.id,f.kind,f.evidence_score,f.proposed_by,COALESCE(a.id,''),COALESCE(a.name,''),f.title,f.severity,f.status,f.version,COALESCE(g.revision,0),COALESCE(ns.external_notifications,'inherit')
  FROM members m JOIN findings f ON f.tenant_id=$1 AND f.engagement_id=m.engagement_id AND f.id=m.finding_id
  JOIN engagements e ON e.tenant_id=f.tenant_id AND e.id=f.engagement_id AND e.project_id=$3
  LEFT JOIN ticket_groups g ON g.tenant_id=f.tenant_id AND g.mapping_id=$2 AND g.project_id=$3 AND g.vulnerability_id=$4
 LEFT JOIN notification_engagement_settings ns ON ns.tenant_id=f.tenant_id AND ns.engagement_id=f.engagement_id
  LEFT JOIN attack_path_edges b ON b.tenant_id=f.tenant_id AND b.engagement_id=f.engagement_id AND b.target_kind='canonical' AND b.to_id=f.id AND b.canonical_finding_id=f.id AND b.confidence='observed'
  LEFT JOIN fleet_assets a ON a.tenant_id=b.tenant_id AND a.id=b.from_id
  WHERE BTRIM(COALESCE(f.advisory_id,''))=$4
  ORDER BY f.engagement_id,f.id,COALESCE(a.id,'') LIMIT 101`, tenant.String(), mappingID.String(), projectID.String(), vulnerability, candidate.EngagementID.String(), candidate.FindingID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var fact ports.TicketGroupFact
			var native finding.Finding
			if err := rows.Scan(&fact.EngagementID, &fact.FindingID, &native.Kind, &native.EvidenceScore, &native.ProposedBy, &fact.AssetID, &fact.AssetName, &fact.Title, &fact.Severity, &fact.Status, &fact.FindingVersion, &fact.GroupRevision, &fact.ExternalNotifications); err != nil {
				return err
			}
			count++
			if count > 100 {
				return shared.ErrValidation
			}
			if native.CanPromote() {
				out = append(out, fact)
			}
		}
		return rows.Err()
	})
	return out, ticketWriteError(err)
}
