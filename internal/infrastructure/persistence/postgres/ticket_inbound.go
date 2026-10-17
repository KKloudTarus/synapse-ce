package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketInboundStore = (*TicketStore)(nil)

type ticketTargetRef struct{ intentID, mappingID shared.ID }

func loadTicketStatusTarget(ctx context.Context, tx pgx.Tx, tenant, intentID, mappingID shared.ID) (ports.TicketStatusTarget, error) {
	mapping, err := scanTicketMapping(tx.QueryRow(ctx, `SELECT `+mappingCols+` FROM ticket_mappings WHERE tenant_id=$1 AND id=$2`, tenant.String(), mappingID.String()))
	if err != nil {
		return ports.TicketStatusTarget{}, err
	}
	intent, err := scanTicketIntent(tx.QueryRow(ctx, `SELECT `+intentCols+` FROM ticket_intents WHERE tenant_id=$1 AND id=$2`, tenant.String(), intentID.String()))
	if err != nil {
		return ports.TicketStatusTarget{}, err
	}
	return ports.TicketStatusTarget{Mapping: mapping, Intent: intent}, nil
}

func (s *TicketStore) ListInboundTicketTargets(ctx context.Context, tenant shared.ID, limit int) (out []ports.TicketStatusTarget, err error) {
	if tenant.IsZero() || limit < 1 || limit > 250 {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT p.intent_id,p.mapping_id FROM ticket_inbound_poll_progress p
			JOIN ticket_intents i ON i.tenant_id=p.tenant_id AND i.id=p.intent_id
			WHERE p.tenant_id=$1 AND i.state='done' AND i.action='create' AND i.remote_id=p.remote_id
			ORDER BY p.checked_at,p.version,p.intent_id LIMIT $2`, tenant.String(), limit)
		if e != nil {
			return e
		}
		var refs []ticketTargetRef
		for rows.Next() {
			var intentID, mappingID shared.ID
			if e := rows.Scan(&intentID, &mappingID); e != nil {
				return e
			}
			refs = append(refs, ticketTargetRef{intentID, mappingID})
		}
		if e := rows.Err(); e != nil {
			return e
		}
		rows.Close()
		for _, ref := range refs {
			target, e := loadTicketStatusTarget(ctx, tx, tenant, ref.intentID, ref.mappingID)
			if e != nil {
				return e
			}
			out = append(out, target)
		}
		return nil
	})
	return out, ticketWriteError(err)
}

func (s *TicketStore) RecordInboundTicketPoll(ctx context.Context, tenant shared.ID, target ports.TicketStatusTarget, checkedAt time.Time) error {
	if tenant.IsZero() || target.Mapping.ID.IsZero() || target.Intent.EngagementID.IsZero() || target.Intent.FindingID.IsZero() || strings.TrimSpace(target.Intent.RemoteID) == "" || checkedAt.IsZero() {
		return shared.ErrValidation
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO ticket_inbound_poll_progress(tenant_id,intent_id,mapping_id,engagement_id,finding_id,remote_id,checked_at,version)
			SELECT tenant_id,id,mapping_id,engagement_id,finding_id,remote_id,$7,1 FROM ticket_intents
			WHERE tenant_id=$1 AND id=$2 AND mapping_id=$3 AND engagement_id=$4 AND finding_id=$5 AND remote_id=$6 AND state='done' AND action='create'
			ON CONFLICT(tenant_id,intent_id)
			DO UPDATE SET checked_at=EXCLUDED.checked_at,version=ticket_inbound_poll_progress.version+1`, tenant.String(), target.Intent.ID.String(), target.Mapping.ID.String(), target.Intent.EngagementID.String(), target.Intent.FindingID.String(), target.Intent.RemoteID, checkedAt.UTC())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrNotFound
		}
		return nil
	}))
}

func (s *TicketStore) ResolveInboundTicket(ctx context.Context, tenant, integrationID shared.ID, remoteID string) (out []ports.TicketStatusTarget, err error) {
	if tenant.IsZero() || integrationID.IsZero() || strings.TrimSpace(remoteID) == "" {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT i.id,i.mapping_id FROM ticket_intents i WHERE i.tenant_id=$1 AND i.integration_id=$2 AND i.remote_id=$3 AND i.state='done' AND i.action='create'`, tenant.String(), integrationID.String(), remoteID)
		if e != nil {
			return e
		}
		var refs []ticketTargetRef
		for rows.Next() {
			var intentID, mappingID shared.ID
			if e := rows.Scan(&intentID, &mappingID); e != nil {
				return e
			}
			refs = append(refs, ticketTargetRef{intentID, mappingID})
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return e
		}
		rows.Close()
		bases := make([]ports.TicketStatusTarget, 0, len(refs))
		for _, ref := range refs {
			target, e := loadTicketStatusTarget(ctx, tx, tenant, ref.intentID, ref.mappingID)
			if e != nil {
				return e
			}
			bases = append(bases, target)
		}
		for _, base := range bases {
			members, e := tx.Query(ctx, `SELECT gm.engagement_id,gm.finding_id FROM ticket_groups g JOIN ticket_group_members gm ON gm.tenant_id=g.tenant_id AND gm.group_id=g.id WHERE g.tenant_id=$1 AND g.mapping_id=$2 AND g.remote_id=$3`, tenant.String(), base.Mapping.ID.String(), remoteID)
			if e != nil {
				return e
			}
			found := false
			for members.Next() {
				var engagementID, findingID shared.ID
				if e = members.Scan(&engagementID, &findingID); e != nil {
					members.Close()
					return e
				}
				copy := base.Intent.Clone()
				copy.EngagementID, copy.FindingID = engagementID, findingID
				out = append(out, ports.TicketStatusTarget{Mapping: base.Mapping, Intent: copy})
				found = true
			}
			if e = members.Err(); e != nil {
				members.Close()
				return e
			}
			members.Close()
			if !found {
				out = append(out, base)
			}
		}
		return nil
	})
	return out, ticketWriteError(err)
}

func (s *TicketStore) ReduceInboundTicket(ctx context.Context, tenant shared.ID, observations []ticketing.ExternalTicketObservation, comments []ticketing.ExternalTicketComment, now time.Time) error {
	if tenant.IsZero() || now.IsZero() {
		return shared.ErrValidation
	}
	tx, err := ticketTx(ctx, tenant)
	if err == nil {
		return s.reduceInboundTicketTx(ctx, tx, tenant, observations, comments, now)
	}
	if !errors.Is(err, shared.ErrValidation) {
		return err
	}
	return ticketWriteError(requireTenant(ctx, s.pool, tenant, func(bound pgx.Tx) error {
		return s.reduceInboundTicketTx(ctx, bound, tenant, observations, comments, now)
	}))
}

// reduceInboundTicketTx is shared by signed-webhook receipts (where the
// caller's transaction also owns dedupe) and polling (which opens a tenant
// transaction for the local reducer only). It never performs network I/O.
func (s *TicketStore) reduceInboundTicketTx(ctx context.Context, tx pgx.Tx, tenant shared.ID, observations []ticketing.ExternalTicketObservation, comments []ticketing.ExternalTicketComment, now time.Time) error {
	type findingKey struct{ engagement, finding shared.ID }
	keys := make(map[findingKey]struct{}, len(observations)+len(comments))
	for _, item := range observations {
		keys[findingKey{item.EngagementID, item.FindingID}] = struct{}{}
	}
	for _, item := range comments {
		keys[findingKey{item.EngagementID, item.FindingID}] = struct{}{}
	}
	ordered := make([]findingKey, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].engagement != ordered[j].engagement {
			return ordered[i].engagement < ordered[j].engagement
		}
		return ordered[i].finding < ordered[j].finding
	})
	for _, key := range ordered {
		var locked int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM findings WHERE tenant_id=$1 AND engagement_id=$2 AND id=$3 FOR UPDATE`, tenant.String(), key.engagement.String(), key.finding.String()).Scan(&locked); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return err
		}
	}
	for _, item := range observations {
		if item.TenantID != tenant || !item.Valid() {
			return shared.ErrValidation
		}
		var previous string
		var previousUpdated *time.Time
		var previousAuthor string
		var previousAuthorKnown, previousPending bool
		var previousStatusChanged *time.Time
		var mapped bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ticket_mappings WHERE tenant_id=$1 AND id=$2 AND integration_id=$3)`, tenant.String(), item.MappingID.String(), item.IntegrationID.String()).Scan(&mapped); err != nil || !mapped {
			if err != nil {
				return err
			}
			return shared.ErrForbidden
		}
		err := tx.QueryRow(ctx, `SELECT status_category,provider_updated_at,author_id,status_author_known,pending_done,status_changed_at FROM ticket_external_observations WHERE tenant_id=$1 AND mapping_id=$2 AND engagement_id=$3 AND finding_id=$4 AND remote_id=$5 FOR UPDATE`, tenant.String(), item.MappingID.String(), item.EngagementID.String(), item.FindingID.String(), item.RemoteID).Scan(&previous, &previousUpdated, &previousAuthor, &previousAuthorKnown, &previousPending, &previousStatusChanged)
		found := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if item.DeletedOrUnreadable && item.StatusCategory == "" && found {
			item.StatusCategory = previous
		}
		if item.DeletedOrUnreadable && item.ProviderUpdatedAt.IsZero() && previousUpdated != nil {
			item.ProviderUpdatedAt = previousUpdated.UTC()
		}
		if found && previousUpdated != nil && !item.ProviderUpdatedAt.IsZero() {
			if item.ProviderUpdatedAt.Before(*previousUpdated) || (item.ProviderUpdatedAt.Equal(*previousUpdated) && item.StatusCategory != previous) {
				continue
			}
		}
		if found && !item.StatusAuthorKnown && previousAuthorKnown && item.StatusCategory == previous {
			item.AuthorID, item.StatusAuthorKnown = previousAuthor, true
			if previousStatusChanged != nil {
				item.StatusChangedAt = previousStatusChanged.UTC()
			}
		}
		enteredDone := item.StatusCategory == "done" && (!found || previous != "done")
		if item.StatusCategory != "done" || item.DeletedOrUnreadable {
			item.PendingDone = false
		} else if enteredDone {
			item.PendingDone = true
		} else if found {
			item.PendingDone = previousPending
		}
		createProposal := item.PendingDone && item.StatusAuthorKnown && !item.OwnWrite
		if item.PendingDone && item.StatusAuthorKnown {
			item.PendingDone = false
		}
		_, err = tx.Exec(ctx, `INSERT INTO ticket_external_observations (tenant_id,integration_id,mapping_id,engagement_id,finding_id,remote_id,status_category,provider_updated_at,status_changed_at,author_id,resolution_name,status_author_known,pending_done,deleted_or_unreadable,checked_at,version) VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,'')::timestamptz,NULLIF($9,'')::timestamptz,$10,$11,$12,$13,$14,$15,1) ON CONFLICT(tenant_id,mapping_id,engagement_id,finding_id,remote_id) DO UPDATE SET status_category=EXCLUDED.status_category,provider_updated_at=EXCLUDED.provider_updated_at,status_changed_at=EXCLUDED.status_changed_at,author_id=EXCLUDED.author_id,resolution_name=EXCLUDED.resolution_name,status_author_known=EXCLUDED.status_author_known,pending_done=EXCLUDED.pending_done,deleted_or_unreadable=EXCLUDED.deleted_or_unreadable,checked_at=EXCLUDED.checked_at,version=ticket_external_observations.version+1`, tenant.String(), item.IntegrationID.String(), item.MappingID.String(), item.EngagementID.String(), item.FindingID.String(), item.RemoteID, item.StatusCategory, timeOrEmpty(item.ProviderUpdatedAt), timeOrEmpty(item.StatusChangedAt), item.AuthorID, item.ResolutionName, item.StatusAuthorKnown, item.PendingDone, item.DeletedOrUnreadable, item.CheckedAt)
		if err != nil {
			return err
		}
		if createProposal {
			var exists bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ticket_retest_proposals WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3 AND observed_at>$4)`, tenant.String(), item.EngagementID.String(), item.FindingID.String(), now.Add(-time.Hour)).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				_, err = tx.Exec(ctx, `INSERT INTO ticket_retest_proposals(id,tenant_id,integration_id,engagement_id,finding_id,remote_id,resolution_name,observed_at,state) VALUES('inbound-proposal-'||md5($1||$2||$3||($4::timestamptz)::text),$1,$5,$2,$3,$6,$7,$4::timestamptz,'pending')`, tenant.String(), item.EngagementID.String(), item.FindingID.String(), now, item.IntegrationID.String(), item.RemoteID, item.ResolutionName)
				if err != nil {
					return err
				}
			}
		}
	}
	for _, comment := range comments {
		if comment.ID.IsZero() || comment.TenantID != tenant || len(comment.Body) == 0 || len(comment.Body) > 16<<10 {
			return shared.ErrValidation
		}
		_, err := tx.Exec(ctx, `INSERT INTO ticket_external_comments(id,tenant_id,integration_id,engagement_id,finding_id,remote_id,author_id,body,provider_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::timestamptz,$10) ON CONFLICT(id) DO NOTHING`, comment.ID.String(), tenant.String(), comment.IntegrationID.String(), comment.EngagementID.String(), comment.FindingID.String(), comment.RemoteID, comment.AuthorID, comment.Body, timeOrEmpty(comment.ProviderAt), comment.CreatedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

func timeOrEmpty(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (s *TicketStore) ListInboundTicketView(ctx context.Context, tenant, engagementID, findingID shared.ID) (out ports.TicketInboundView, err error) {
	if tenant.IsZero() || engagementID.IsZero() || findingID.IsZero() {
		return out, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT integration_id,mapping_id,remote_id,status_category,provider_updated_at,status_changed_at,author_id,resolution_name,status_author_known,pending_done,deleted_or_unreadable,checked_at,version FROM ticket_external_observations WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3 ORDER BY checked_at DESC LIMIT 100`, tenant.String(), engagementID.String(), findingID.String())
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v ticketing.ExternalTicketObservation
			v.TenantID, v.EngagementID, v.FindingID = tenant, engagementID, findingID
			var providerUpdatedAt, statusChangedAt *time.Time
			if e = rows.Scan(&v.IntegrationID, &v.MappingID, &v.RemoteID, &v.StatusCategory, &providerUpdatedAt, &statusChangedAt, &v.AuthorID, &v.ResolutionName, &v.StatusAuthorKnown, &v.PendingDone, &v.DeletedOrUnreadable, &v.CheckedAt, &v.Version); e != nil {
				return e
			}
			if providerUpdatedAt != nil {
				v.ProviderUpdatedAt = providerUpdatedAt.UTC()
			}
			if statusChangedAt != nil {
				v.StatusChangedAt = statusChangedAt.UTC()
			}
			out.Observations = append(out.Observations, v)
		}
		if e = rows.Err(); e != nil {
			return e
		}
		proposals, e := tx.Query(ctx, `SELECT id,integration_id,remote_id,resolution_name,observed_at,state FROM ticket_retest_proposals WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3 ORDER BY observed_at DESC LIMIT 100`, tenant.String(), engagementID.String(), findingID.String())
		if e != nil {
			return e
		}
		defer proposals.Close()
		for proposals.Next() {
			var v ticketing.RetestProposal
			v.TenantID, v.EngagementID, v.FindingID = tenant, engagementID, findingID
			if e = proposals.Scan(&v.ID, &v.IntegrationID, &v.RemoteID, &v.ResolutionName, &v.ObservedAt, &v.State); e != nil {
				return e
			}
			out.Proposals = append(out.Proposals, v)
		}
		if e = proposals.Err(); e != nil {
			return e
		}
		comments, e := tx.Query(ctx, `SELECT id,integration_id,remote_id,author_id,body,provider_at,created_at FROM ticket_external_comments WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3 ORDER BY created_at DESC LIMIT 100`, tenant.String(), engagementID.String(), findingID.String())
		if e != nil {
			return e
		}
		defer comments.Close()
		for comments.Next() {
			var v ticketing.ExternalTicketComment
			var providerAt *time.Time
			v.TenantID, v.EngagementID, v.FindingID = tenant, engagementID, findingID
			if e = comments.Scan(&v.ID, &v.IntegrationID, &v.RemoteID, &v.AuthorID, &v.Body, &providerAt, &v.CreatedAt); e != nil {
				return e
			}
			if providerAt != nil {
				v.ProviderAt = providerAt.UTC()
			}
			out.Comments = append(out.Comments, v)
		}
		return comments.Err()
	})
	if err != nil {
		return out, fmt.Errorf("list inbound ticket view: %w", ticketWriteError(err))
	}
	return out, nil
}
