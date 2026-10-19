package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
)

func TestTicketInboundReducerPostgresSerializesFindingProposalWindow(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate ticket schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	stamp := time.Now().UTC().UnixNano()
	tenant := shared.ID(fmt.Sprintf("ticket-inbound-race-%d", stamp))
	project := shared.ID(tenant.String() + "-project")
	engagement := shared.ID(tenant.String() + "-engagement")
	finding := shared.ID(tenant.String() + "-finding")
	integrationA := shared.ID(tenant.String() + "-integration-a")
	integrationB := shared.ID(tenant.String() + "-integration-b")
	mappingA := shared.ID(tenant.String() + "-mapping-a")
	mappingB := shared.ID(tenant.String() + "-mapping-b")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_ = WithTenant(context.Background(), pool, tenant.String(), func(tx pgx.Tx) error {
			for _, table := range []string{
				"ticket_external_comments", "ticket_retest_proposals", "ticket_external_observations",
				"ticket_inbound_poll_progress", "ticket_inbound_config", "ticket_status_sync",
				"ticket_auto_push_receipts", "ticket_dispatch_breakers", "ticket_intents", "ticket_links",
				"ticket_group_members", "ticket_groups", "ticket_mappings",
			} {
				_, _ = tx.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
			}
			_, _ = tx.Exec(context.Background(), `DELETE FROM findings WHERE tenant_id=$1`, tenant)
			_, _ = tx.Exec(context.Background(), `DELETE FROM integrations WHERE tenant_id=$1`, tenant)
			_, _ = tx.Exec(context.Background(), `DELETE FROM engagements WHERE tenant_id=$1`, tenant)
			_, _ = tx.Exec(context.Background(), `DELETE FROM projects WHERE tenant_id=$1`, tenant)
			return nil
		})
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES($1,$2,'Inbound reducer project',$1,'{}'::jsonb)`, project.String(), tenant.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name,project_id) VALUES($1,$2,'Inbound reducer engagement',$3)`, engagement.String(), tenant.String(), project.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,$2,$3,'Inbound reducer finding')`, finding.String(), tenant.String(), engagement.String()); err != nil {
			return err
		}
		for _, integration := range []shared.ID{integrationA, integrationB} {
			if _, err := tx.Exec(ctx, `INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,created_at,updated_at) VALUES($1,$2,'jira-cloud',$1,'https://' || $1 || '.example',now(),now())`, integration.String(), tenant.String()); err != nil {
				return err
			}
		}
		for i, pair := range [][2]shared.ID{{mappingA, integrationA}, {mappingB, integrationB}} {
			if _, err := tx.Exec(ctx, `INSERT INTO ticket_mappings(id,tenant_id,integration_id,engagement_id,project_key,issue_type,version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'10001',1,now(),now())`, pair[0].String(), tenant.String(), pair[1].String(), engagement.String(), fmt.Sprintf("SEC%d", i+1)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed inbound reducer fixture: %v", err)
	}

	store, err := NewTicketStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.October, 17, 10, 59, 0, 0, time.UTC)
	observation := func(integration, mapping shared.ID, remote, category string, at time.Time) ticketing.ExternalTicketObservation {
		return ticketing.ExternalTicketObservation{
			TenantID: tenant, IntegrationID: integration, MappingID: mapping,
			EngagementID: engagement, FindingID: finding, RemoteID: remote,
			StatusCategory: category, ProviderUpdatedAt: at, StatusChangedAt: at,
			AuthorID: "human-status-author", StatusAuthorKnown: true,
			CheckedAt: at, Version: 1,
		}
	}
	first := []ticketing.ExternalTicketObservation{
		observation(integrationA, mappingA, "SEC-1", "done", base),
		observation(integrationB, mappingB, "SEC-2", "done", base),
	}
	start := make(chan struct{})
	errs := make(chan error, len(first))
	var wait sync.WaitGroup
	for _, item := range first {
		wait.Add(1)
		go func(item ticketing.ExternalTicketObservation) {
			defer wait.Done()
			<-start
			errs <- store.ReduceInboundTicket(context.Background(), tenant, []ticketing.ExternalTicketObservation{item}, nil, base)
		}(item)
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent inbound reduction: %v", err)
		}
	}
	view, err := store.ListInboundTicketView(ctx, tenant, engagement, finding)
	if err != nil {
		t.Fatalf("list initial inbound view: %v", err)
	}
	if len(view.Proposals) != 1 {
		t.Fatalf("concurrent mappings must create one rolling proposal, got %d", len(view.Proposals))
	}

	// A second done episode at 11:00 after a proposal at 10:59 remains inside
	// the rolling hour. It must be recorded but must not create another proposal.
	if err := store.ReduceInboundTicket(ctx, tenant, []ticketing.ExternalTicketObservation{
		observation(integrationA, mappingA, "SEC-1", "new", base.Add(30*time.Second)),
		observation(integrationA, mappingA, "SEC-1", "done", base.Add(time.Minute)),
	}, nil, base.Add(time.Minute)); err != nil {
		t.Fatalf("reduce inside rolling hour: %v", err)
	}
	view, err = store.ListInboundTicketView(ctx, tenant, engagement, finding)
	if err != nil {
		t.Fatalf("list rolling-hour inbound view: %v", err)
	}
	if len(view.Proposals) != 1 {
		t.Fatalf("proposal created inside rolling hour: %d", len(view.Proposals))
	}

	// At the one-hour boundary the previous proposal is no longer in the
	// (now-1h, now] interval, so a distinct later done episode may propose.
	if err := store.ReduceInboundTicket(ctx, tenant, []ticketing.ExternalTicketObservation{
		observation(integrationA, mappingA, "SEC-1", "new", base.Add(59*time.Minute)),
		observation(integrationA, mappingA, "SEC-1", "done", base.Add(time.Hour)),
	}, nil, base.Add(time.Hour)); err != nil {
		t.Fatalf("reduce at rolling boundary: %v", err)
	}
	view, err = store.ListInboundTicketView(ctx, tenant, engagement, finding)
	if err != nil {
		t.Fatalf("list boundary inbound view: %v", err)
	}
	if len(view.Proposals) != 2 {
		t.Fatalf("expected a second proposal at rolling boundary, got %d", len(view.Proposals))
	}

	// A bad item later in a reducer batch must roll back an earlier valid item.
	atomic := observation(integrationA, mappingA, "SEC-atomic", "done", base.Add(2*time.Hour))
	forged := atomic
	forged.MappingID = "unknown-mapping"
	if err := store.ReduceInboundTicket(ctx, tenant, []ticketing.ExternalTicketObservation{atomic, forged}, nil, base.Add(2*time.Hour)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("invalid mixed batch error=%v, want forbidden", err)
	}
	view, err = store.ListInboundTicketView(ctx, tenant, engagement, finding)
	if err != nil {
		t.Fatalf("list after atomic rejection: %v", err)
	}
	for _, item := range view.Observations {
		if item.RemoteID == "SEC-atomic" {
			t.Fatal("invalid batch committed an earlier observation")
		}
	}

	comment := ticketing.ExternalTicketComment{
		ID: "inbound-comment-pg-snapshot", TenantID: tenant, IntegrationID: integrationA,
		EngagementID: engagement, FindingID: finding, RemoteID: "SEC-1", AuthorID: "human-comment-author",
		Body: "same provider comment snapshot", ProviderAt: base, CreatedAt: base,
	}
	start = make(chan struct{})
	errs = make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- store.ReduceInboundTicket(context.Background(), tenant, nil, []ticketing.ExternalTicketComment{comment}, base)
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent duplicate comment snapshot: %v", err)
		}
	}
	view, err = store.ListInboundTicketView(ctx, tenant, engagement, finding)
	if err != nil {
		t.Fatalf("list duplicate comment snapshot: %v", err)
	}
	if len(view.Comments) != 1 || view.Comments[0].ID != comment.ID {
		t.Fatalf("duplicate comment snapshot was not idempotent: %+v", view.Comments)
	}
}
