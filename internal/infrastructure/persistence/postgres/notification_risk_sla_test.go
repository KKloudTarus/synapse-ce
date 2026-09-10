package postgres

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"sync"
	"testing"
	"time"
)

func TestNotificationPostgresRiskAndSLA(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "risk-tenant")
	tenant := shared.ID("risk-tenant")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('risk-tenant','Risk')"); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { _, e := tx.Exec(ctx, query, args...); return e }); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewNotificationRepository(pool)
	source := NewNotificationSource(pool, repo, time.Minute, true)
	if _, err := source.Poll(ctx, now.Add(-time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	for _, channel := range []notification.Channel{
		{TenantID: tenant, ID: "slack", Name: "Slack", Type: notification.ChannelSlack, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now},
		{TenantID: tenant, ID: "email", Name: "Email", Type: notification.ChannelEmail, Recipients: []string{"one@example.com", "two@example.com"}, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now},
	} {
		if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []notification.Rule{
		{TenantID: tenant, ID: "high-risk", Name: "High risk", Enabled: true, EventType: notification.EventVulnerabilityAction, MinSeverity: shared.SeverityHigh, ActionTypes: []string{"new_exposure"}, ChannelIDs: []shared.ID{"slack"}, Revision: 1, CreatedAt: now, UpdatedAt: now},
		{TenantID: tenant, ID: "sla", Name: "24 hours", Enabled: true, EventType: notification.EventSLAApproaching, LeadTimeSecs: 86400, ChannelIDs: []shared.ID{"email"}, Revision: 1, CreatedAt: now, UpdatedAt: now},
	} {
		if _, err := repo.CreateRule(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO engagements(id,tenant_id,name) VALUES('eng','risk-tenant','E')`)
	exec(`INSERT INTO advisories(id,data) VALUES('CVE-test','{}')`)
	exec(`INSERT INTO sboms(id,tenant_id,engagement_id,target_ref,source) VALUES('sbom','risk-tenant','eng','test','test')`)
	exec(`INSERT INTO components(id,tenant_id,sbom_id,name,version,purl,ecosystem,package_name,identity_hash,identity_status) VALUES('component','risk-tenant','sbom','pkg','1.0','pkg:npm/pkg@1.0','npm','pkg','fingerprint','resolved')`)
	exec(`INSERT INTO vulnerability_occurrences(tenant_id,id,engagement_id,advisory_id,component_id,sbom_id,component_fingerprint,ecosystem,package_name,component_version,match_method,confidence,advisory_revision,state,match_evidence) VALUES('risk-tenant','occurrence','eng','CVE-test','component','sbom','fingerprint','npm','pkg','1.0','package_range','high',1,'detected','[{}]')`)
	exec(`INSERT INTO vulnerability_risk_assessments(tenant_id,id,engagement_id,occurrence_id,advisory_id,component_fingerprint,advisory_revision,severity,occurrence_state,risk_score,priority,model_version,input_hash,assessed_at) VALUES('risk-tenant','risk-high','eng','occurrence','CVE-test','fingerprint',1,'high','detected',8,1,'risk-v1',repeat('a',64),$1),('risk-tenant','newer-low','eng','occurrence','CVE-test','fingerprint',1,'low','detected',2,5,'risk-v1',repeat('b',64),$2)`, now, now.Add(time.Second))
	exec(`INSERT INTO findings(id,tenant_id,engagement_id,title,advisory_id,occurrence_id,component_fingerprint,risk_assessment_id) VALUES('finding','risk-tenant','eng','Finding','CVE-test','occurrence','fingerprint','newer-low')`)
	exec(`INSERT INTO vulnerability_risk_transitions(tenant_id,id,engagement_id,occurrence_id,advisory_id,transition_type,after_assessment_id,after_occurrence_state,reason_codes,created_at) VALUES('risk-tenant','transition','eng','occurrence','CVE-test','new_exposure','risk-high','detected','["first_detected"]',$1)`, now)
	exec(`INSERT INTO vulnerability_actions(tenant_id,id,engagement_id,occurrence_id,finding_id,transition_id,action_type,status,title,created_at,updated_at) VALUES('risk-tenant','action','eng','occurrence','finding','transition','new_exposure','open','New exposure',$1,$1)`, now)
	exec(`INSERT INTO vulnerability_action_outbox(tenant_id,id,action_id,idempotency_key,event_type,payload,state,available_at,created_at,updated_at) VALUES('risk-tenant','outbox','action','outbox','vulnerability_action.created','{}','pending',$1,$1,$1)`, now)
	exec(`INSERT INTO sla_policies(tenant_id,config_version,config,sha256,created_by,created_at) VALUES('risk-tenant','v1','{}',repeat('c',64),'admin',$1)`, now)
	for _, id := range []string{"sla-one", "sla-two"} {
		// Two reminders with a batch size of one prove old deduplicated rows do
		// not repeatedly consume the scheduler limit and starve later findings.
		finding := "finding-" + id
		exec(`INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,'risk-tenant','eng','SLA')`, finding)
		exec(`INSERT INTO sla_assessments(tenant_id,id,engagement_id,finding_id,inputs,result,input_hash,config_hash,config_version,tier,score,mitigate_by,remediate_by,deadline_anchor_at,assessed_at,created_at) VALUES('risk-tenant',$1,'eng',$2,'{}','{}',repeat('d',64),repeat('c',64),'v1','high',60,$3,$4,$3,$3,$3)`, id, finding, now, now.Add(12*time.Hour))
		exec(`INSERT INTO sla_current_assessments(tenant_id,engagement_id,finding_id,assessment_id,updated_at) VALUES('risk-tenant','eng',$1,$2,$3)`, finding, id, now)
		exec(`INSERT INTO sla_lifecycles(tenant_id,engagement_id,finding_id,assessment_id,status,version,updated_by,updated_at) VALUES('risk-tenant','eng',$1,$2,'open',1,'system',$3)`, finding, id, now)
	}
	source.SetVulnerabilityEnabled(false)
	if _, err := source.Poll(ctx, now, 1); err != nil {
		t.Fatal(err)
	}
	source.SetVulnerabilityEnabled(true)
	// Two concurrent schedulers use the same durable observations and event keys.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := source.Poll(ctx, now.Add(time.Minute), 1); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := source.Poll(ctx, now.Add(2*time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 5 {
		t.Fatalf("risk + two SLA per-recipient fanouts: %d %v", len(page.Items), err)
	}
	for _, delivery := range page.Items {
		w, err := repo.LoadWork(ctx, tenant, delivery.ID)
		if err != nil {
			t.Fatal(err)
		}
		if w.Event.Type == notification.EventVulnerabilityAction && w.Event.Severity != shared.SeverityHigh {
			t.Fatal("used mutable finding severity")
		}
		if w.Event.Type == notification.EventSLAApproaching {
			exec("UPDATE sla_lifecycles SET status='remediated' WHERE tenant_id='risk-tenant'")
			if relevant, err := repo.DeliveryStillRelevant(ctx, w); err != nil || relevant {
				t.Fatalf("resolved SLA remains relevant: %v %v", relevant, err)
			}
		}
	}
}
