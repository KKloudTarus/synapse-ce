package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func ownershipNotificationService(t *testing.T, f *ownershipFixture) (*notificationuc.Service, *notificationTestSender, *notificationTestClock) {
	t.Helper()
	cipher, err := vault.NewCipher([]byte(strings.Repeat("n", 32)))
	if err != nil {
		t.Fatal(err)
	}
	sender := &notificationTestSender{result: ports.NotificationSendResult{StatusCode: 204}}
	clock := &notificationTestClock{f.at}
	svc, err := notificationuc.NewService(NewNotificationRepository(f.pool), cipher, sender, NewAuditLog(f.pool), clock, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(NewTenantTransactionRunner(f.pool))
	return svc, sender, clock
}

func ownershipNotificationChannel(t *testing.T, f *ownershipFixture, svc *notificationuc.Service, name string) shared.ID {
	t.Helper()
	c, err := svc.CreateChannel(f.ctx, "alice", notificationuc.ChannelInput{Name: name, Type: notification.ChannelWebhook,
		Enabled: true, URL: "https://example.com/ownership", Secret: "ownership-signing-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func TestOwnershipNotificationFanoutRecoveryAndSuppression(t *testing.T) {
	f := newOwnershipFixture(t)
	svc, sender, clock := ownershipNotificationService(t, f)
	pay := ownershipNotificationChannel(t, f, svc, "Payments")
	ops := ownershipNotificationChannel(t, f, svc, "Operations")
	common := ownershipNotificationChannel(t, f, svc, "Shared")
	global := ownershipNotificationChannel(t, f, svc, "All teams")
	for _, rule := range []notificationuc.RuleInput{
		{Name: "Pay", TeamIDs: []shared.ID{"pay"}, ChannelIDs: []shared.ID{pay, common}},
		{Name: "Pay duplicate", TeamIDs: []shared.ID{"pay"}, ChannelIDs: []shared.ID{pay}},
		{Name: "Ops", TeamIDs: []shared.ID{"ops"}, ChannelIDs: []shared.ID{ops, common}},
		{Name: "All", AllTeams: true, ChannelIDs: []shared.ID{global}},
	} {
		rule.Enabled, rule.EventType = true, notification.EventOwnershipChanged
		if _, err := svc.CreateRule(f.ctx, "alice", rule); err != nil {
			t.Fatal(err)
		}
	}
	// Capture while delivery is disabled; enabling the worker later never replays it.
	first := f.mutation(t, "assign")
	first.TeamID, first.Notify, first.LegacyAssignee = "pay", false, "sensitive legacy free text"
	if _, err := f.repo.ApplyAssignment(f.ctx, first); err != nil {
		t.Fatal(err)
	}
	move := f.mutation(t, "assign")
	move.Key, move.DecisionID = "move", "decision-move"
	move.TeamID, move.AssigneeID, move.LegacyAssignee = "ops", "bob", "bob"
	if _, err := f.repo.ApplyAssignment(f.ctx, move); err != nil {
		t.Fatal(err)
	}
	// Crash after commit, before dispatch. A new source has no activation watermark
	// yet, but the eligible intent must still be recovered.
	newSource := func() *NotificationSource {
		return NewNotificationSource(f.pool, NewNotificationRepository(f.pool), time.Minute, false)
	}
	n, err := newSource().Poll(f.ctx, f.at.Add(time.Minute), 1)
	if err != nil || n != 1 {
		t.Fatalf("first poll=%d %v", n, err)
	}
	page, err := svc.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{EventType: notification.EventOwnershipChanged})
	if err != nil || len(page.Items) != 4 {
		t.Fatalf("fanout=%+v %v", page, err)
	}
	for _, delivery := range page.Items {
		work, err := NewNotificationRepository(f.pool).LoadWork(f.ctx, "own-a", delivery.ID)
		if err != nil {
			t.Fatal(err)
		}
		var data notification.OwnershipChanged
		if err := json.Unmarshal(work.Event.Data, &data); err != nil {
			t.Fatal(err)
		}
		if data.OldTeamID != "pay" || data.NewTeamID != "ops" || data.NewAssigneeID != "bob" || data.Actor != "alice" || data.DecisionID != move.DecisionID || data.Reason != "manual_assign" {
			t.Fatalf("wrong immutable transition: %+v", data)
		}
		if strings.Contains(string(work.Event.Data), "sensitive") || strings.Contains(string(work.Event.Data), "@org/pay") {
			t.Fatal("private evidence leaked into transport payload")
		}
		if (delivery.ChannelID == common || delivery.ChannelID == pay) && len(delivery.MatchedRuleIDs) != 2 {
			t.Fatalf("overlapping rules did not deduplicate channel: %+v", delivery)
		}
	}
	if _, err := f.repo.ApplyAssignment(f.ctx, move); err != nil {
		t.Fatal(err)
	}
	if n, err := newSource().Poll(f.ctx, f.at.Add(2*time.Minute), 200); err != nil || n != 0 {
		t.Fatalf("replay=%d %v", n, err)
	}
	// Exercise the production delivery use case and real durable queue; transport
	// is fake so this test sends nothing outside the test process.
	for i := 0; i < 4; i++ {
		clock.at = clock.at.Add(time.Second) // honor tenant delivery pacing without sleeping
		job, err := f.queue.Claim(f.ctx, time.Minute, notificationuc.JobKind)
		if err != nil || job == nil {
			t.Fatalf("claim=%v %v", job, err)
		}
		if err := svc.HandleJob(f.ctx, *job); err != nil {
			t.Fatal(err)
		}
		if err := svc.HandleJob(f.ctx, *job); err != nil {
			t.Fatal(err)
		} // crash before Complete
		if err := f.queue.Complete(f.ctx, job.ID, job.Fence); err != nil {
			t.Fatal(err)
		}
	}
	if sender.calls != 4 {
		t.Fatalf("transport calls=%d", sender.calls)
	}
	var suppressed int
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT count(*) FROM ownership_intents WHERE kind='notification' AND state='suppressed'`).Scan(&suppressed)
	}); err != nil || suppressed != 1 {
		t.Fatalf("suppression=%d %v", suppressed, err)
	}
	other, err := svc.ListDeliveries(shared.WithTenant(f.ctx, "own-b"), ports.NotificationDeliveryFilter{})
	if err != nil || len(other.Items) != 0 {
		t.Fatalf("tenant leak=%+v %v", other, err)
	}
}

func TestOwnershipNotificationRollbackAndConcurrentPoll(t *testing.T) {
	f := newOwnershipFixture(t)
	svc, _, _ := ownershipNotificationService(t, f)
	c := ownershipNotificationChannel(t, f, svc, "Recovery")
	if _, err := svc.CreateRule(f.ctx, "alice", notificationuc.RuleInput{Name: "All", Enabled: true, EventType: notification.EventOwnershipChanged, AllTeams: true, ChannelIDs: []shared.ID{c}}); err != nil {
		t.Fatal(err)
	}
	m := f.mutation(t, "assign")
	m.TeamID = "pay"
	if _, err := f.repo.ApplyAssignment(f.ctx, m); err != nil {
		t.Fatal(err)
	}
	// Fail the last write, after Publish has inserted its event, delivery and job.
	if _, err := f.ddl.Exec(`CREATE FUNCTION fail_ownership_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected ownership dispatch failure'; END $$;
		CREATE TRIGGER fail_ownership_dispatch BEFORE UPDATE ON ownership_intents FOR EACH ROW WHEN (NEW.state='processed') EXECUTE FUNCTION fail_ownership_dispatch()`); err != nil {
		t.Fatal(err)
	}
	source := NewNotificationSource(f.pool, NewNotificationRepository(f.pool), time.Minute, false)
	if n, err := source.Poll(f.ctx, f.at, 200); err == nil || n != 0 {
		t.Fatalf("fault=%d %v", n, err)
	}
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		for _, table := range []string{"notification_events", "notification_deliveries", "jobs"} {
			var count int
			if err := tx.QueryRow(f.ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Errorf("rollback left %d %s", count, table)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if intents, err := f.repo.ListPendingIntents(f.ctx, "notification", 200); err != nil || len(intents) != 1 {
		t.Fatalf("lost intent=%v %v", intents, err)
	}
	if _, err := f.ddl.Exec(`DROP TRIGGER fail_ownership_dispatch ON ownership_intents; DROP FUNCTION fail_ownership_dispatch()`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := source.Poll(f.ctx, f.at, 200); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	page, err := svc.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("recovery fanout=%+v %v", page, err)
	}
	if intents, err := f.repo.ListPendingIntents(f.ctx, "notification", 200); err != nil || len(intents) != 0 {
		t.Fatalf("pending=%v %v", intents, err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if _, err := source.Poll(ctx, f.at, 200); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
}

func TestOwnershipNotificationTeamBindingsAndCAS(t *testing.T) {
	f := newOwnershipFixture(t)
	svc, _, _ := ownershipNotificationService(t, f)
	c := ownershipNotificationChannel(t, f, svc, "Scoped")
	otherCtx := shared.WithTenant(f.ctx, "own-b")
	if _, err := f.repo.CreateTeam(otherCtx, ownership.Team{TenantID: "own-b", ID: "foreign-team", Slug: "foreign", Name: "Other", Revision: 1, CreatedAt: f.at, UpdatedAt: f.at}); err != nil {
		t.Fatal(err)
	}
	in := notificationuc.RuleInput{Name: "Scoped", Enabled: true, EventType: notification.EventOwnershipChanged, TeamIDs: []shared.ID{"pay"}, ChannelIDs: []shared.ID{c}}
	rule, err := svc.CreateRule(f.ctx, "alice", in)
	if err != nil {
		t.Fatal(err)
	}
	in.Revision, in.TeamIDs = rule.Revision, []shared.ID{"foreign-team"}
	if _, err := svc.UpdateRule(f.ctx, "alice", rule.ID, in); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign update=%v", err)
	}
	if _, err := svc.CreateRule(f.ctx, "alice", in); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign create=%v", err)
	}
	in.TeamIDs = []shared.ID{"ops"}
	updated, err := svc.UpdateRule(f.ctx, "alice", rule.ID, in)
	if err != nil || updated.Revision != 2 {
		t.Fatalf("update=%+v %v", updated, err)
	}
	if _, err := svc.UpdateRule(f.ctx, "alice", rule.ID, in); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update=%v", err)
	}
	stored, err := svc.GetRule(f.ctx, rule.ID)
	if err != nil || len(stored.TeamIDs) != 1 || stored.TeamIDs[0] != "ops" || stored.AllTeams {
		t.Fatalf("persisted scope=%+v %v", stored, err)
	}
	// Database constraints and RLS must protect bindings even below the API.
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_rule_teams(tenant_id,rule_id,team_id) VALUES('own-a',$1,'foreign-team')`, rule.ID)
		return err
	}); err == nil {
		t.Fatal("cross-tenant team FK accepted")
	}
	if err := WithTenant(otherCtx, f.pool, "own-b", func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(otherCtx, `SELECT count(*) FROM notification_rule_teams`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("RLS leaked rule-team bindings")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	in.TeamIDs, in.AllTeams, in.Revision = nil, true, 2
	if _, err := svc.UpdateRule(f.ctx, "alice", rule.ID, in); err != nil {
		t.Fatal(err)
	}
	stored, err = svc.GetRule(f.ctx, rule.ID)
	if err != nil || !stored.AllTeams || len(stored.TeamIDs) != 0 {
		t.Fatalf("all teams=%+v %v", stored, err)
	}
}
