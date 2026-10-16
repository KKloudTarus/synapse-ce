package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	approvaluc "github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresApprovalFacts struct{}

func (postgresApprovalFacts) SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (ports.NotificationLifecycleFacts, error) {
	return ports.NotificationLifecycleFacts{EngagementName: "Captured engagement", LeadUserID: "lead"}, nil
}

func (postgresApprovalFacts) SnapshotNotificationApprovers(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{"reviewer"}, nil
}

type postgresApprovalRosterFacts struct{ ids []shared.ID }

func (f postgresApprovalRosterFacts) SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (ports.NotificationLifecycleFacts, error) {
	return ports.NotificationLifecycleFacts{EngagementName: "Captured engagement", LeadUserID: "lead"}, nil
}

func (f postgresApprovalRosterFacts) SnapshotNotificationApprovers(context.Context, shared.ID) ([]shared.ID, error) {
	return append([]shared.ID(nil), f.ids...), nil
}

type failingApprovalProducerOutbox struct {
	next *NotificationOutbox
}

// competingApprovalStore makes both requests observe the initial missing row,
// then lets the intrusive proposal insert before the low-risk retry reaches its
// idempotent INSERT. It exercises the real Postgres ON CONFLICT path without
// relying on scheduler timing.
type competingApprovalStore struct {
	*ApprovalStore
	mu              sync.Mutex
	initialReads    int
	readsReady      chan struct{}
	highEnqueued    chan struct{}
	highEnqueueOnce sync.Once
}

func (s *competingApprovalStore) Get(ctx context.Context, actionID shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	p, decision, err := s.ApprovalStore.Get(ctx, actionID)
	if !errors.Is(err, shared.ErrNotFound) {
		return p, decision, err
	}
	s.mu.Lock()
	s.initialReads++
	if s.initialReads == 2 {
		close(s.readsReady)
	}
	s.mu.Unlock()
	select {
	case <-s.readsReady:
		return p, decision, err
	case <-ctx.Done():
		return agent.ProposedAction{}, agent.ApprovalDecision{}, ctx.Err()
	}
}

func (s *competingApprovalStore) Enqueue(ctx context.Context, proposal agent.ProposedAction) error {
	if proposal.Risk == agent.RiskRead {
		select {
		case <-s.highEnqueued:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	err := s.ApprovalStore.Enqueue(ctx, proposal)
	if proposal.Risk == agent.RiskIntrusive {
		s.highEnqueueOnce.Do(func() { close(s.highEnqueued) })
	}
	return err
}

func (o failingApprovalProducerOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return errors.New("approval capture unavailable")
}

func (o failingApprovalProducerOutbox) AppendApprovalSource(ctx context.Context, record notification.SourceRecord, recipients []shared.ID) error {
	if err := o.next.AppendApprovalSource(ctx, record, recipients); err != nil {
		return err
	}
	return errors.New("approval capture unavailable")
}

func TestApprovalProducerPostgresConcurrentRequestUsesCanonicalStoredProposal(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("approval-producer-race")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id)
			VALUES('reviewer','Reviewer','reviewer','approval-reviewer-key',$1)`, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES
			('approval-race-stored',$1,'Stored engagement'),('approval-race-retry',$1,'Retry engagement')`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
			VALUES($1,'framework','activation','v1',true,$2)`, tenant, at.Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	base := NewApprovalStore(pool)
	store := &competingApprovalStore{ApprovalStore: base, readsReady: make(chan struct{}), highEnqueued: make(chan struct{})}
	runner, outbox := NewTenantTransactionRunner(pool), NewNotificationOutbox(pool)
	newService := func() *approvaluc.Service {
		svc, err := approvaluc.NewService(store, NewAuditLog(pool), &notificationTestClock{at: at}, agent.ModeAuto, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.SetNotifications(runner, outbox, postgresApprovalFacts{}, postgresApprovalFacts{}); err != nil {
			t.Fatal(err)
		}
		return svc
	}
	high := agent.ProposedAction{ID: "approval-race", SessionID: "stored-session", EngagementID: "approval-race-stored", Tool: "tool", Action: "action", Target: engagement.Target{Kind: engagement.TargetDomain, Value: "stored.example.test"}, Risk: agent.RiskIntrusive, ProposedAt: at.Add(-time.Minute)}
	low := high
	low.SessionID, low.EngagementID, low.Target.Value, low.Risk, low.ProposedAt = "response:low-retry", "approval-race-retry", "retry.example.test", agent.RiskRead, at
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, item := range []struct {
		svc *approvaluc.Service
		p   agent.ProposedAction
	}{{newService(), high}, {newService(), low}} {
		go func(svc *approvaluc.Service, p agent.ProposedAction) {
			<-start
			decision, err := svc.Request(ctx, p)
			if err == nil && decision.State != agent.ApprovalPending {
				err = errors.New("stored intrusive proposal was auto-approved")
			}
			errs <- err
		}(item.svc, item.p)
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	stored, decision, err := base.Get(ctx, high.ID)
	if err != nil || stored.Risk != high.Risk || stored.SessionID != high.SessionID || stored.EngagementID != high.EngagementID || !stored.ProposedAt.Equal(high.ProposedAt) || decision.State != agent.ApprovalPending {
		t.Fatalf("stored=%+v decision=%+v err=%v", stored, decision, err)
	}
	var events int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_kind='approval_requested' AND source_id='approval-race'`, tenant).Scan(&events)
	}); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("requested source records=%d, want one", events)
	}
	var audits int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='agent.approval.requested' AND metadata->>'agent_action_id'='approval-race'`, tenant).Scan(&audits)
	}); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("raced request audits=%d, want one", audits)
	}
}

func TestApprovalProducerPostgresTransactionDedupeAndProjection(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("approval-producer-events")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, query, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO engagements(id,tenant_id,name) VALUES('approval-engagement',$1,'Approval engagement')`, tenant)
	exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id)
		VALUES('reviewer','Reviewer','reviewer','approval-reviewer-key',$1)`, tenant)
	exec(`INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'framework','activation','v1',true,$2)`, tenant, at.Add(-time.Second))
	store, outbox, runner := NewApprovalStore(pool), NewNotificationOutbox(pool), NewTenantTransactionRunner(pool)
	clock := &notificationTestClock{at: at}
	service, err := approvaluc.NewService(store, NewAuditLog(pool), clock, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetNotifications(runner, failingApprovalProducerOutbox{next: outbox}, postgresApprovalFacts{}, postgresApprovalFacts{}); err != nil {
		t.Fatal(err)
	}
	p := agent.ProposedAction{ID: "approval-rollback", SessionID: "session", EngagementID: "approval-engagement", Tool: "tool", Action: "action", Target: engagement.Target{Kind: engagement.TargetDomain, Value: "example.test"}, Risk: agent.RiskActive, ProposedAt: at}
	if _, err := service.Request(ctx, p); err == nil {
		t.Fatal("want capture failure")
	}
	if _, _, err := store.Get(ctx, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("approval escaped rollback: %v", err)
	}
	if err := service.SetNotifications(runner, outbox, postgresApprovalFacts{}, postgresApprovalFacts{}); err != nil {
		t.Fatal(err)
	}
	p.ID = "approval-durable"
	if _, err := service.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	retry := p
	retry.Target.Value = "changed-after-request.test"
	if _, err := service.Request(ctx, retry); err != nil {
		t.Fatal(err)
	}
	stored, pending, err := store.Get(ctx, p.ID)
	if err != nil || stored.Target.Value != p.Target.Value || pending.State != agent.ApprovalPending {
		t.Fatalf("stored approval=%+v decision=%+v err=%v", stored, pending, err)
	}
	if _, err := service.Decide(ctx, "reviewer", p.ID, true, "reason remains in audit only"); err != nil {
		t.Fatal(err)
	}
	var records []notification.SourceRecord
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT source_kind,source_id,event_type,engagement_id,occurred_at,data,context,capture_version FROM notification_source_records WHERE tenant_id=$1 ORDER BY source_kind`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var record notification.SourceRecord
			if err := rows.Scan(&record.SourceKind, &record.SourceID, &record.EventType, &record.EngagementID, &record.OccurredAt, &record.Data, &record.Context, &record.CaptureVersion); err != nil {
				return err
			}
			record.TenantID = tenant
			records = append(records, record)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("source records=%d, want requested plus decided", len(records))
	}
	for _, record := range records {
		if record.CaptureVersion != 3 {
			t.Fatalf("capture version=%d", record.CaptureVersion)
		}
		var data map[string]any
		if err := json.Unmarshal(record.Data, &data); err != nil {
			t.Fatal(err)
		}
		if _, ok := data["approver_count"]; !ok {
			t.Fatalf("%s has no approver count", record.EventType)
		}
		if ctx, err := notification.DecodeTemplateContext(record.Context); err != nil || ctx.Vars["event_type"] == "" || ctx.Vars["title"] == "" {
			t.Fatalf("snapshot=%+v err=%v", ctx, err)
		}
	}

	// A one-connection pool makes nested-reader connection acquisition fail
	// deterministically: projection must reuse its held tenant transaction.
	oneConfig := pool.Config()
	oneConfig.MaxConns = 1
	onePool, err := pgxpool.NewWithConfig(ctx, oneConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(onePool.Close)
	projectionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Projection occurs after the durable source write; a crash before this poll is
	// recoverable, and a repeated poll cannot create a second event.
	repository := NewNotificationRepository(onePool)
	repository.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(onePool, repository, time.Minute)
	if _, err := source.Poll(projectionCtx, at.Add(time.Second), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(projectionCtx, at.Add(2*time.Second), 100); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []notification.EventType{notification.EventApprovalRequested, notification.EventApprovalDecided} {
		events, err := repository.ListRecentNotificationEvents(projectionCtx, tenant, typ, 10)
		if err != nil || len(events) != 1 {
			t.Fatalf("%s events=%d err=%v", typ, len(events), err)
		}
		assertPublishedEventSchema(t, events[0])
		recipients, err := repository.ResolvePersonalRecipients(projectionCtx, tenant, events[0])
		if err != nil || len(recipients) != 1 {
			t.Fatalf("single-connection recipients=%d err=%v", len(recipients), err)
		}
	}
}

func TestApprovalProducerPostgresLargeImmutableRecipientSnapshots(t *testing.T) {
	for _, rosterSize := range []int{51, 1_000} {
		t.Run(fmt.Sprintf("%d-reviewers", rosterSize), func(t *testing.T) {
			pool := notificationTestPool(t)
			tenant := shared.ID(fmt.Sprintf("approval-roster-%d", rosterSize))
			ctx := shared.WithTenant(context.Background(), tenant)
			at := time.Now().UTC().Truncate(time.Microsecond)
			if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
				t.Fatal(err)
			}
			if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES('approval-large-engagement',$1,'Large approval roster')`, tenant); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
					VALUES($1,'framework','activation','v1',true,$2)`, tenant, at.Add(-time.Second)); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled)
					SELECT 'roster-user-' || lpad(series::text,4,'0'), 'Reviewer ' || series, 'reviewer',
						'roster-key-' || series, $1, false
					FROM generate_series(1,$2) AS series`, tenant, rosterSize)
				return err
			}); err != nil {
				t.Fatal(err)
			}

			ids := postgresApprovalRosterIDs(rosterSize)
			store, outbox, runner := NewApprovalStore(pool), NewNotificationOutbox(pool), NewTenantTransactionRunner(pool)
			service, err := approvaluc.NewService(store, NewAuditLog(pool), &notificationTestClock{at: at}, agent.ModeManual, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			facts := postgresApprovalRosterFacts{ids: ids}
			if err := service.SetNotifications(runner, outbox, facts, facts); err != nil {
				t.Fatal(err)
			}
			proposal := agent.ProposedAction{ID: "approval-large", SessionID: "session", EngagementID: "approval-large-engagement", Tool: "tool", Action: "action", Target: engagement.Target{Kind: engagement.TargetDomain, Value: "example.test"}, Risk: agent.RiskActive, ProposedAt: at}
			if _, err := service.Request(ctx, proposal); err != nil {
				t.Fatal(err)
			}

			reader := NewApprovalNotificationRecipients(pool)
			captured, err := reader.ApprovalNotificationRecipients(ctx, tenant, "approval_requested", proposal.ID.String())
			if err != nil || len(captured) != rosterSize {
				t.Fatalf("captured recipients=%d err=%v", len(captured), err)
			}
			var publicBytes int
			var leaked bool
			if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT octet_length(data::text), data ? 'approver_user_ids'
					FROM notification_source_records WHERE tenant_id=$1 AND source_kind='approval_requested' AND source_id=$2`, tenant, proposal.ID).Scan(&publicBytes, &leaked)
			}); err != nil {
				t.Fatal(err)
			}
			if publicBytes > 16*1024 || leaked {
				t.Fatalf("public approval snapshot bytes=%d leaked_roster=%v", publicBytes, leaked)
			}

			// A replay observes changed membership but cannot modify the first
			// committed source roster. It also exercises the source/outbox transaction.
			if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled)
					VALUES('roster-user-new','New reviewer','reviewer','roster-key-new',$1,false)`, tenant)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			replay := notification.SourceRecord{TenantID: tenant, SourceKind: "approval_requested", SourceID: proposal.ID.String(), EventType: notification.EventApprovalRequested, EngagementID: proposal.EngagementID, OccurredAt: at, Data: json.RawMessage(`{"approval_id":"approval-large"}`), SubjectKind: "approval", SubjectID: proposal.ID.String()}
			if err := runner.Run(ctx, tenant, func(tx context.Context) error {
				return outbox.AppendApprovalSource(tx, replay, append(postgresApprovalRosterIDs(51), shared.ID("roster-user-new")))
			}); err != nil {
				t.Fatal(err)
			}
			captured, err = reader.ApprovalNotificationRecipients(ctx, tenant, "approval_requested", proposal.ID.String())
			if err != nil || len(captured) != rosterSize {
				t.Fatalf("replayed recipients=%d err=%v", len(captured), err)
			}

			// An inserted source and roster share the transaction boundary: neither
			// survives a later business-write failure.
			rollback := replay
			rollback.SourceID = "approval-large-rollback"
			rollback.Data = json.RawMessage(`{"approval_id":"approval-large-rollback","engagement_id":"approval-large-engagement","kind":"agent","status":"pending","title":"Approval requested","summary":"A governed approval needs review.","approver_count":51}`)
			rollbackErr := errors.New("force approval snapshot rollback")
			if err := runner.Run(ctx, tenant, func(tx context.Context) error {
				if err := outbox.AppendApprovalSource(tx, rollback, postgresApprovalRosterIDs(51)); err != nil {
					return err
				}
				return rollbackErr
			}); !errors.Is(err, rollbackErr) {
				t.Fatalf("rollback error=%v, want sentinel", err)
			}
			rolledBack, err := reader.ApprovalNotificationRecipients(ctx, tenant, rollback.SourceKind, rollback.SourceID)
			if err != nil || len(rolledBack) != 0 {
				t.Fatalf("rollback recipients=%d err=%v", len(rolledBack), err)
			}

			// The private roster stays immutable, while projection rechecks the
			// recipient's current review role and omits a later-demoted reviewer.
			if rosterSize == 1_000 {
				if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE users SET role='member' WHERE ownership_tenant_id=$1 AND id='roster-user-1000'`, tenant)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				repository := NewNotificationRepository(pool)
				repository.SetEventProjector(notificationuc.NewEventBuilders())
				source := NewNotificationSource(pool, repository, time.Minute)
				if _, err := source.Poll(ctx, at.Add(time.Second), 200); err != nil {
					t.Fatal(err)
				}
				if _, err := source.Poll(ctx, at.Add(2*time.Second), 200); err != nil {
					t.Fatal(err)
				}
				var notices int
				if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, `SELECT count(*) FROM user_notifications
						WHERE tenant_id=$1 AND event_type='approval.requested'`, tenant).Scan(&notices)
				}); err != nil {
					t.Fatal(err)
				}
				if notices != rosterSize-1 {
					t.Fatalf("projected notices=%d, want %d after review-role revocation", notices, rosterSize-1)
				}
				events, err := repository.ListRecentNotificationEvents(ctx, tenant, notification.EventApprovalRequested, 2)
				if err != nil || len(events) != 1 {
					t.Fatalf("projected approval events=%d err=%v", len(events), err)
				}
				assertPublishedEventSchema(t, events[0])
			}
		})
	}
}

func postgresApprovalRosterIDs(size int) []shared.ID {
	ids := make([]shared.ID, size)
	for index := range ids {
		ids[index] = shared.ID(fmt.Sprintf("roster-user-%04d", index+1))
	}
	return ids
}

func TestCommentMentionsPostgresAreAtomicAndTenantScoped(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("comment-producer-events")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),('comment-producer-other','Other')`, []any{tenant}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES('comment-engagement',$1,'Comments')`, []any{tenant}},
		{`INSERT INTO findings(id,tenant_id,engagement_id,title,severity,status,dedup_key,created_at,updated_at) VALUES('comment-finding',$1,'comment-engagement','Comment finding','high','open','comment-dedupe',$2,$2)`, []any{tenant, at}},
		{`INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('comment-user','Comment user','reviewer','comment-key',$1,false)`, []any{tenant}},
	} {
		if statement.query == `INSERT INTO tenants(id,name) VALUES($1,$1),('comment-producer-other','Other')` {
			if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement.query, statement.args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	repository := NewCommentRepository(pool)
	comment := finding.Comment{ID: "comment-id", EngagementID: "comment-engagement", FindingID: "comment-finding", Author: "author", Body: "hello", CreatedAt: at}
	if err := NewTenantTransactionRunner(pool).Run(ctx, tenant, func(tx context.Context) error {
		return repository.AddWithMentions(tx, comment, []shared.ID{"comment-user"})
	}); err != nil {
		t.Fatal(err)
	}
	comments, err := repository.ListByEngagementFinding(ctx, comment.EngagementID, comment.FindingID)
	if err != nil || len(comments) != 1 || len(comments[0].MentionUserIDs) != 1 || comments[0].MentionUserIDs[0] != "comment-user" {
		t.Fatalf("comments=%+v err=%v", comments, err)
	}
	if foreign, err := repository.ListByEngagementFinding(shared.WithTenant(ctx, "comment-producer-other"), comment.EngagementID, comment.FindingID); err != nil || len(foreign) != 0 {
		t.Fatalf("foreign comments=%+v err=%v", foreign, err)
	}
	rollback := finding.Comment{ID: "rollback-comment", EngagementID: comment.EngagementID, FindingID: comment.FindingID, Author: "author", Body: "rollback", CreatedAt: at}
	err = NewTenantTransactionRunner(pool).Run(ctx, tenant, func(tx context.Context) error {
		if err := repository.AddWithMentions(tx, rollback, []shared.ID{"comment-user"}); err != nil {
			return err
		}
		return errors.New("force rollback")
	})
	if err == nil {
		t.Fatal("want rollback")
	}
	comments, err = repository.ListByEngagementFinding(ctx, comment.EngagementID, comment.FindingID)
	if err != nil || len(comments) != 1 {
		t.Fatalf("comment transaction escaped rollback: %+v %v", comments, err)
	}
}
