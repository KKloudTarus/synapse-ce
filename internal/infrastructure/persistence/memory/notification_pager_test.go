package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func pagerFinding(id string, episode, revision int64, terminal bool) notification.Event {
	typ := notification.EventFindingCreated
	if terminal {
		typ = notification.EventFindingStatusChanged
	}
	e := testEvent(id, typ)
	e.SubjectKind, e.SubjectID = "finding", "same-finding"
	e.PagerLifecycle = notification.PagerLifecycle{Episode: episode, Revision: revision, Terminal: terminal}
	return e
}

func TestPagerLateReceiptClosesOnlyItsEpisode(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	now := notificationTestNow
	jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return now })
	repo := NewNotificationRepository(jobs, func() time.Time { return now })
	mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
	mustCreateRule(t, repo, testRule("created-only", notification.EventFindingCreated, "pager"))
	ids, err := repo.Publish(ctx, pagerFinding("trigger-1", 1, 1, false))
	if err != nil || len(ids) != 1 {
		t.Fatalf("trigger %v %v", ids, err)
	}
	job, err := jobs.Claim(ctx, time.Second, notificationDeliverJobKey)
	if err != nil || job == nil {
		t.Fatalf("claim %v %v", job, err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], job.ID, job.Fence, "operation-1", now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	first, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], job.ID, job.Fence, "operation-1")
	if err != nil || first.Action != "send" {
		t.Fatalf("first %+v %v", first, err)
	}
	if got, err := repo.Publish(ctx, pagerFinding("terminal-1", 1, 2, true)); err != nil || len(got) != 0 {
		t.Fatalf("terminal %v %v", got, err)
	}
	if got, err := repo.Publish(ctx, pagerFinding("late-active", 1, 1, false)); err != nil || len(got) != 0 {
		t.Fatalf("late active %v %v", got, err)
	}
	nextIDs, err := repo.Publish(ctx, pagerFinding("trigger-2", 2, 3, false))
	if err != nil || len(nextIDs) != 1 {
		t.Fatalf("second episode %v %v", nextIDs, err)
	}
	now = now.Add(2 * time.Second)
	reclaimed, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || reclaimed == nil {
		t.Fatalf("reclaim %v %v", reclaimed, err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], reclaimed.ID, reclaimed.Fence, "operation-2", now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	blocked, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], reclaimed.ID, reclaimed.Fence, "operation-2")
	if err != nil || blocked.Action != "blocked" {
		t.Fatalf("reclaim must not resend: %+v %v", blocked, err)
	}
	// Receipt has the original operation identity, independent of the expired claim.
	if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "operation-1", ports.NotificationSendResult{StatusCode: 202, ProviderRequestRef: "request-1"}); err != nil {
		t.Fatal(err)
	}
	poll, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], reclaimed.ID, reclaimed.Fence, "operation-2")
	if err != nil || poll.Action != "poll" || poll.ProviderRequestRef != "request-1" || poll.OperationID != "operation-1" {
		t.Fatalf("poll %+v %v", poll, err)
	}
	if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "operation-1", ports.NotificationSendResult{StatusCode: 200, RemoteRef: "alias-1"}); err != nil {
		t.Fatal(err)
	}
	terminalID := notificationStableID(notificationTestTenant.String(), "event-terminal-1", "pager", "")
	closeWork, err := repo.LoadWork(ctx, notificationTestTenant, terminalID)
	if err != nil || closeWork.Event.PagerLifecycle.Episode != 1 || !closeWork.Event.PagerLifecycle.Terminal {
		t.Fatalf("close work %+v %v", closeWork.Event.PagerLifecycle, err)
	}
	if err := jobs.Complete(ctx, reclaimed.ID, reclaimed.Fence); err != nil {
		t.Fatal(err)
	}
	var sawClose, sawNext bool
	for i := 0; i < 2; i++ {
		next, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
		if err != nil || next == nil {
			t.Fatalf("claim queued %v %v", next, err)
		}
		now = now.Add(2 * time.Second)
		for _, id := range []shared.ID{terminalID, nextIDs[0]} {
			attempt := shared.ID("op-" + id.String())
			_, err := repo.BeginAttempt(ctx, notificationTestTenant, id, next.ID, next.Fence, attempt, now, ports.AttemptAdmission{})
			if err == ports.ErrStaleLease {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, id, next.ID, next.Fence, attempt)
			if err == ports.ErrStaleLease {
				continue
			}
			if err != nil || result.Action != "send" {
				t.Fatalf("admission %+v %v", result, err)
			}
			if id == terminalID {
				sawClose = true
				if result.SubjectAnchor != "alias-1" {
					t.Fatalf("close anchor %q", result.SubjectAnchor)
				}
			} else {
				sawNext = true
				if result.SubjectAnchor != "" {
					t.Fatal("new episode reused old anchor")
				}
			}
		}
		if err := jobs.Complete(ctx, next.ID, next.Fence); err != nil {
			t.Fatal(err)
		}
	}
	if !sawClose || !sawNext {
		t.Fatalf("close=%v next=%v", sawClose, sawNext)
	}
}

func TestPagerUnknownCannotRetryAndTerminalBeforeTriggerSuppresses(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	repo := newTestNotificationRepository()
	mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
	mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
	if _, err := repo.Publish(ctx, pagerFinding("terminal-first", 1, 3, true)); err != nil {
		t.Fatal(err)
	}
	if ids, err := repo.Publish(ctx, pagerFinding("late", 1, 1, false)); err != nil || len(ids) != 0 {
		t.Fatalf("late %v %v", ids, err)
	}
	ids, err := repo.Publish(ctx, pagerFinding("unknown", 2, 4, false))
	if err != nil || len(ids) != 1 {
		t.Fatalf("trigger %v %v", ids, err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], "", 0, "operation", notificationTestNow, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	admitted, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], "", 0, "operation")
	if err != nil || admitted.Action != "send" {
		t.Fatalf("admit %+v %v", admitted, err)
	}
	if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "operation", ports.NotificationSendResult{ErrorCode: "network_error", Retryable: true}); err != nil {
		t.Fatal(err)
	}
	blocked, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], "", 0, "operation")
	if err != nil || blocked.Action != "blocked" || blocked.Code != "pager_unknown" {
		t.Fatalf("unknown %+v %v", blocked, err)
	}
}

func TestPagerConfirmationRetainsHandleAcrossRotation(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	repo := newTestNotificationRepository()
	channel := mustCreateChannel(t, repo, testChannel("pager-rotation", notification.ChannelJSM))
	mustCreateRule(t, repo, testRule("pager-rule", notification.EventFindingCreated, "pager-rotation"))
	ids, err := repo.Publish(ctx, pagerFinding("rotate", 1, 1, false))
	if err != nil || len(ids) != 1 {
		t.Fatalf("publish %v %v", ids, err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], "", 0, "op", notificationTestNow, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], "", 0, "op"); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "op", ports.NotificationSendResult{StatusCode: 202, ProviderRequestRef: "request"}); err != nil {
		t.Fatal(err)
	}
	channel.Revision++
	if _, err := repo.UpdateChannel(ctx, channel, "replacement", true); err != nil {
		t.Fatal(err)
	}
	got, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], "", 0, "op")
	if err != nil || got.Action != "blocked" || got.ProviderRequestRef != "request" {
		t.Fatalf("rotated %+v %v", got, err)
	}
}

func TestPagerConfirmationWakesAfterDeadLetterRace(t *testing.T) {
	for _, receiptBeforeFailure := range []bool{true, false} {
		t.Run(fmt.Sprint(receiptBeforeFailure), func(t *testing.T) {
			ctx := shared.WithTenant(context.Background(), notificationTestTenant)
			now := notificationTestNow
			jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return now })
			repo := NewNotificationRepository(jobs, func() time.Time { return now })
			mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
			mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
			ids, err := repo.Publish(ctx, pagerFinding("race", 1, 1, false))
			if err != nil || len(ids) != 1 {
				t.Fatalf("publish %v %v", ids, err)
			}
			first, _ := jobs.Claim(ctx, time.Second, notificationDeliverJobKey)
			if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], first.ID, first.Fence, "first-op", now, ports.AttemptAdmission{}); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], first.ID, first.Fence, "first-op"); err != nil {
				t.Fatal(err)
			}
			now = now.Add(2 * time.Second)
			second, _ := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
			if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], second.ID, second.Fence, "second-op", now, ports.AttemptAdmission{}); err != nil {
				t.Fatal(err)
			}
			blocked, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], second.ID, second.Fence, "second-op")
			if err != nil || blocked.Code != "pager_sending" {
				t.Fatalf("blocked %+v %v", blocked, err)
			}
			receipt := func() {
				t.Helper()
				if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "first-op", ports.NotificationSendResult{StatusCode: 202, ProviderRequestRef: "request"}); err != nil {
					t.Fatal(err)
				}
			}
			if receiptBeforeFailure {
				receipt()
			}
			if err := repo.FinishAttempt(ctx, notificationTestTenant, ids[0], second.ID, second.Fence, "second-op", now, "failed", 0, "pager_sending", nil); err != nil {
				t.Fatal(err)
			}
			if err := jobs.Deadletter(ctx, second.ID, second.Fence); err != nil {
				t.Fatal(err)
			}
			if !receiptBeforeFailure {
				receipt()
			}
			if _, err := repo.DeadLetterDelivery(ctx, notificationTestTenant, ids[0], second.Fence, "worker_dead_letter"); err != nil {
				t.Fatal(err)
			}
			next, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
			if err != nil || next == nil {
				t.Fatalf("confirmation was stranded: %v %v", next, err)
			}
			now = now.Add(2 * time.Second)
			if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], next.ID, next.Fence, "third-op", now, ports.AttemptAdmission{}); err != nil {
				t.Fatal(err)
			}
			decision, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], next.ID, next.Fence, "third-op")
			if err != nil || decision.Action != "poll" || decision.OperationID != "first-op" || decision.ProviderRequestRef != "request" {
				t.Fatalf("decision %+v %v", decision, err)
			}
		})
	}
}

func TestPagerRolledBackOutboxDoesNotCreateTombstone(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	outbox := NewNotificationOutbox()
	source := NewNotificationSource(repo, outbox)
	transactions := NewTenantTransactionRunner()
	outbox.Activate(notificationTestTenant, notificationTestNow)
	rollback := errors.New("rollback")
	terminal := notification.SourceRecord{TenantID: notificationTestTenant, SourceKind: "finding_status", SourceID: "rolled-back", EventType: notification.EventFindingStatusChanged, SubjectKind: "finding", SubjectID: "same-finding", PagerLifecycle: notification.PagerLifecycle{Episode: 1, Revision: 2, Terminal: true}, OccurredAt: notificationTestNow, Data: json.RawMessage(`{"title":"terminal"}`)}
	if err := transactions.Run(ctx, notificationTestTenant, func(ctx context.Context) error {
		if err := outbox.Append(ctx, terminal); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback %v", err)
	}
	if n, err := source.Poll(ctx, notificationTestNow.Add(time.Second), 10); err != nil || n != 0 {
		t.Fatalf("poll %d %v", n, err)
	}
	mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
	mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
	if ids, err := repo.Publish(ctx, pagerFinding("after-rollback", 1, 1, false)); err != nil || len(ids) != 1 {
		t.Fatalf("trigger %v %v", ids, err)
	}
}

func TestPagerRejectsMissingOrDifferentStartedAttempt(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	repo := newTestNotificationRepository()
	mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
	mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
	ids, err := repo.Publish(ctx, pagerFinding("attempt", 1, 1, false))
	if err != nil || len(ids) != 1 {
		t.Fatalf("publish %v %v", ids, err)
	}
	if _, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], "", 0, "absent"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("missing attempt: %v", err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], "", 0, "started", notificationTestNow, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], "", 0, "other"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("other attempt: %v", err)
	}
	admitted, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], "", 0, "started")
	if err != nil || admitted.Action != "send" {
		t.Fatalf("started %+v %v", admitted, err)
	}
}

func TestPagerUpdatesSerializeAndCloseAfterDefinitiveFailure(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	repo := newTestNotificationRepository()
	mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
	mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
	publish := func(id string, revision int64) shared.ID {
		t.Helper()
		ids, err := repo.Publish(ctx, pagerFinding(id, 1, revision, false))
		if err != nil || len(ids) != 1 {
			t.Fatalf("publish %s %v %v", id, ids, err)
		}
		return ids[0]
	}
	first := publish("first", 1)
	second := publish("update-a", 2)
	third := publish("update-b", 3)
	begin := func(id, op shared.ID, at time.Time) ports.PagerMutation {
		t.Helper()
		if _, err := repo.BeginAttempt(ctx, notificationTestTenant, id, "", 0, op, at, ports.AttemptAdmission{}); err != nil {
			t.Fatal(err)
		}
		decision, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, id, "", 0, op)
		if err != nil {
			t.Fatal(err)
		}
		return decision
	}
	if got := begin(first, "first-op", notificationTestNow); got.Action != "send" {
		t.Fatalf("first %+v", got)
	}
	if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, first, "first-op", ports.NotificationSendResult{StatusCode: 200, RemoteRef: "same-alias"}); err != nil {
		t.Fatal(err)
	}
	if got := begin(second, "second-op", notificationTestNow.Add(2*time.Second)); got.Action != "send" || got.SubjectAnchor != "same-alias" {
		t.Fatalf("update %+v", got)
	}
	if got := begin(third, "third-op", notificationTestNow.Add(4*time.Second)); got.Action != "blocked" || got.Code != "pager_waiting" {
		t.Fatalf("waiting %+v", got)
	}
	if ids, err := repo.Publish(ctx, pagerFinding("terminal", 1, 4, true)); err != nil || len(ids) != 0 {
		t.Fatalf("terminal %v %v", ids, err)
	}
	closeID := notificationStableID(notificationTestTenant.String(), "event-terminal", "pager", "")
	if _, err := repo.GetDelivery(ctx, notificationTestTenant, closeID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("closed before update settled: %v", err)
	}
	if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, second, "second-op", ports.NotificationSendResult{StatusCode: 400, ErrorCode: "http_400"}); err != nil {
		t.Fatal(err)
	}
	closeWork, err := repo.LoadWork(ctx, notificationTestTenant, closeID)
	if err != nil || !closeWork.Event.PagerLifecycle.Terminal {
		t.Fatalf("close %+v %v", closeWork.Event.PagerLifecycle, err)
	}
	suppressed, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, third, "", 0, "third-op")
	if err != nil || suppressed.Action != "suppressed" {
		t.Fatalf("suppressed %+v %v", suppressed, err)
	}
	if got := begin(closeID, "close-op", notificationTestNow.Add(6*time.Second)); got.Action != "send" || got.SubjectAnchor != "same-alias" {
		t.Fatalf("close %+v", got)
	}
}

func TestPagerLateDoneReconcilesAfterChannelDisabled(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprint(before), func(t *testing.T) {
			ctx := shared.WithTenant(context.Background(), notificationTestTenant)
			now := notificationTestNow
			jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return now })
			repo := NewNotificationRepository(jobs, func() time.Time { return now })
			channel := mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
			mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
			ids, err := repo.Publish(ctx, pagerFinding("late-done", 1, 1, false))
			if err != nil || len(ids) != 1 {
				t.Fatalf("publish %v %v", ids, err)
			}
			first, _ := jobs.Claim(ctx, time.Second, notificationDeliverJobKey)
			if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], first.ID, first.Fence, "first", now, ports.AttemptAdmission{}); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], first.ID, first.Fence, "first"); err != nil {
				t.Fatal(err)
			}
			now = now.Add(2 * time.Second)
			second, _ := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
			if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], second.ID, second.Fence, "second", now, ports.AttemptAdmission{}); err != nil {
				t.Fatal(err)
			}
			blocked, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], second.ID, second.Fence, "second")
			if err != nil || blocked.Code != "pager_sending" {
				t.Fatalf("blocked %+v %v", blocked, err)
			}
			channel.Revision++
			channel.Enabled = false
			if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
				t.Fatal(err)
			}
			receipt := func() {
				t.Helper()
				if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "first", ports.NotificationSendResult{StatusCode: 200, RemoteRef: "alias"}); err != nil {
					t.Fatal(err)
				}
			}
			if before {
				receipt()
			}
			if err := repo.FinishAttempt(ctx, notificationTestTenant, ids[0], second.ID, second.Fence, "second", now, "failed", 0, "pager_sending", nil); err != nil {
				t.Fatal(err)
			}
			if err := jobs.Deadletter(ctx, second.ID, second.Fence); err != nil {
				t.Fatal(err)
			}
			if !before {
				receipt()
			}
			if _, err := repo.DeadLetterDelivery(ctx, notificationTestTenant, ids[0], second.Fence, "worker_dead_letter"); err != nil {
				t.Fatal(err)
			}
			next, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
			if err != nil || next == nil {
				t.Fatalf("claim %v %v", next, err)
			}
			reconciled, err := repo.ReconcilePagerAcknowledgement(ctx, notificationTestTenant, ids[0], next.ID, next.Fence)
			if err != nil || !reconciled {
				t.Fatalf("reconcile %v %v", reconciled, err)
			}
			d, err := repo.GetDelivery(ctx, notificationTestTenant, ids[0])
			if err != nil || d.State != notification.DeliverySucceeded || d.RemoteRef != "alias" {
				t.Fatalf("delivery %+v %v", d, err)
			}
		})
	}
}

func TestPagerParkedLaneWakesAfterDefinitiveFailure(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	now := notificationTestNow
	jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return now })
	repo := NewNotificationRepository(jobs, func() time.Time { return now })
	mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
	mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
	publish := func(id string, revision int64) shared.ID {
		t.Helper()
		ids, err := repo.Publish(ctx, pagerFinding(id, 1, revision, false))
		if err != nil || len(ids) != 1 {
			t.Fatalf("publish %v %v", ids, err)
		}
		return ids[0]
	}
	first, second, third := publish("lane-first", 1), publish("lane-second", 2), publish("lane-third", 3)
	claim := func(id, op shared.ID) *ports.QueuedJob {
		t.Helper()
		now = now.Add(2 * time.Second)
		job, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
		if err != nil || job == nil {
			t.Fatalf("claim %v %v", job, err)
		}
		if _, err := repo.BeginAttempt(ctx, notificationTestTenant, id, job.ID, job.Fence, op, now, ports.AttemptAdmission{}); err != nil {
			t.Fatal(err)
		}
		return job
	}
	one := claim(first, "op-one")
	if _, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, first, one.ID, one.Fence, "op-one"); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, first, "op-one", ports.NotificationSendResult{StatusCode: 200, RemoteRef: "alias"}); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Complete(ctx, one.ID, one.Fence); err != nil {
		t.Fatal(err)
	}
	two := claim(second, "op-two")
	if d, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, second, two.ID, two.Fence, "op-two"); err != nil || d.Action != "send" {
		t.Fatalf("second %+v %v", d, err)
	}
	three := claim(third, "op-three")
	if d, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, third, three.ID, three.Fence, "op-three"); err != nil || d.Code != "pager_waiting" {
		t.Fatalf("third %+v %v", d, err)
	}
	if err := repo.FinishAttempt(ctx, notificationTestTenant, third, three.ID, three.Fence, "op-three", now, "failed", 0, "pager_waiting", nil); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Deadletter(ctx, three.ID, three.Fence); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DeadLetterDelivery(ctx, notificationTestTenant, third, three.Fence, "worker_dead_letter"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Publish(ctx, pagerFinding("lane-terminal", 1, 4, true)); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, second, "op-two", ports.NotificationSendResult{StatusCode: 400, ErrorCode: "http_400"}); err != nil {
		t.Fatal(err)
	}
	next, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || next == nil || next.ID != three.ID {
		t.Fatalf("parked job not resumed: %v %v", next, err)
	}
	now = now.Add(2 * time.Second)
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, third, next.ID, next.Fence, "op-resume", now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	if d, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, third, next.ID, next.Fence, "op-resume"); err != nil || d.Action != "suppressed" {
		t.Fatalf("terminal admission %+v %v", d, err)
	}
}

func TestPagerCancelledJobLateAcknowledgementReconciles(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprint(before), func(t *testing.T) {
			ctx := shared.WithTenant(context.Background(), notificationTestTenant)
			now := notificationTestNow
			jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return now })
			repo := NewNotificationRepository(jobs, func() time.Time { return now })
			source := NewNotificationSource(repo, NewNotificationOutbox())
			channel := mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
			mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
			ids, err := repo.Publish(ctx, pagerFinding("cancelled", 1, 1, false))
			if err != nil || len(ids) != 1 {
				t.Fatalf("publish %v %v", ids, err)
			}
			first, _ := jobs.Claim(ctx, time.Second, notificationDeliverJobKey)
			if _, err := repo.BeginAttempt(ctx, notificationTestTenant, ids[0], first.ID, first.Fence, "first", now, ports.AttemptAdmission{}); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], first.ID, first.Fence, "first"); err != nil {
				t.Fatal(err)
			}
			now = now.Add(2 * time.Second)
			second, _ := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
			receipt := func() {
				t.Helper()
				if err := repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "first", ports.NotificationSendResult{StatusCode: 200, RemoteRef: "alias"}); err != nil {
					t.Fatal(err)
				}
			}
			if before {
				receipt()
			}
			channel.Revision++
			channel.Enabled = false
			if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
				t.Fatal(err)
			}
			if err := repo.CancelDelivery(ctx, notificationTestTenant, ids[0], second.ID, second.Fence, "channel_disabled"); err != nil {
				t.Fatal(err)
			}
			if err := jobs.Complete(ctx, second.ID, second.Fence); err != nil {
				t.Fatal(err)
			}
			if !before {
				receipt()
			}
			if _, err := source.Poll(ctx, now, 10); err != nil {
				t.Fatal(err)
			}
			next, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
			if err != nil || next == nil {
				t.Fatalf("reconcile claim %v %v", next, err)
			}
			done, err := repo.ReconcilePagerAcknowledgement(ctx, notificationTestTenant, ids[0], next.ID, next.Fence)
			if err != nil || !done {
				t.Fatalf("reconcile %v %v", done, err)
			}
			d, err := repo.GetDelivery(ctx, notificationTestTenant, ids[0])
			if err != nil || d.State != notification.DeliverySucceeded || d.RemoteRef != "alias" {
				t.Fatalf("delivery %+v %v", d, err)
			}
		})
	}
}

func TestPagerCancelledConfirmationResumesWhenChannelEnabled(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	now := notificationTestNow
	jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return now })
	repo := NewNotificationRepository(jobs, func() time.Time { return now })
	source := NewNotificationSource(repo, NewNotificationOutbox())
	channel := mustCreateChannel(t, repo, testChannel("pager", notification.ChannelJSM))
	mustCreateRule(t, repo, testRule("created", notification.EventFindingCreated, "pager"))
	ids, err := repo.Publish(ctx, pagerFinding("resume", 1, 1, false))
	if err != nil || len(ids) != 1 {
		t.Fatalf("publish %v %v", ids, err)
	}
	first, err := jobs.Claim(ctx, time.Second, notificationDeliverJobKey)
	if err != nil || first == nil {
		t.Fatalf("claim %v %v", first, err)
	}
	if _, err = repo.BeginAttempt(ctx, notificationTestTenant, ids[0], first.ID, first.Fence, "first", now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	if a, e := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], first.ID, first.Fence, "first"); e != nil || a.Action != "send" {
		t.Fatalf("admit %+v %v", a, e)
	}
	if err = repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "first", ports.NotificationSendResult{StatusCode: 202, ProviderRequestRef: "request"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	second, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || second == nil {
		t.Fatalf("reclaim %v %v", second, err)
	}
	channel.Enabled = false
	channel.Revision++
	if _, err = repo.UpdateChannel(ctx, channel, "", false); err != nil {
		t.Fatal(err)
	}
	if err = repo.CancelDelivery(ctx, notificationTestTenant, ids[0], second.ID, second.Fence, "channel_disabled"); err != nil {
		t.Fatal(err)
	}
	if err = jobs.Complete(ctx, second.ID, second.Fence); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Publish(ctx, pagerFinding("resume-terminal", 1, 2, true)); err != nil {
		t.Fatal(err)
	}
	if _, err = source.Poll(ctx, now, 10); err != nil {
		t.Fatal(err)
	}
	if j, e := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey); e != nil || j != nil {
		t.Fatalf("disabled wake %v %v", j, e)
	}
	channel.Enabled = true
	channel.Revision++
	if _, err = repo.UpdateChannel(ctx, channel, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err = source.Poll(ctx, now, 10); err != nil {
		t.Fatal(err)
	}
	resumed, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || resumed == nil {
		t.Fatalf("resume %v %v", resumed, err)
	}
	if _, err = repo.BeginAttempt(ctx, notificationTestTenant, ids[0], resumed.ID, resumed.Fence, "poll", now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	a, err := repo.AdmitPagerMutation(ctx, notificationTestTenant, ids[0], resumed.ID, resumed.Fence, "poll")
	if err != nil || a.Action != "poll" || a.OperationID != "first" || a.ProviderRequestRef != "request" {
		t.Fatalf("poll %+v %v", a, err)
	}
	if err = repo.RecordPagerReceipt(ctx, notificationTestTenant, ids[0], "first", ports.NotificationSendResult{StatusCode: 200, RemoteRef: "alias"}); err != nil {
		t.Fatal(err)
	}
	closeID := notificationStableID(notificationTestTenant.String(), "event-resume-terminal", "pager", "")
	work, err := repo.LoadWork(ctx, notificationTestTenant, closeID)
	if err != nil || !work.Event.PagerLifecycle.Terminal {
		t.Fatalf("close %v %v", work.Event.PagerLifecycle, err)
	}
}
