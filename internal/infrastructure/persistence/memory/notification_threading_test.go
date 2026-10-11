package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestSubjectAnchorUsesEarliestAcknowledgedPinnedDelivery(t *testing.T) {
	ctx := context.Background()
	now := notificationTestNow
	repo := NewNotificationRepository(nil, func() time.Time { return now })
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelTelegram))

	publish := func(source string) string {
		t.Helper()
		event := testEvent(source, notification.EventTest)
		event.SubjectKind, event.SubjectID = "finding", "finding-1"
		id, err := repo.PublishToChannel(ctx, event, "ch-1")
		if err != nil {
			t.Fatal(err)
		}
		return id.String()
	}
	first, second := publish("first"), publish("second")
	for _, tc := range []struct {
		id  string
		at  time.Time
		ref string
	}{
		{id: second, at: now.Add(time.Second), ref: "earliest"},
		{id: first, at: now.Add(2 * time.Second), ref: "later"},
	} {
		if _, err := repo.BeginAttempt(ctx, notificationTestTenant, shared.ID(tc.id), "job", 1, shared.ID("attempt-"+tc.id), tc.at, ports.AttemptAdmission{}); err != nil {
			t.Fatal(err)
		}
		if err := repo.FinishAttemptWithRemoteRef(ctx, notificationTestTenant, shared.ID(tc.id), "job", 1, shared.ID("attempt-"+tc.id), tc.at, "delivered", 200, "", nil, tc.ref); err != nil {
			t.Fatal(err)
		}
	}
	anchor, err := repo.SubjectAnchor(ctx, notificationTestTenant, "ch-1", 1, "finding", "finding-1")
	if err != nil || anchor != "earliest" {
		t.Fatalf("anchor=%q err=%v", anchor, err)
	}
	delivery, err := repo.GetDelivery(ctx, notificationTestTenant, shared.ID(second))
	if err != nil || delivery.RemoteRef != "earliest" {
		t.Fatalf("delivery remote reference=%q err=%v", delivery.RemoteRef, err)
	}
	if anchor, err := repo.SubjectAnchor(ctx, notificationTestTenant, "ch-1", 2, "finding", "finding-1"); err != nil || anchor != "" {
		t.Fatalf("rotated configuration anchor=%q err=%v", anchor, err)
	}
}
