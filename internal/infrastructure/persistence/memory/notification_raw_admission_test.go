package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestRawWebhookRevocationAfterLoadStopsSend(t *testing.T) {
	h := newDataClassHarness(t)
	h.repo.AddEngagement(notificationTestTenant, "eng-1")
	channel := h.webhook(t)
	enabled := true
	var err error
	channel, err = h.service.UpdateChannel(h.ctx, "admin", channel.ID, notificationuc.ChannelInput{Name: channel.Name, Enabled: true, Revision: channel.Revision, DataClass: classPtr(notification.DataClassDetail), RawEvent: &enabled, AllowClassRaise: true})
	if err != nil {
		t.Fatal(err)
	}
	job := h.queuedScan(t, channel)
	worker := h.worker(t, changeAfterLoad{NotificationRepository: h.repo, change: func(ctx context.Context) error {
		disabled := false
		_, err := h.service.UpdateChannel(ctx, "integrator", channel.ID, notificationuc.ChannelInput{Name: channel.Name, Enabled: true, Revision: channel.Revision, RawEvent: &disabled})
		return err
	}})
	if err := worker.HandleJob(h.ctx, job); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("stale raw send error=%v", err)
	}
	if len(h.sender.sent) != 0 {
		t.Fatal("sent raw event after opt-in was revoked")
	}
	page, err := h.service.ListDeliveries(h.ctx, ports.NotificationDeliveryFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Attempts != 0 {
		t.Fatalf("stale raw admission wrote attempt: %+v err=%v", page.Items, err)
	}
}
