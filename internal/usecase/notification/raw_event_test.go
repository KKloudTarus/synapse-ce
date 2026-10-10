package notification

import (
	"context"
	"errors"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRawEventRequiresAuditedAdministratorOptIn(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	current := webhookChannel()
	current.DataClass = domain.DataClassDetail
	enabled := true
	for _, admin := range []bool{false, true} {
		repo := &channelAdminRepo{killSwitchRepo: killSwitchRepo{current: current}}
		audit := &recordingAudit{}
		svc := channelAdminService(t, repo, audit)
		got, err := svc.UpdateChannel(ctx, "operator", current.ID, ChannelInput{
			Name: current.Name, Enabled: true, Revision: current.Revision,
			RawEvent: &enabled, AllowClassRaise: admin,
		})
		if !admin {
			if !errors.Is(err, shared.ErrForbidden) || repo.updated {
				t.Fatalf("err=%v updated=%v", err, repo.updated)
			}
			continue
		}
		if err != nil || !got.RawEvent {
			t.Fatalf("channel=%+v err=%v", got, err)
		}
		entry := audit.last(t, "notification.channel.updated")
		if entry.Metadata["raw_event"] != "true" || entry.Metadata["previous_raw_event"] != "false" {
			t.Fatalf("metadata=%v", entry.Metadata)
		}
		// An integration manager can rename an existing raw channel without opting in again.
		got, err = svc.UpdateChannel(ctx, "manager", current.ID, ChannelInput{Name: "renamed", Enabled: true, Revision: got.Revision})
		if err != nil || !got.RawEvent {
			t.Fatalf("rename=%+v err=%v", got, err)
		}
	}
}

func TestRawEventCannotBypassClassOrCustomBody(t *testing.T) {
	on, off := true, false
	for _, channel := range []domain.Channel{
		{Type: domain.ChannelWebhook, DataClass: domain.DataClassSignal},
		{Type: domain.ChannelWebhook, DataClass: domain.DataClassSummary},
		{Type: domain.ChannelEmail, DataClass: domain.DataClassDetail},
		{Type: domain.ChannelWebhook, DataClass: domain.DataClassDetail, TemplateBinding: domain.TemplateBinding{CustomBody: true}},
	} {
		if _, err := channelRawEvent(channel, false, ChannelInput{RawEvent: &on, AllowClassRaise: true}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("channel=%+v err=%v", channel, err)
		}
		if _, err := channelRawEvent(channel, true, ChannelInput{}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("invalid retained mode channel=%+v err=%v", channel, err)
		}
		if got, err := channelRawEvent(channel, true, ChannelInput{RawEvent: &off}); err != nil || got {
			t.Fatalf("disable got=%v err=%v", got, err)
		}
	}
}
