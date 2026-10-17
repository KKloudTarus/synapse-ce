package notification

import (
	"context"
	"fmt"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SendTemplateTest queues a fixture-only test through the ordinary targeted channel delivery
// path. It snapshots the selected draft or resolved template on the event, so retries keep the
// exact text the administrator previewed even if the template later changes.
func (s *Service) SendTemplateTest(ctx context.Context, actor string, in PreviewInput) (shared.ID, error) {
	return mutation(ctx, s, func(ctx context.Context) (shared.ID, error) {
		return s.sendTemplateTest(ctx, actor, in)
	})
}

func (s *Service) sendTemplateTest(ctx context.Context, actor string, in PreviewInput) (shared.ID, error) {
	if !in.EventID.IsZero() {
		return "", fmt.Errorf("%w: template send test only accepts the published fixture", shared.ErrValidation)
	}
	preview, err := s.PreviewTemplate(ctx, in)
	if err != nil {
		return "", err
	}
	channel := preview.prepared.channel
	if err = s.refuseDisabled(channel.Type); err != nil {
		return "", err
	}
	if channel.Type == domain.ChannelEmail {
		if err = s.validateEmailRecipients(ctx, channel.TenantID, channel.Recipients); err != nil {
			return "", err
		}
	}

	event := preview.prepared.event
	event.ID, event.SourceKind, event.SourceID = s.ids.NewID(), "template_test", s.ids.NewID().String()
	event.TestTemplate = previewTemplateSnapshot(preview)
	delivery, err := s.repo.PublishToChannel(ctx, event, channel.ID)
	if err != nil {
		return "", err
	}
	meta := map[string]string{"delivery_id": delivery.String(), "event_type": string(event.Type)}
	if preview.Message != nil {
		meta["template_ref"] = preview.Message.TemplateRef
	}
	if err = s.record(ctx, actor, "notification.template_test_queued", channel.ID.String(), channelAuditMetadata(channel, meta)); err != nil {
		return "", err
	}
	return delivery, nil
}

func previewTemplateSnapshot(preview TemplatePreview) *domain.TemplateVersion {
	var source *domain.TemplateVersion
	if preview.prepared.draft != nil {
		source = preview.prepared.draft
	} else if preview.Resolution != nil {
		source = preview.Resolution.Version
		if source == nil && preview.Resolution.Builtin != nil {
			source = &domain.TemplateVersion{TemplateID: shared.ID(preview.Resolution.Builtin.Ref), Version: 1, Fields: preview.Resolution.Builtin.Fields}
		}
	}
	if source == nil {
		// An empty snapshot deliberately takes the existing fallback path. It prevents a template
		// created after the test was queued from changing what the test delivers.
		source = &domain.TemplateVersion{TemplateID: "fallback", Version: 1}
	}
	snapshot := *source
	snapshot.Fields = clonePreviewFields(source.Fields)
	return &snapshot
}

func clonePreviewFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}
