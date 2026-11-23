package notification

import (
	"context"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// prepareSubjectThread decorates outbound work with a prior provider reference when the event has
// a declared subject. This is a best-effort read with no network operation or held persistence
// lock; concurrent first sends may each create a root message by contract.
func (s *Service) prepareSubjectThread(ctx context.Context, work *ports.NotificationWork) error {
	work.SubjectResolved = false
	if pagerLifecycleWork(*work) {
		// Pager anchors and closure are admitted by the durable episode gate.
		return nil
	}
	switch work.Channel.Type {
	case domain.ChannelTelegram, domain.ChannelPagerDuty, domain.ChannelJSM, domain.ChannelType("slack_bot"):
	default:
		return nil
	}
	if work.Event.SubjectKind == "" || work.Event.SubjectID == "" {
		return nil
	}
	reader, ok := s.repo.(ports.NotificationSubjectAnchorReader)
	if !ok {
		return nil
	}
	anchor, err := reader.SubjectAnchor(ctx, work.Event.TenantID, work.Channel.ID, work.Channel.SecretVersion, work.Event.SubjectKind, work.Event.SubjectID)
	if err != nil {
		return err
	}
	work.SubjectAnchor = anchor
	return nil
}

// subjectResolved reads only the authoritative lifecycle snapshot.
func subjectResolved(event domain.Event) bool {
	return event.PagerLifecycle.Episode > 0 && event.PagerLifecycle.Revision > 0 && event.PagerLifecycle.Terminal
}
