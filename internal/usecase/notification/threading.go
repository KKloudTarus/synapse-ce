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
	work.SubjectResolved = subjectResolved(work.Event)
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

// subjectResolved remains false until a catalog event explicitly declares a trusted closure
// state. Generic event JSON is intentionally never interpreted as a closure signal.
func subjectResolved(domain.Event) bool { return false }
